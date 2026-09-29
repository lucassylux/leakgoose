package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucassylux/leakgoose/internal/rules"
)

const testRulesYAML = `
rules:
  - id: fake-key
    name: 测试密钥
    severity: critical
    pattern: 'FAKEKEY[0-9A-Za-z]{10}'
  - id: cn-id-card
    name: 身份证
    severity: critical
    pattern: '(?<![0-9Xx])[1-8]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])'
    validate: builtin:id-card-checksum
`

func loadRules(t *testing.T) *rules.Set {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	if err := os.WriteFile(p, []byte(testRulesYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := rules.Load(nil, []string{p})
	if err != nil {
		t.Fatalf("规则加载: %v", err)
	}
	return s
}

func TestScanDirBasics(t *testing.T) {
	rs := loadRules(t)
	root := t.TempDir()
	files := map[string]string{
		"app.go":            "k := \"FAKEKEYAbc123def45\"", // 命中
		"clean.go":          "k := \"nothing-here\"",
		"allow.go":          "k := \"FAKEKEYAllow0000xx\" // leakgoose:allow 测试样例", // 行内豁免
		"id-ok.txt":         "证号 11010519491231002X 一枚",                            // 验真通过
		"id-bad.txt":        "证号 110105194912310021 一枚",                            // 校验位不过
		".git/config":       "FAKEKEYGitHist0000zz",                                // .git 跳过
		"node_modules/x.js": "FAKEKEYDeps0000aaaaaa",                               // node_modules 跳过
		"binary.bin":        "\x00\x01FAKEKEYBin0000bbbb",                          // 二进制跳过
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := ScanDir(rs, root, 5*1024*1024)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	byRule := map[string]int{}
	for _, f := range findings {
		byRule[f.Rule]++
		if f.Line == 0 {
			t.Errorf("发现缺行号: %+v", f)
		}
	}
	if byRule["fake-key"] != 1 {
		t.Errorf("fake-key 应恰命中 1 处（豁免/跳过路径不算），实际 %d: %+v", byRule["fake-key"], findings)
	}
	if byRule["cn-id-card"] != 1 {
		t.Errorf("cn-id-card 应命中 1 处（校验位拦截误报），实际 %d", byRule["cn-id-card"])
	}
}

func TestScanStdin(t *testing.T) {
	rs := loadRules(t)
	findings, err := ScanStdin(rs, strings.NewReader("line1\nsecret=FAKEKEYStdin00000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Line != 2 || findings[0].File != "<stdin>" {
		t.Fatalf("stdin 扫描结果异常: %+v", findings)
	}
}

func TestScanHistoryWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("无 git 可执行文件")
	}
	rs := loadRules(t)
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t.local"}, args...)
		cmd := exec.Command("git", full...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	// 提交 1：引入密钥 A
	write(t, dir, "a.txt", "key = FAKEKEYCommitOne1\n")
	git("add", "-A")
	git("commit", "-q", "-m", "add a")
	// 提交 2：引入密钥 B（不同内容）
	write(t, dir, "b.txt", "key = FAKEKEYCommitTwo2\n")
	git("add", "-A")
	git("commit", "-q", "-m", "add b")
	// 提交 3：密钥 A 出现在另一文件（指纹含路径：独立发现，不去重）
	write(t, dir, "c.txt", "dup = FAKEKEYCommitOne1\n")
	git("add", "-A")
	git("commit", "-q", "-m", "dup a in new file")
	// 提交 4：整文件重写 a.txt（同文件同密钥再入 diff——同指纹去重，保留最早提交）
	write(t, dir, "a.txt", "// rewritten\nkey = FAKEKEYCommitOne1\n")
	git("add", "-A")
	git("commit", "-q", "-m", "rewrite a")

	findings, err := ScanHistory(rs, dir)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("应命中 3 处（a/b/c 各一，a.txt 重写去重），实际 %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Commit == "" {
			t.Errorf("history 模式发现缺提交号: %+v", f)
		}
	}
	// A 的最早提交是第一个提交；行号映射正确性（a.txt 第 1 行）
	var aFinding *Finding
	for i, f := range findings {
		if f.File == "a.txt" {
			aFinding = &findings[i]
		}
	}
	if aFinding == nil {
		t.Fatalf("未找到 a.txt 的命中: %+v", findings)
	}
	if aFinding.Line != 1 {
		t.Errorf("a.txt 行号应为 1，实际 %d", aFinding.Line)
	}
}

func TestScanHistoryNotARepo(t *testing.T) {
	rs := loadRules(t)
	if _, err := ScanHistory(rs, t.TempDir()); err == nil {
		t.Error("非 git 仓库应报错")
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("r", "f.txt", "secret")
	b := Fingerprint("r", "f.txt", "secret")
	c := Fingerprint("r", "f.txt", "secret2")
	if a != b || a == c {
		t.Error("指纹稳定性异常")
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
