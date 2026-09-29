package rules

import (
	"os"
	"path/filepath"
	"testing"
)

const overlayYAML = `
rules:
  - id: fake-key
    name: 测试叠加规则
    severity: high
    pattern: 'FAKE[0-9]{8}'
  - id: cn-mobile
    name: 中国大陆手机号（叠加收窄：测试与种子路径豁免）
    severity: high
    pattern: '(?<!\d)1[3-9]\d{9}(?!\d)'
    validate: builtin:cn-mobile-segment
    exclude-paths: ['**/test/**', '**/*_test.go', 'sql/**']
`

func TestBuiltinLoadAndCompile(t *testing.T) {
	data, err := os.ReadFile("../../rules/builtin.yaml")
	if err != nil {
		t.Fatalf("读取内置规则: %v", err)
	}
	s, err := Load(data, nil)
	if err != nil {
		t.Fatalf("内置规则加载失败: %v", err)
	}
	if len(s.Rules) < 10 {
		t.Fatalf("内置规则数量异常: %d", len(s.Rules))
	}
	seen := map[string]bool{}
	for _, r := range s.Rules {
		if seen[r.ID] {
			t.Errorf("规则 id 重复: %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestOverlayReplaceByID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(p, []byte(overlayYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(nil, []string{p})
	if err != nil {
		t.Fatalf("叠加加载失败: %v", err)
	}
	var mobile *Rule
	for _, r := range s.Rules {
		if r.ID == "cn-mobile" {
			mobile = r
		}
	}
	if mobile == nil {
		t.Fatal("叠加未生效：找不到 cn-mobile")
	}
	if len(mobile.excludes) != 3 {
		t.Fatalf("叠加替换应重定义 exclude-paths，实际 %d 条", len(mobile.excludes))
	}
	if mobile.MatchesPath("sql/mysql/data.sql") {
		t.Errorf("sql/** 应被排除")
	}
	if !mobile.MatchesPath("src/App.java") {
		t.Errorf("非排除路径应命中")
	}
	// 新增规则
	found := false
	for _, r := range s.Rules {
		if r.ID == "fake-key" {
			found = true
		}
	}
	if !found {
		t.Error("叠加新增规则未生效")
	}
}

func TestInvalidRules(t *testing.T) {
	cases := []string{
		"rules:\n  - id: x\n    pattern: ''\n",                              // 缺 pattern
		"rules:\n  - id: x\n    pattern: '['\n",                             // 非法正则
		"rules:\n  - id: x\n    pattern: 'a'\n    severity: fatal\n",        // 非法 severity
		"rules:\n  - id: x\n    pattern: 'a'\n    validate: builtin:nope\n", // 未知验真函数
		"rules:\n  - id: x\n    pattern: 'a'\n    exclude-paths: ['[']\n",   // 非法通配
	}
	for i, yaml := range cases {
		if _, err := Load(nil, []string{writeTemp(t, yaml)}); err == nil {
			t.Errorf("case %d 应报配置错误", i)
		}
	}
}

func TestEmptyRulesFile(t *testing.T) {
	if _, err := Load(nil, []string{writeTemp(t, "rules: []\n")}); err == nil {
		t.Error("空规则文件应报错")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
