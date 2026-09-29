// git 全历史扫描：`git log -p -U0 --all` 单进程流式解析，
// 只扫新增行（+ 行），行号取 hunk 头的新文件起始行；同指纹多提交去重，保留最早引入提交。
package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/lucassylux/leakgoose/internal/rules"
)

// ScanHistory 扫描 repo 的全部提交历史（含全部分支）
func ScanHistory(rs *rules.Set, repo string) ([]Finding, error) {
	// 探活：非 git 仓库/无提交时 git 以非零退出，转成可读错误
	if err := exec.Command("git", "-C", repo, "rev-parse", "--git-dir").Run(); err != nil {
		return nil, fmt.Errorf("%s 不是 git 仓库（或 git 不可用）: %w", repo, err)
	}
	// core.quotepath=false：非 ASCII 路径不转义，直接 UTF-8 输出，省去八进制反解
	cmd := exec.Command("git", "-C", repo, "-c", "core.quotepath=false",
		"log", "-p", "-U0", "--all", "--no-color", "--no-ext-diff")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	findings, err := parseLogStream(rs, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	if err := cmd.Wait(); err != nil && stderr.Len() > 0 {
		return nil, fmt.Errorf("git log 执行失败: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return dedupeOldest(findings), nil
}

// parseLogStream 状态机解析 unified diff 流。
// 判定顺序保证正确性：内容行必以 +/-/空白开头，而 +++/--- 头也是 +/- 开头——
// 头部前缀（commit/diff/+++/@@）必须先于内容行分支判断。
func parseLogStream(rs *rules.Set, r io.Reader) ([]Finding, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	var findings []Finding
	commit := ""
	file := ""
	var added []Line
	newLine := 0
	inHunk := false

	flush := func() {
		if file != "" && len(added) > 0 {
			findings = append(findings, ScanLines(rs, file, commit, added)...)
		}
		file, added, newLine, inHunk = "", nil, 0, false
	}

	for {
		raw, err := br.ReadString('\n')
		if len(raw) > 0 {
			text := strings.TrimRight(raw, "\r\n")
			switch {
			case strings.HasPrefix(text, "commit "):
				flush()
				commit = strings.TrimSpace(strings.TrimPrefix(text, "commit "))
			case strings.HasPrefix(text, "diff --git "):
				flush()
			case strings.HasPrefix(text, "+++ "):
				// b/ 侧路径；/dev/null = 纯删除（历史对象仍存在，但无新增行可扫）
				p := strings.TrimPrefix(text, "+++ ")
				if p == "/dev/null" {
					file = ""
				} else {
					file = strings.TrimPrefix(p, "b/")
				}
			case strings.HasPrefix(text, "@@ "):
				if n, ok := parseNewStart(text); ok {
					newLine, inHunk = n, true
				}
			case inHunk && strings.HasPrefix(text, "+"):
				if file != "" {
					added = append(added, Line{No: newLine, Text: text[1:]})
				}
				newLine++
			case inHunk && strings.HasPrefix(text, "-"):
				// 删除行：不影响新文件行号
			}
			// 其余行（author/date/message/上下文行/\ No newline）不参与
		}
		if err != nil {
			flush()
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return findings, nil
}

// parseNewStart 从 "@@ -3,7 +10,9 @@ ctx" 提取新文件起始行号 10
func parseNewStart(header string) (int, bool) {
	i := strings.Index(header, " +")
	if i < 0 {
		return 0, false
	}
	rest := header[i+2:]
	if j := strings.IndexAny(rest, ", @"); j >= 0 {
		rest = rest[:j]
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// dedupeOldest 同指纹去重：log 输出新→旧，后处理的同指纹记录更老——直接覆盖，
// 最终保留"最早引入该内容的提交"；输出按 文件→行号→规则 排序保证报告稳定。
func dedupeOldest(in []Finding) []Finding {
	byFP := make(map[string]Finding, len(in))
	for _, f := range in {
		byFP[f.Fingerprint] = f
	}
	out := make([]Finding, 0, len(byFP))
	for _, f := range byFP {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
