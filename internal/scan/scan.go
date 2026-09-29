// 扫描引擎：行级检测管线（路径过滤 → 关键字预筛 → 正则 → 验真 → 行内豁免 → 指纹）。
// 三种输入源共用本管线：目录快照（scan.go）、git 全历史增量行（git.go）、stdin。
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucassylux/leakgoose/internal/rules"
)

// Finding 单条敏感信息命中
type Finding struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Commit      string `json:"commit,omitempty"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

// Fingerprint 规则 + 文件 + 命中内容的复合指纹（内容哈希使行号漂移不影响基线匹配）
func Fingerprint(ruleID, file, secret string) string {
	ch := sha256.Sum256([]byte(secret))
	fph := sha256.Sum256([]byte(ruleID + "|" + file + "|" + hex.EncodeToString(ch[:])))
	return hex.EncodeToString(fph[:])
}

// Line 带行号的一行文本（git 模式行号来自 hunk 头，dir 模式按序号）
type Line struct {
	No   int
	Text string
}

const (
	maxLineBytes = 16 * 1024         // 超长行（压缩产物/数据文件）跳过：minified 一行即全文件
	allowToken   = "leakgoose:allow" // 行内豁免标记（整行对所有规则豁免；豁免应附原因注释）
	binarySniff  = 8 * 1024          // 二进制嗅探窗口
)

// ScanLines 对已收集的行集合跑全部规则（调用方完成路径过滤与读取）
func ScanLines(rs *rules.Set, path, commit string, lines []Line) []Finding {
	var out []Finding
	lowered := make([]byte, 0, 64)
	for _, ln := range lines {
		lowered = append(lowered, ln.Text...)
		lowered = append(lowered, '\n')
	}
	lowerStr := strings.ToLower(string(lowered))
	for _, r := range rs.Rules {
		if !r.MatchesPath(path) {
			continue
		}
		if len(r.Keywords) > 0 && !rules.ContainsAny(lowerStr, r.Keywords) {
			continue
		}
		for _, ln := range lines {
			if len(ln.Text) > maxLineBytes || strings.Contains(ln.Text, allowToken) {
				continue
			}
			for _, m := range r.FindAll(ln.Text) {
				if !r.Check(m) {
					continue
				}
				out = append(out, Finding{
					Rule: r.ID, Severity: r.Severity, File: path, Line: ln.No, Commit: commit,
					Secret: m, Fingerprint: Fingerprint(r.ID, path, m),
				})
			}
		}
	}
	return out
}

// dir 模式的默认目录排除（.git 是历史本体已由 history 模式覆盖；node_modules 为第三方产物）
var defaultSkipDirs = map[string]bool{".git": true, "node_modules": true}

// ScanDir 目录快照扫描：遍历文件（跳过默认目录、二进制与超大文件），逐文件过管线
func ScanDir(rs *rules.Set, root string, maxFileBytes int64) ([]Finding, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []Finding
	err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if defaultSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil // 单文件读失败（权限/并发删除）不拖垮整轮扫描
		}
		if isBinary(data) {
			return nil
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return nil
		}
		out = append(out, ScanLines(rs, filepath.ToSlash(rel), "", splitLines(data))...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("目录扫描失败: %w", err)
	}
	return out, nil
}

// ScanStdin 管道输入（行号即序号，文件名固定 <stdin>）
func ScanStdin(rs *rules.Set, r io.Reader) ([]Finding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return ScanLines(rs, "<stdin>", "", splitLines(data)), nil
}

func splitLines(data []byte) []Line {
	s := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	out := make([]Line, 0, len(s))
	for i, t := range s {
		out = append(out, Line{No: i + 1, Text: t})
	}
	return out
}

func isBinary(head []byte) bool {
	n := len(head)
	if n > binarySniff {
		n = binarySniff
	}
	return strings.IndexByte(string(head[:n]), 0) >= 0
}
