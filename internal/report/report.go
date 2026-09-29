// 报告输出：CLI 表格（人看）与 JSON（机器消费）。默认脱敏展示命中内容，
// 防止"扫描报告本身把敏感信息再泄漏一遍"（日志/工单/IM 转发都是常见去向）。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/lucassylux/leakgoose/internal/scan"
)

// Mask 命中内容脱敏：保留前 3 后 2（足够人工比对定位，不足以复用）
func Mask(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return "***"
	}
	return string(r[:3]) + "***" + string(r[len(r)-2:])
}

// Table 表格输出（表格后附汇总行；返回写入行数供测试断言）
func Table(w io.Writer, findings []scan.Finding, redact, suppressed bool, suppressedCount int) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tLOCATION\tCOMMIT\tMATCH")
	for _, f := range findings {
		secret := f.Secret
		if redact {
			secret = Mask(secret)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s:%d\t%s\t%s\n", f.Rule, f.Severity, f.File, f.Line, shortCommit(f.Commit), secret)
	}
	_ = tw.Flush()
	if suppressed {
		fmt.Fprintf(w, "发现 %d 处敏感信息（另有 %d 处基线豁免）\n", len(findings), suppressedCount)
	} else {
		fmt.Fprintf(w, "发现 %d 处敏感信息\n", len(findings))
	}
}

// JSON JSON 输出（数组；secret 按 redact 决定脱敏）
func JSON(w io.Writer, findings []scan.Finding, redact bool) error {
	type outFinding struct {
		Rule        string `json:"rule"`
		Severity    string `json:"severity"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Commit      string `json:"commit,omitempty"`
		Secret      string `json:"secret"`
		Fingerprint string `json:"fingerprint"`
	}
	out := make([]outFinding, 0, len(findings))
	for _, f := range findings {
		s := f.Secret
		if redact {
			s = Mask(s)
		}
		out = append(out, outFinding{f.Rule, f.Severity, f.File, f.Line, f.Commit, s, f.Fingerprint})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}
