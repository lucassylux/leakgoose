// Package rules 实现规则模型：YAML 加载（内置包 + 项目叠加）、编译校验、路径/关键字过滤。
// 叠加语义：叠加文件中与内置规则同 id 的条目整体替换内置项（用于收窄路径/调整严重级），
// 新 id 追加；全部规则在加载期完成编译与验真函数解析，配置错误 fail-fast。
package rules

import (
	"fmt"
	"os"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v3"
)

// 规则严重级（severity）取值；门禁按阈值比较（--fail-severity）
var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// SeverityRank 返回严重级排序值（用于 --fail-severity 阈值比较）
func SeverityRank(s string) int { return severityRank[s] }

// Rule 单条敏感信息规则
type Rule struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Severity     string   `yaml:"severity"`
	Pattern      string   `yaml:"pattern"`
	Validate     string   `yaml:"validate,omitempty"`
	Keywords     []string `yaml:"keywords,omitempty"`
	IncludePaths []string `yaml:"include-paths,omitempty"`
	ExcludePaths []string `yaml:"exclude-paths,omitempty"`

	re       *regexp2.Regexp
	includes []string
	excludes []string
	checker  ValidatorFunc
}

// FindAll 在单行文本上取全部命中（regexp2 无 FindAll 助手，按官方姿势迭代）。
// 正则由内置/项目规则文件提供（评审态），回溯风险可接受；行级 16KB 上限兜底最坏情况。
func (r *Rule) FindAll(line string) []string {
	var out []string
	m, err := r.re.FindStringMatch(line)
	for err == nil && m != nil {
		out = append(out, m.String())
		m, err = r.re.FindNextMatch(m)
	}
	return out
}

// Check 跑验真函数（无验真恒真）；验真不过的命中视为误报丢弃
func (r *Rule) Check(s string) bool {
	if r.checker == nil {
		return true
	}
	return r.checker(s)
}

// MatchesPath 判定相对路径是否命中该规则的路径过滤（统一 / 分隔符后匹配）
func (r *Rule) MatchesPath(path string) bool {
	p := strings.ReplaceAll(path, "\\", "/")
	for _, ex := range r.excludes {
		if ok, _ := doublestar.Match(ex, p); ok {
			return false
		}
	}
	if len(r.includes) == 0 {
		return true
	}
	for _, in := range r.includes {
		if ok, _ := doublestar.Match(in, p); ok {
			return true
		}
	}
	return false
}

// Set 已编译规则集
type Set struct {
	Rules []*Rule
}

type ruleFile struct {
	Rules []*Rule `yaml:"rules"`
}

// Load 组装规则集：builtin 为内置规则包内容（可为 nil），overlays 为项目叠加文件路径（按序应用）。
func Load(builtin []byte, overlays []string) (*Set, error) {
	var list []*Rule
	if len(builtin) > 0 {
		parsed, err := parse(builtin, "builtin")
		if err != nil {
			return nil, err
		}
		list = append(list, parsed...)
	}
	for _, p := range overlays {
		buf, err := readFile(p)
		if err != nil {
			return nil, fmt.Errorf("读取规则文件 %s: %w", p, err)
		}
		parsed, err := parse(buf, p)
		if err != nil {
			return nil, err
		}
		list = append(list, parsed...)
	}

	s := &Set{}
	byID := map[string]*Rule{}
	for _, r := range list {
		// 同 id 叠加 = 整体替换（收窄路径/调整严重级的正式姿势）
		if prev, ok := byID[r.ID]; ok {
			for i, x := range s.Rules {
				if x == prev {
					s.Rules[i] = r
					break
				}
			}
		} else {
			s.Rules = append(s.Rules, r)
		}
		byID[r.ID] = r
	}
	// 全量终检（叠加替换后仍要保证每条都已编译）
	for _, r := range s.Rules {
		if err := r.finalize(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func parse(buf []byte, src string) ([]*Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(buf, &rf); err != nil {
		return nil, fmt.Errorf("解析规则文件 %s: %w", src, err)
	}
	if len(rf.Rules) == 0 {
		return nil, fmt.Errorf("规则文件 %s 未包含任何规则（rules: 为空）", src)
	}
	var out []*Rule
	for _, r := range rf.Rules {
		if r.ID == "" || r.Pattern == "" {
			return nil, fmt.Errorf("%s: 规则缺少 id 或 pattern", src)
		}
		if err := r.finalize(); err != nil {
			return nil, fmt.Errorf("%s: 规则 %s: %w", src, r.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// finalize 校验并编译单个规则（幂等）
func (r *Rule) finalize() error {
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if _, ok := severityRank[r.Severity]; !ok {
		return fmt.Errorf("severity 非法: %s（可选 critical/high/medium/low）", r.Severity)
	}
	if r.Validate != "" {
		fn, ok := validators[r.Validate]
		if !ok {
			return fmt.Errorf("validate 非法: %s（可选 %s）", r.Validate, validatorNames())
		}
		r.checker = fn
	}
	re, err := regexp2.Compile(r.Pattern, regexp2.None)
	if err != nil {
		return fmt.Errorf("pattern 编译失败: %w", err)
	}
	r.re = re
	// 重置再编译（幂等）：finalize 可能因叠加替换等被再次调用，追加语义会翻倍
	r.includes, r.excludes = nil, nil
	for _, p := range r.IncludePaths {
		if !doublestar.ValidatePattern(p) {
			return fmt.Errorf("include-paths 非法通配: %s", p)
		}
		r.includes = append(r.includes, p)
	}
	for _, p := range r.ExcludePaths {
		if !doublestar.ValidatePattern(p) {
			return fmt.Errorf("exclude-paths 非法通配: %s", p)
		}
		r.excludes = append(r.excludes, p)
	}
	return nil
}

// ContainsAny 报告低置信全文是否包含任一关键字（关键字预筛，规则可配）
func ContainsAny(loweredContent string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(loweredContent, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

var _ = strings.Contains // 占位防 import 漂移（strings 由 ContainsAny/MatchesPath 使用）
