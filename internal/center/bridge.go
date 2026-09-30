// 桥接层：中心存储形态的规则 → 扫描引擎编译/匹配。
// 所有"这条规则能不能用/会命中什么"的判定都走扫描同一份引擎代码（防双引擎漂移的落点）。
package center

import "github.com/lucassylux/leakgoose/internal/rules"

// tryCompile 规则入库前的编译校验（正则/验真函数/路径通配/严重级）
func tryCompile(r Rule) (*rules.Rule, error) {
	rr := &rules.Rule{
		ID:           r.RID,
		Name:         r.Name,
		Severity:     r.Severity,
		Pattern:      r.Pattern,
		Validate:     r.Validate,
		Keywords:     r.Keywords,
		IncludePaths: r.IncludePaths,
		ExcludePaths: r.ExcludePaths,
	}
	if err := rules.Compile(rr); err != nil {
		return nil, err
	}
	return rr, nil
}

// tryMatch 测试沙箱（透传引擎，命中语义与扫描完全一致）
func tryMatch(pattern, validate, sample string) ([]string, error) {
	return rules.TryMatch(pattern, validate, sample)
}
