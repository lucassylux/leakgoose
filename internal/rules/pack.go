// 规则包（Pack）：规则中心发布与 CLI 同步的版本化快照。
// 校验和的单一事实源：对包内容做 YAML 规范序列化后取 sha256——服务端发布时计算，
// CLI sync 拉取后重算比对（供应链完整性），扫描端与发布端共用本实现。
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func marshalYAML(v any) ([]byte, error) { return yaml.Marshal(v) }

// Pack 已发布规则包（JSON 为 API 载荷形态；rules 字段与规则文件 schema 同构）
type Pack struct {
	Version     string  `json:"version" yaml:"version"`
	Sha256      string  `json:"sha256" yaml:"sha256"`
	GeneratedAt string  `json:"generatedAt" yaml:"generatedAt"`
	Rules       []*Rule `json:"rules" yaml:"rules"`
}

// packContent 规范载荷：仅规则清单（校验和覆盖的内容——版本号/时间戳自身不参与）
type packContent struct {
	Rules []*Rule `yaml:"rules"`
}

// ComputeChecksum 对规则清单的规范 YAML 序列化取 sha256。
// YAML 序列化对同构输入是确定性的（字段顺序按 struct 定义），两端一致即可比。
func (p *Pack) ComputeChecksum() string {
	data, err := marshalYAML(packContent{Rules: p.Rules})
	if err != nil {
		return "" // 序列化规则清单不会失败（无动态结构）；防御性兜底
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Verify 包完整性：重算校验和与包内声明一致
func (p *Pack) Verify() bool {
	return p.Sha256 != "" && p.ComputeChecksum() == p.Sha256
}

// NewPackVersion 当日序号式版本号（2026.09.30-3）：existing 为当日已有版本数
func NewPackVersion(t time.Time, existingToday int) string {
	return t.Format("2006.01.02") + "-" + itoa(existingToday+1)
}

// Compile 校验并编译一条规则（规则中心入库前与用例回归使用；
// 与加载规则文件走同一 finalize，保证中心判定与扫描行为一致）
func Compile(r *Rule) error { return r.finalize() }

// TryMatch 规则测试沙箱（规则中心 UI / 发布前用例回归共用）：
// 按 pattern+validate 组装单条规则并跑样例文本，返回去重命中。
// 配置错误（正则/验真函数非法）返回 error——UI 里即时反馈，不静默。
func TryMatch(pattern, validate string, sample string) ([]string, error) {
	r := &Rule{Pattern: pattern, Validate: validate}
	if err := r.finalize(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var hits []string
	for _, ln := range strings.Split(strings.ReplaceAll(sample, "\r\n", "\n"), "\n") {
		for _, m := range r.FindAll(ln) {
			if r.Check(m) && !seen[m] {
				seen[m] = true
				hits = append(hits, m)
			}
		}
	}
	return hits, nil
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
