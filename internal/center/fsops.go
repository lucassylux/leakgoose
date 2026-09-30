// 规则包的 CLI 侧配套：JSON 解析、校验和消费、规则文件落盘，以及静态资源的 FS 适配。
package center

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lucassylux/leakgoose/internal/rules"
)

// ParsePackJSON 解析规则中心的 JSON 包响应
func ParsePackJSON(data []byte) (*rules.Pack, error) {
	var p rules.Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Version == "" || len(p.Rules) == 0 {
		return nil, fmt.Errorf("缺少 version 或 rules")
	}
	return &p, nil
}

// WritePackFile 把包写成规则文件（schema 与中心 YAML 端点一致，scan -r 直接可用）；
// 头部注释带版本与校验和（供应链可追溯）
func WritePackFile(p *rules.Pack, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := yamlMarshal(struct {
		Version string        `yaml:"version"`
		Sha256  string        `yaml:"sha256"`
		Rules   []*rules.Rule `yaml:"rules"`
	}{p.Version, p.Sha256, p.Rules})
	if err != nil {
		return err
	}
	header := fmt.Sprintf("# 由 leakgoose rules sync 生成（版本 %s，sha256 %s）——手工改动会在下次同步被覆盖\n", p.Version, p.Sha256)
	return os.WriteFile(path, append([]byte(header), body...), 0o644)
}

// SubFS 取嵌入资源子树（dist 目录）
func SubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil
	}
	return sub
}

// DirFS 本地目录静态资源（开发期 --ui-dir 指到 web/dist）
func DirFS(dir string) fs.FS { return os.DirFS(dir) }
