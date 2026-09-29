// 基线：存量已知发现的指纹登记表。新扫描中命中基线的发现不阻断（计入豁免数），
// 指纹 = 规则 + 文件 + 内容哈希，行号漂移不影响匹配；路径变更视为新发现（保守）。
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/lucassylux/leakgoose/internal/scan"
)

type fileFormat struct {
	Version      int      `json:"version"`
	Fingerprints []string `json:"fingerprints"`
}

// Load 读取基线文件；文件不存在视为空基线（首次接入的常规态）
func Load(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("读取基线 %s: %w", path, err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析基线 %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("基线 %s 版本不支持: %d（当前支持 1）", path, f.Version)
	}
	m := make(map[string]bool, len(f.Fingerprints))
	for _, fp := range f.Fingerprints {
		m[fp] = true
	}
	return m, nil
}

// Save 把当前发现写入基线文件（排序保证 diff 友好；自动建父目录）
func Save(path string, findings []scan.Finding) error {
	set := map[string]bool{}
	for _, f := range findings {
		set[f.Fingerprint] = true
	}
	fps := make([]string, 0, len(set))
	for fp := range set {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Version: 1, Fingerprints: fps}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Filter 按基线切分：返回（新增发现, 豁免数）
func Filter(findings []scan.Finding, base map[string]bool) ([]scan.Finding, int) {
	var fresh []scan.Finding
	suppressed := 0
	for _, f := range findings {
		if base[f.Fingerprint] {
			suppressed++
			continue
		}
		fresh = append(fresh, f)
	}
	return fresh, suppressed
}
