package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucassylux/leakgoose/internal/scan"
)

func TestBaselineRoundtrip(t *testing.T) {
	dir := t.TempDir()
	bp := filepath.Join(dir, "sub", "baseline.json") // Save 应自动建父目录
	findings := []scan.Finding{
		{Rule: "a", Severity: "critical", File: "f.txt", Line: 1, Secret: "s1", Fingerprint: scan.Fingerprint("a", "f.txt", "s1")},
		{Rule: "b", Severity: "high", File: "g.txt", Line: 2, Secret: "s2", Fingerprint: scan.Fingerprint("b", "g.txt", "s2")},
	}
	if err := Save(bp, findings); err != nil {
		t.Fatalf("Save: %v", err)
	}
	base, err := Load(bp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(base) != 2 {
		t.Fatalf("基线应含 2 条指纹，实际 %d", len(base))
	}
	// 同指纹豁免 + 新发现保留
	mixed := append(findings, scan.Finding{
		Rule: "c", Severity: "medium", File: "h.txt", Line: 3, Secret: "s3",
		Fingerprint: scan.Fingerprint("c", "h.txt", "s3"),
	})
	fresh, suppressed := Filter(mixed, base)
	if len(fresh) != 1 || fresh[0].Rule != "c" || suppressed != 2 {
		t.Fatalf("基线过滤异常: fresh=%d suppressed=%d", len(fresh), suppressed)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	base, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(base) != 0 {
		t.Fatalf("缺失基线文件应为空基线: %v %d", err, len(base))
	}
}

func TestLoadBadVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(`{"version":9,"fingerprints":[]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("不支持的版本应报错")
	}
}
