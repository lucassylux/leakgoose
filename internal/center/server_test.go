package center

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucassylux/leakgoose/internal/rules"
)

// newTestServer 每用例独立临时库 + 已登录会话的客户端封装
type testApp struct {
	t       *testing.T
	srv     *httptest.Server
	store   *Store
	session *http.Client // 带 cookie 的客户端（登录后）
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	store, adminPw, err := Open(filepath.Join(t.TempDir(), "center.db"), "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if adminPw == "" {
		t.Fatal("首次启动应返回一次性初始口令")
	}
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	t.Cleanup(func() { srv.Close(); _ = store.Close() })

	jar, _ := cookiejar.New(nil)
	app := &testApp{t: t, srv: srv, store: store, session: &http.Client{Jar: jar}}
	app.login("admin", adminPw)
	return app
}

func (a *testApp) login(username, password string) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := a.session.Post(a.srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		a.t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		a.t.Fatalf("login 状态码 %d", resp.StatusCode)
	}
}

func (a *testApp) do(method, path string, body any) (int, map[string]any, string) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, a.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.session.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(buf.Bytes(), &m)
	return resp.StatusCode, m, buf.String()
}

func TestAuthFlow(t *testing.T) {
	store, pw, _ := Open(filepath.Join(t.TempDir(), "c.db"), "")
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	t.Cleanup(func() { srv.Close(); _ = store.Close() })
	_ = store.Close()

	// 错误口令 401 且文案不区分用户名/口令（防枚举）
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("错误口令应 401，实际 %d", resp.StatusCode)
	}

	// 未登录访问受保护端点 401
	resp2, _ := http.Get(srv.URL + "/api/rules")
	if resp2.StatusCode != 401 {
		t.Fatalf("未登录应 401，实际 %d", resp2.StatusCode)
	}
	_ = pw
}

func TestRuleCRUDAndSandbox(t *testing.T) {
	app := newTestApp(t)

	// 建规则（带验真）
	code, m, _ := app.do("POST", "/api/rules", map[string]any{
		"id": "test-mobile", "name": "测试手机号", "severity": "high",
		"pattern": `(?<!\d)1[3-9]\d{9}(?!\d)`, "validate": "builtin:cn-mobile-segment", "enabled": true,
	})
	if code != 200 {
		t.Fatalf("建规则失败: %d %v", code, m)
	}

	// 坏正则被引擎拒绝入库
	code, m, _ = app.do("POST", "/api/rules", map[string]any{
		"id": "bad", "pattern": "[", "severity": "low",
	})
	if code != 400 || !strings.Contains(m["error"].(string), "编译") {
		t.Fatalf("坏正则应 400 且提示编译失败: %d %v", code, m)
	}

	// 沙箱：真实样例命中、校验位拦截误报样例
	code, m, _ = app.do("POST", "/api/rules/test", map[string]any{
		"pattern": `(?<!\d)1[3-9]\d{9}(?!\d)`, "validate": "builtin:cn-mobile-segment",
		"sample": "联系 13800138000 或 10000000000",
	})
	if code != 200 {
		t.Fatalf("沙箱失败: %v", m)
	}
	hits := m["hits"].([]any)
	if len(hits) != 1 || hits[0] != "13800138000" {
		t.Fatalf("沙箱应只命中合法号段手机号: %v", hits)
	}

	// 用例整组替换 + 回读
	code, _, _ = app.do("PUT", "/api/rules/test-mobile/cases", []map[string]any{
		{"ruleId": "test-mobile", "input": "13800138000", "expectMatch": true},
		{"ruleId": "test-mobile", "input": "10000000000", "expectMatch": false},
	})
	if code != 200 {
		t.Fatalf("用例保存失败: %d", code)
	}
	code, _, raw := app.do("GET", "/api/rules/test-mobile/cases", nil)
	var caseArr []TestCase
	if code != 200 || json.Unmarshal([]byte(raw), &caseArr) != nil || len(caseArr) != 2 {
		t.Fatalf("用例回读异常 code=%d raw=%s", code, raw)
	}
}

func TestPublishGateAndPackAPI(t *testing.T) {
	app := newTestApp(t)

	// 建规则 + 一条会失败的用例 → 发布必须被拒
	app.do("POST", "/api/rules", map[string]any{
		"id": "r1", "name": "x", "severity": "low", "pattern": `LTAI[0-9A-Za-z]{12,20}`, "enabled": true,
	})
	app.do("PUT", "/api/rules/r1/cases", []map[string]any{
		{"ruleId": "r1", "input": "LTAIabcdefghijkl", "expectMatch": false}, // 期望不命中但会命中
	})
	code, m, _ := app.do("POST", "/api/packs", map[string]string{"changelog": "v1"})
	if code != 422 || !strings.Contains(m["error"].(string), "r1") {
		t.Fatalf("用例回归失败应 422 拒绝发布: %d %v", code, m)
	}

	// 修正用例 → 发布成功，版本号为当日序号式
	app.do("PUT", "/api/rules/r1/cases", []map[string]any{
		{"ruleId": "r1", "input": "LTAIabcdefghijkl", "expectMatch": true},
	})
	code, m, _ = app.do("POST", "/api/packs", map[string]string{"changelog": "首发"})
	if code != 200 {
		t.Fatalf("发布失败: %d %v", code, m)
	}
	version := m["version"].(string)
	if !strings.Contains(version, "-1") {
		t.Fatalf("当日首个版本应为 -1 结尾: %s", version)
	}

	// changelog 必填
	code, _, _ = app.do("POST", "/api/packs", map[string]string{"changelog": " "})
	if code != 400 {
		t.Fatalf("空 changelog 应 400: %d", code)
	}

	// 未带令牌拉包 401
	resp, _ := http.Get(app.srv.URL + "/api/packs/latest")
	if resp.StatusCode != 401 {
		t.Fatalf("无凭证拉包应 401: %d", resp.StatusCode)
	}

	// 建读令牌 → 拉 JSON 与 YAML 包，校验和自证
	_, m, _ = app.do("POST", "/api/tokens", map[string]string{"name": "ci"})
	token := m["token"].(string)
	req, _ := http.NewRequest("GET", app.srv.URL+"/api/packs/latest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	var pack rules.Pack
	_ = json.NewDecoder(resp.Body).Decode(&pack)
	resp.Body.Close()
	if pack.Version != version || len(pack.Rules) != 1 || pack.Rules[0].ID != "r1" {
		t.Fatalf("包内容异常: %+v", pack)
	}
	if !pack.Verify() {
		t.Fatalf("包校验和不匹配（sha256=%s）", pack.Sha256)
	}

	// YAML 端点与 scan -r 同构（能被规则加载器解析）
	req2, _ := http.NewRequest("GET", app.srv.URL+"/api/packs/"+version+".yaml", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, _ := http.DefaultClient.Do(req2)
	var ybuf bytes.Buffer
	_, _ = ybuf.ReadFrom(resp2.Body)
	resp2.Body.Close()
	if s, err := rules.Load(ybuf.Bytes(), nil); err != nil || len(s.Rules) != 1 {
		t.Fatalf("YAML 包应可直接作为规则文件加载: err=%v", err)
	}

	// 指定版本 + 不存在版本
	req3, _ := http.NewRequest("GET", app.srv.URL+"/api/packs/nope-9", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	resp3, _ := http.DefaultClient.Do(req3)
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Fatalf("不存在的版本应 404: %d", resp3.StatusCode)
	}

	// 审计含发布记录
	_, _, raw := app.do("GET", "/api/audit", nil)
	if !strings.Contains(raw, `"publish"`) {
		t.Fatalf("审计应含 publish 记录: %s", raw)
	}
}

func TestPackVersionSequence(t *testing.T) {
	store, _, _ := Open(filepath.Join(t.TempDir(), "c.db"), "pw123456")
	t.Cleanup(func() { _ = store.Close() })
	if err := store.UpsertRule(&Rule{RID: "r", Name: "x", Severity: "low", Pattern: "LTAI[0-9A-Za-z]{12,20}", Enabled: true}, "admin"); err != nil {
		t.Fatalf("建规则: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := store.Publish("第"+string(rune('1'+i))+"版", "admin"); err != nil {
			t.Fatalf("第 %d 次发布失败: %v", i+1, err)
		}
	}
	p, err := store.LatestPack()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.Version, "-3") {
		t.Fatalf("第三次发布版本应为 -3: %s", p.Version)
	}
}
