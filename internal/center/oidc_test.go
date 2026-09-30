package center

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOidcAllow(t *testing.T) {
	raw := "alice, Bob\ncarol; dave"
	for _, u := range []string{"alice", "Bob", "boB", "carol", "dave"} {
		if !oidcAllow(raw, u) {
			t.Errorf("%s 应命中白名单", u)
		}
	}
	for _, u := range []string{"eve", "", "mallory"} {
		if oidcAllow(raw, u) {
			t.Errorf("%s 不应命中白名单", u)
		}
	}
	if oidcAllow("", "alice") {
		t.Error("空白名单应拒绝所有人")
	}
}

func TestUpsertSSOUser(t *testing.T) {
	store, _, err := Open(filepath.Join(t.TempDir(), "center.db"), "seed-pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// 首登建户（viewer）
	u, err := store.UpsertSSOUser("alice", "sub-1", "viewer")
	if err != nil || u.Username != "alice" || u.Role != "viewer" {
		t.Fatalf("建户: %+v err=%v", u, err)
	}
	// 同 sub 再次登录：角色列表口径同步为 admin
	u, err = store.UpsertSSOUser("alice", "sub-1", "admin")
	if err != nil || u.Role != "admin" {
		t.Fatalf("角色同步: %+v err=%v", u, err)
	}
	// 本地账号（admin）同名：拒绝绑定，防 IdP 同名接管
	if _, err := store.UpsertSSOUser("admin", "sub-2", "viewer"); !errors.Is(err, ErrConflict) {
		t.Fatalf("本地撞名应 ErrConflict，实得 %v", err)
	}
	// 其他 sub 抢已有 SSO 用户名：拒绝
	if _, err := store.UpsertSSOUser("alice", "sub-3", "viewer"); !errors.Is(err, ErrConflict) {
		t.Fatalf("SSO 互撞应 ErrConflict，实得 %v", err)
	}
	// SSO 用户随机密码不可本地登录
	local, err := store.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	for _, pw := range []string{"", "seed-pw", "alice", "viewer", "admin"} {
		if bcryptCompare(local.PasswordHash, pw) {
			t.Fatalf("SSO 用户随机密码不应匹配 %q", pw)
		}
	}
}

func TestSeedOIDCEnvAndConfig(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "http://localhost:8080")
	t.Setenv("OIDC_CLIENT_ID", "leakgoose-center")
	t.Setenv("OIDC_CLIENT_SECRET", "s3cret")
	t.Setenv("OIDC_ALLOWED_USERS", "alice, bob")
	store, _, err := Open(filepath.Join(t.TempDir(), "center.db"), "seed-pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if got := store.SettingGet("oidc_issuer"); got != "http://localhost:8080" {
		t.Fatalf("issuer 注入失效: %q", got)
	}
	if !store.oidcConfigured() {
		t.Fatal("三要素齐备应视为已配置")
	}
	if !store.oidcEnabled() {
		t.Fatal("白名单非空应视为启用")
	}
	// PKCE 公开客户端：无 secret 也算已配置
	store.SettingSet("oidc_client_secret", "")
	if !store.oidcConfigured() || !store.oidcEnabled() {
		t.Fatal("公开客户端（无 secret）应视为已配置且启用")
	}
}

// 独立用例：环境变量在上一用例结束时已自动还原，此库保持未配置 → 整套 SSO 端点休眠
func TestOidcDormantWithoutConfig(t *testing.T) {
	store, _, err := Open(filepath.Join(t.TempDir(), "center.db"), "seed-pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	if store.oidcEnabled() {
		t.Fatal("未配置不应启用")
	}
	srv := NewServer(store, nil)
	req, _ := http.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	w := &captureWriter{}
	srv.Handler().ServeHTTP(w, req)
	if w.code != http.StatusServiceUnavailable {
		t.Fatalf("未配置时 login 应 503，实得 %d", w.code)
	}
}

func TestOidcRedirectURI(t *testing.T) {
	store, _, err := Open(filepath.Join(t.TempDir(), "center.db"), "seed-pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	r, _ := http.NewRequest(http.MethodGet, "http://localhost:65175/api/auth/oidc/login", nil)
	if got := store.oidcRedirectURI(r); got != "http://localhost:65175/oidc/callback" {
		t.Fatalf("按请求推断回调地址: %q", got)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := store.oidcRedirectURI(r); !strings.HasPrefix(got, "https://") {
		t.Fatalf("反代协议推断: %q", got)
	}
	store.SettingSet("oidc_redirect_base", "https://rules.example.com/")
	if got := store.oidcRedirectURI(r); got != "https://rules.example.com/oidc/callback" {
		t.Fatalf("固定基准地址: %q", got)
	}
}

// captureWriter 最小 ResponseWriter 捕获状态码
type captureWriter struct{ code int }

func (w *captureWriter) Header() http.Header         { return http.Header{} }
func (w *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureWriter) WriteHeader(code int)        { w.code = code }

func TestOidcSettingsAPI(t *testing.T) {
	app := newTestApp(t)
	// 非登录态 401
	req, _ := http.NewRequest(http.MethodGet, app.srv.URL+"/api/auth/oidc/settings", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录应 401，实得 %v %v", resp, err)
	}
	resp.Body.Close()

	// 空库默认值：未启用、secret 未设置
	code, m, _ := app.do("GET", "/api/auth/oidc/settings", nil)
	if code != 200 || m["enabled"] != false || m["clientSecretSet"] != false {
		t.Fatalf("默认设置: code=%d %v", code, m)
	}

	// 写入（含 issuer 形状校验拒绝）
	if code, m, _ = app.do("PUT", "/api/auth/oidc/settings", map[string]any{"issuer": "not-a-url"}); code != 400 {
		t.Fatalf("坏 issuer 应 400: %d %v", code, m)
	}
	code, m, _ = app.do("PUT", "/api/auth/oidc/settings", map[string]any{
		"issuer":       "http://localhost:8080",
		"clientId":     "leakgoose-center",
		"clientSecret": "s3cret",
		"allowedUsers": "admin, bob",
		"adminUsers":   "admin",
	})
	if code != 200 {
		t.Fatalf("保存设置: %d %v", code, m)
	}
	if m["clientSecretSet"] != true {
		t.Fatalf("secret 应显示已设置")
	}
	if _, has := m["clientSecret"]; has {
		t.Fatalf("secret 值不得回传")
	}
	if m["enabled"] != true {
		t.Fatalf("白名单非空应启用: %v", m)
	}

	// secret 空串 = 不改；"-" = 清除
	app.do("PUT", "/api/auth/oidc/settings", map[string]any{"clientSecret": ""})
	_, m, _ = app.do("GET", "/api/auth/oidc/settings", nil)
	if m["clientSecretSet"] != true {
		t.Fatal("空串 secret 不应清除")
	}
	app.do("PUT", "/api/auth/oidc/settings", map[string]any{"clientSecret": "-"})
	_, m, _ = app.do("GET", "/api/auth/oidc/settings", nil)
	if m["clientSecretSet"] != false {
		t.Fatal("'-' 应清除 secret")
	}

	// 清空白名单 → SSO 停用
	app.do("PUT", "/api/auth/oidc/settings", map[string]any{"allowedUsers": ""})
	_, m, _ = app.do("GET", "/api/auth/oidc/settings", nil)
	if m["enabled"] != false {
		t.Fatal("白名单清空应停用 SSO")
	}
}

func TestSeedRules(t *testing.T) {
	store, _, err := Open(filepath.Join(t.TempDir(), "center.db"), "seed-pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	builtin, err := os.ReadFile(filepath.Join("..", "..", "rules", "builtin.yaml"))
	if err != nil {
		t.Fatalf("读内置规则: %v", err)
	}
	if err := store.SeedRules(builtin); err != nil {
		t.Fatalf("SeedRules: %v", err)
	}
	list, err := store.ListRules("", nil)
	if err != nil || len(list) == 0 {
		t.Fatalf("种子后应有规则: %d %v", len(list), err)
	}
	// 二次种子不重复（幂等）
	if err := store.SeedRules(builtin); err != nil {
		t.Fatalf("二次 SeedRules: %v", err)
	}
	list2, _ := store.ListRules("", nil)
	if len(list2) != len(list) {
		t.Fatalf("二次种子不应追加: %d != %d", len(list2), len(list))
	}
	// 演示用例已挂
	cases, err := store.ListCases("cn-mobile")
	if err != nil || len(cases) != 2 {
		t.Fatalf("cn-mobile 演示用例: %d %v", len(cases), err)
	}
}
