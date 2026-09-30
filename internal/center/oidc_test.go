package center

import (
	"errors"
	"net/http"
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
