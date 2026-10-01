// 规则中心 HTTP 服务：会话登录（UI）+ Bearer 令牌（CLI 拉包）双通道认证，
// 规则/用例/发布/审计/令牌的 REST API，以及内嵌 SPA 的静态服务。
// 会话存内存（单实例部署；重启即全员重新登录，可接受），令牌校验走库。
package center

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lucassylux/leakgoose/internal/rules"
)

// Server 规则中心服务
type Server struct {
	store *Store
	ui    fs.FS // 前端静态资源（根为 dist 内容）

	mu       sync.Mutex
	sessions map[string]session // token → 会话
}

type session struct {
	User    User
	Expires time.Time
}

const sessionTTL = 12 * time.Hour

// NewServer 构造服务；ui 传 nil 则只提供 API（无静态页）
func NewServer(store *Store, ui fs.FS) *Server {
	return &Server{store: store, ui: ui, sessions: map[string]session{}}
}

// Handler 组装路由（Go 1.22+ 方法+路径模式）
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 认证（oidc 三端点公开：config 探测 / login 发起 / callback 换码）
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth/me", s.requireUI(s.handleMe))
	mux.HandleFunc("GET /api/auth/oidc/config", s.handleOidcConfig)
	mux.HandleFunc("GET /api/auth/oidc/login", s.handleOidcLogin)
	mux.HandleFunc("POST /api/auth/oidc/callback", s.handleOidcCallback)
	mux.HandleFunc("POST /api/auth/password", s.requireUI(s.handleChangePassword))
	mux.HandleFunc("GET /api/settings/session", s.requireRole("admin", s.handleSessionSettingsGet))
	mux.HandleFunc("PUT /api/settings/session", s.requireRole("admin", s.handleSessionSettingsPut))
	mux.HandleFunc("GET /api/auth/oidc/settings", s.requireRole("admin", s.handleOidcSettingsGet))
	mux.HandleFunc("PUT /api/auth/oidc/settings", s.requireRole("admin", s.handleOidcSettingsPut))

	// 规则（UI 会话）
	mux.HandleFunc("GET /api/rules", s.requireUI(s.handleListRules))
	mux.HandleFunc("POST /api/rules", s.requireRole("editor", s.handleSaveRule))
	mux.HandleFunc("POST /api/rules/test", s.requireUI(s.handleSandbox))
	mux.HandleFunc("PUT /api/rules/{rid}", s.requireRole("editor", s.handleSaveRule))
	mux.HandleFunc("DELETE /api/rules/{rid}", s.requireRole("editor", s.handleDeleteRule))
	mux.HandleFunc("GET /api/rules/{rid}/cases", s.requireUI(s.handleListCases))
	mux.HandleFunc("PUT /api/rules/{rid}/cases", s.requireRole("editor", s.handleReplaceCases))

	// 发布与版本（读：UI 或令牌；发布：admin）
	mux.HandleFunc("POST /api/packs", s.requireRole("admin", s.handlePublish))
	mux.HandleFunc("GET /api/packs", s.requirePack(s.handleListPacks))
	// latest 与 {version} 各一条路由；.yaml 后缀在 handler 内分流（ServeMux 通配符必须整段，
	// "{version}.yaml" 这种半段通配是注册期 panic）
	mux.HandleFunc("GET /api/packs/latest", s.requirePack(s.handleGetPack))
	mux.HandleFunc("GET /api/packs/{version}", s.requirePack(s.handleGetPack))

	// 审计与令牌（admin）
	mux.HandleFunc("GET /api/audit", s.requireUI(s.handleAudit))
	mux.HandleFunc("GET /api/dicts", s.requireUI(s.handleListDicts))
	mux.HandleFunc("GET /api/dict-types", s.requireUI(s.handleListDictTypes))
	mux.HandleFunc("POST /api/dicts", s.requireRole("editor", s.handleSaveDict))
	mux.HandleFunc("DELETE /api/dicts/{id}", s.requireRole("editor", s.handleDeleteDict))
	mux.HandleFunc("GET /api/tokens", s.requireRole("admin", s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", s.requireRole("admin", s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.requireRole("admin", s.handleDeleteToken))

	// 静态 SPA（内嵌 dist；未命中路径回退 index.html 由前端路由接管）
	if s.ui != nil {
		mux.Handle("GET /", http.HandlerFunc(s.serveUI))
	}
	return s.withCommonHeaders(mux)
}

// ---------- 中间件 ----------

// withCommonHeaders 统一安全头 + 简易 CSRF 面：写请求带 Origin 且非同源即拒绝（同源 cookie 会话的前提）
func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r, origin) {
				writeErr(w, http.StatusForbidden, "跨源写请求被拒绝")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request, origin string) bool {
	host := r.Host
	if p := r.Header.Get("X-Forwarded-Host"); p != "" {
		host = p
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return origin == scheme+"://"+host
}

// requireUI 需登录会话（任何角色）
func (s *Server) requireUI(next func(w http.ResponseWriter, r *http.Request, u *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.sessionUser(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		next(w, r, u)
	}
}

// requireRole 需登录且角色满足（admin 全通过；编辑类操作 editor+admin；发布/令牌仅 admin）
func (s *Server) requireRole(min string, next func(w http.ResponseWriter, r *http.Request, u *User)) http.HandlerFunc {
	rank := map[string]int{"viewer": 1, "editor": 2, "admin": 3}
	return s.requireUI(func(w http.ResponseWriter, r *http.Request, u *User) {
		if rank[u.Role] < rank[min] {
			writeErr(w, http.StatusForbidden, "角色权限不足（需要 "+min+"）")
			return
		}
		next(w, r, u)
	})
}

// requirePack 包分发端点：会话或 Bearer 令牌任一即可（CI 用令牌，UI 预览用会话）
func (s *Server) requirePack(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionUser(r) != nil {
			next(w, r)
			return
		}
		if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer ") {
			if s.store.CheckToken(strings.TrimPrefix(b, "Bearer ")) {
				next(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="leakgoose-center"`)
		writeErr(w, http.StatusUnauthorized, "需要登录会话或 Bearer 令牌")
	}
}

// ---------- 认证 ----------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.store.GetUser(body.Username)
	if err != nil || !bcryptCompare(u.PasswordHash, body.Password) {
		// 统一文案：不区分"用户不存在/口令错误"，防用户名枚举
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	s.issueSession(w, *u)
	writeJSON(w, http.StatusOK, map[string]any{"username": u.Username, "role": u.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("lg_center_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "lg_center_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, http.StatusOK, u)
}

// handleChangePassword POST /api/auth/password：本地账号自助改密。
// SSO 绑定用户无本地密码（随机值），明确拒绝引导走 SSO
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct{ OldPassword, NewPassword string }
	if !readJSON(w, r, &body) {
		return
	}
	if u.Subject != "" {
		writeErr(w, http.StatusBadRequest, "SSO 账号无本地密码，请使用 SSO 登录")
		return
	}
	if len(body.NewPassword) < 8 {
		writeErr(w, http.StatusBadRequest, "新密码至少 8 位")
		return
	}
	current, err := s.store.GetUser(u.Username)
	if err != nil || !bcryptCompare(current.PasswordHash, body.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "原密码错误")
		return
	}
	hash, err := bcryptHash(body.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.UpdatePassword(u.Username, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(u.Username, "update", "user/"+u.Username+"/password", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- 会话设置 ----------

func (s *Server) handleSessionSettingsGet(w http.ResponseWriter, _ *http.Request, _ *User) {
	writeJSON(w, http.StatusOK, map[string]any{"ttlHours": s.store.SessionTTLHours()})
}

func (s *Server) handleSessionSettingsPut(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct{ TtlHours int }
	if !readJSON(w, r, &body) {
		return
	}
	if body.TtlHours < 1 || body.TtlHours > 168 {
		writeErr(w, http.StatusBadRequest, "会话时长需在 1-168 小时之间")
		return
	}
	s.store.SettingSet("session_ttl_hours", fmt.Sprint(body.TtlHours))
	_ = s.store.Audit(u.Username, "update", "settings/session", fmt.Sprintf("%dh", body.TtlHours))
	s.handleSessionSettingsGet(w, r, nil)
}

func (s *Server) sessionUser(r *http.Request) *User {
	c, err := r.Cookie("lg_center_session")
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.Expires) {
		return nil
	}
	return &sess.User
}

// ---------- 规则 ----------

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request, _ *User) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	var enabled *bool
	if v := r.URL.Query().Get("enabled"); v == "true" || v == "false" {
		b := v == "true"
		enabled = &b
	}
	list, err := s.store.ListRules(q, enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 空表时 Go 侧为 nil，JSON 会变 null——前端 SkTable 直接 .data.filter 会崩，
	// 与 audit/tokens/packs 同口径归一化为 []
	if list == nil {
		list = []*Rule{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request, u *User) {
	var rule Rule
	if !readJSON(w, r, &rule) {
		return
	}
	if r.PathValue("rid") != "" && r.PathValue("rid") != rule.RID {
		writeErr(w, http.StatusBadRequest, "路径与 body 的规则 id 不一致")
		return
	}
	if rule.RID == "" || rule.Pattern == "" {
		writeErr(w, http.StatusBadRequest, "id 与 pattern 必填")
		return
	}
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	// 落库前先过引擎编译（规则中心的价值：坏规则进不了草稿库）
	if _, err := tryCompile(rule); err != nil {
		writeErr(w, http.StatusBadRequest, "规则无法编译: "+err.Error())
		return
	}
	if err := s.store.UpsertRule(&rule, u.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(u.Username, actionOf(r), "rule/"+rule.RID, rule.Name)
	writeJSON(w, http.StatusOK, rule)
}

func actionOf(r *http.Request) string {
	if r.Method == http.MethodPost {
		return "create"
	}
	return "update"
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request, u *User) {
	rid := r.PathValue("rid")
	if err := s.store.DeleteRule(rid); err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.store.Audit(u.Username, "delete", "rule/"+rid, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSandbox 测试沙箱：pattern+validate+样例 → 命中（真实引擎，UI 即所得）
func (s *Server) handleSandbox(w http.ResponseWriter, r *http.Request, _ *User) {
	var body struct{ Pattern, Validate, Sample string }
	if !readJSON(w, r, &body) {
		return
	}
	hits, err := tryMatch(body.Pattern, body.Validate, body.Sample)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if hits == nil {
		hits = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": hits})
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request, _ *User) {
	cases, err := s.store.ListCases(r.PathValue("rid"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cases == nil {
		cases = []TestCase{}
	}
	writeJSON(w, http.StatusOK, cases)
}

func (s *Server) handleReplaceCases(w http.ResponseWriter, r *http.Request, u *User) {
	var cases []TestCase
	if !readJSON(w, r, &cases) {
		return
	}
	rid := r.PathValue("rid")
	if _, err := s.store.GetRule(rid); err != nil {
		writeStoreErr(w, err)
		return
	}
	if err := s.store.ReplaceCases(rid, cases); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(u.Username, "update-cases", "rule/"+rid, fmt.Sprintf("%d 条", len(cases)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(cases)})
}

// ---------- 发布 ----------

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct{ Changelog string }
	if !readJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Changelog) == "" {
		writeErr(w, http.StatusBadRequest, "changelog 必填（发布说明进入版本历史）")
		return
	}
	pack, err := s.store.Publish(body.Changelog, u.Username)
	if err != nil {
		var rej *PublishRejected
		if errors.As(err, &rej) {
			writeErr(w, http.StatusUnprocessableEntity, rej.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pack)
}

func (s *Server) handleListPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListPacks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []PackRow{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetPack(w http.ResponseWriter, r *http.Request) {
	// 末段以 .yaml 结尾 → 规则文件形态输出（scan -r 直接可用的 schema），否则 JSON
	if strings.HasSuffix(r.URL.Path, ".yaml") {
		p, err := s.pickPack(r)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write([]byte(p.RulesYAML))
		return
	}
	p, err := s.pickPack(r)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	// JSON 形态 = 元数据 + 规则清单（从 YAML 快照反解；包小无性能顾虑，且 YAML 快照是唯一事实源）
	var out packJSON
	if err := yamlUnmarshal([]byte(p.RulesYAML), &out); err != nil {
		writeErr(w, http.StatusInternalServerError, "包快照反解失败: "+err.Error())
		return
	}
	out.Changelog, out.PublishedBy, out.PublishedAt = p.Changelog, p.PublishedBy, p.PublishedAt
	if out.Rules == nil {
		out.Rules = []*rules.Rule{}
	}
	writeJSON(w, http.StatusOK, out)
}

// packJSON 分发载荷：与 YAML 快照同构 + 发布元数据（CLI sync 消费同一形状）
type packJSON struct {
	Version     string        `json:"version" yaml:"version"`
	Sha256      string        `json:"sha256" yaml:"sha256"`
	Changelog   string        `json:"changelog,omitempty"`
	PublishedBy string        `json:"publishedBy,omitempty"`
	PublishedAt string        `json:"publishedAt,omitempty"`
	Rules       []*rules.Rule `json:"rules" yaml:"rules"`
}

func (s *Server) pickPack(r *http.Request) (*PackRow, error) {
	if r.URL.Path == "/api/packs/latest" || r.URL.Path == "/api/packs/latest.yaml" {
		return s.store.LatestPack()
	}
	version := strings.TrimSuffix(r.PathValue("version"), ".yaml")
	return s.store.GetPack(version)
}

// ---------- 审计 / 令牌 ----------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ *User) {
	list, err := s.store.ListAudit(500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, list)
}

// ---------- 数据字典 ----------

func (s *Server) handleListDictTypes(w http.ResponseWriter, _ *http.Request, _ *User) {
	list, err := s.store.ListDictTypes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []DictType{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleListDicts(w http.ResponseWriter, r *http.Request, _ *User) {
	t := r.URL.Query().Get("type")
	if t == "" {
		writeErr(w, http.StatusBadRequest, "type 必填")
		return
	}
	// 编辑态要看到停用项，业务取值只要启用的（?enabled=true）
	onlyEnabled := r.URL.Query().Get("enabled") == "true"
	list, err := s.store.ListDicts(t, onlyEnabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []DictItem{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSaveDict(w http.ResponseWriter, r *http.Request, u *User) {
	var d DictItem
	if !readJSON(w, r, &d) {
		return
	}
	if err := s.store.SaveDict(&d, u.Username); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeleteDict(w http.ResponseWriter, r *http.Request, u *User) {
	var id int64
	if _, err := fmt.Sscan(r.PathValue("id"), &id); err != nil {
		writeErr(w, http.StatusBadRequest, "id 非法")
		return
	}
	if err := s.store.DeleteDict(id); err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.store.Audit(u.Username, "delete", fmt.Sprintf("dict/%d", id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, _ *User) {
	list, err := s.store.ListTokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []Token{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct{ Name string }
	if !readJSON(w, r, &body) || strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name 必填")
		return
	}
	plain, err := s.store.CreateToken(strings.TrimSpace(body.Name), u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 明文仅此一次返回
	writeJSON(w, http.StatusOK, map[string]string{"name": body.Name, "token": plain})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, u *User) {
	var id int64
	if _, err := fmt.Sscan(r.PathValue("id"), &id); err != nil {
		writeErr(w, http.StatusBadRequest, "id 非法")
		return
	}
	if err := s.store.DeleteToken(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(u.Username, "delete-token", fmt.Sprintf("token/%d", id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- 静态 SPA ----------

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if _, err := fs.Stat(s.ui, path); err != nil {
		path = "index.html" // 前端路由回退
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, s.ui, path)
}

// ---------- 助手 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "不存在")
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return false
	}
	return true
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
