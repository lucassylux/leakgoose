// Package center 实现规则中心服务端：规则草稿 CRUD、测试用例、版本化发布、
// 规则包分发 API、审计。存储默认 SQLite（单文件、零运维），规则数据量小（几十条），
// 单连接串行写足够且天然规避 SQLITE_BUSY。
package center

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动：保住 CGO_ENABLED=0 的六平台交叉编译

	"github.com/lucassylux/leakgoose/internal/rules"
)

// Rule 草稿态规则（存储形态；keywords/paths 以 CSV 存列，读取时拆分）
type Rule struct {
	RID          string   `json:"id"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Pattern      string   `json:"pattern"`
	Validate     string   `json:"validate,omitempty"`
	Keywords     []string `json:"keywords,omitempty"`
	IncludePaths []string `json:"include-paths,omitempty"`
	ExcludePaths []string `json:"exclude-paths,omitempty"`
	Enabled      bool     `json:"enabled"`
	Description  string   `json:"description,omitempty"`
	UpdatedBy    string   `json:"updatedBy,omitempty"`
	UpdatedAt    string   `json:"updatedAt,omitempty"`
}

// TestCase 规则用例：样例输入 + 期望命中（发布前全量回归）
type TestCase struct {
	ID          int64  `json:"id,omitempty"`
	RuleRID     string `json:"ruleId"`
	Input       string `json:"input"`
	ExpectMatch bool   `json:"expectMatch"`
}

// PackRow 已发布包记录
type PackRow struct {
	Version     string `json:"version"`
	Sha256      string `json:"sha256"`
	Changelog   string `json:"changelog"`
	PublishedBy string `json:"publishedBy"`
	PublishedAt string `json:"publishedAt"`
	RulesYAML   string `json:"-"` // 分发时使用，列表不回传
}

// Token API 读令牌（哈希落库，明文仅创建时一次性返回）
type Token struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	TokenHash string `json:"-"`
	CreatedAt string `json:"createdAt"`
	LastUsed  string `json:"lastUsed,omitempty"`
}

// AuditEntry 审计记录
type AuditEntry struct {
	ID     int64  `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Entity string `json:"entity"`
	Detail string `json:"detail,omitempty"`
}

// User 登录用户
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"` // admin / editor / viewer
	Subject      string `json:"-"`    // OIDC sub（SSO 用户非空；按 subject 绑定而非用户名，防 IdP 同名接管本地账号）
}

// ErrConflict 状态冲突（如 SSO 用户名与本地账号撞名）
var ErrConflict = errors.New("conflict")

var ErrNotFound = errors.New("not found")

// Store SQLite 存储
type Store struct {
	db *sql.DB
}

// Open 打开（或初始化）库文件；首次启动种子管理员，返回管理员初始口令（调用方打印一次性告知）
func Open(path, seedAdminPassword string) (*Store, string, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, "", err
	}
	db.SetMaxOpenConns(1) // 单写者串行：规则中心流量小，彻底规避 SQLITE_BUSY
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, "", err
	}
	s.seedOIDCEnv()                       // 环境变量注入 SSO 配置（settings 已有值不覆盖）
	if err := s.seedDicts(); err != nil { // 数据字典种子（严重级中文映射）
		return nil, "", err
	}
	if seedAdminPassword != "" {
		if err := s.SeedAdmin(seedAdminPassword); err != nil {
			return nil, "", err
		}
		return s, "", nil
	}
	// 未显式给初始口令：仅当尚无用户时生成随机口令（一次性返回；忘了就删 users 行重来）
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return nil, "", err
	}
	if n == 0 {
		pw, err := randomToken(16)
		if err != nil {
			return nil, "", err
		}
		if err := s.SeedAdmin(pw); err != nil {
			return nil, "", err
		}
		return s, pw, nil
	}
	return s, "", nil
}

// Close 关闭库
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users(
			username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS rules(
			rid TEXT PRIMARY KEY, name TEXT NOT NULL, severity TEXT NOT NULL, pattern TEXT NOT NULL,
			validate TEXT NOT NULL DEFAULT '', keywords TEXT NOT NULL DEFAULT '',
			include_paths TEXT NOT NULL DEFAULT '', exclude_paths TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1, description TEXT NOT NULL DEFAULT '',
			updated_by TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS test_cases(
			id INTEGER PRIMARY KEY AUTOINCREMENT, rule_rid TEXT NOT NULL,
			input TEXT NOT NULL, expect_match INTEGER NOT NULL, sort INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS packs(
			version TEXT PRIMARY KEY, sha256 TEXT NOT NULL, changelog TEXT NOT NULL DEFAULT '',
			published_by TEXT NOT NULL, published_at TEXT NOT NULL, rules_yaml TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS api_tokens(
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
			created_at TEXT NOT NULL, last_used_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS audit(
			id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
			action TEXT NOT NULL, entity TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS settings(
			key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS dicts(
			id INTEGER PRIMARY KEY AUTOINCREMENT, dict_type TEXT NOT NULL,
			label TEXT NOT NULL, value TEXT NOT NULL, sort INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("初始化表结构: %w", err)
		}
	}
	// 旧库升级：users 补 subject 列（已存在则忽略重复列错误）
	if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN subject TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return fmt.Errorf("升级 users 表: %w", err)
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_subject ON users(subject) WHERE subject != ''`); err != nil {
		return fmt.Errorf("建 subject 索引: %w", err)
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dicts_type_value ON dicts(dict_type, value)`); err != nil {
		return fmt.Errorf("建字典唯一索引: %w", err)
	}
	return nil
}

// ---------- 数据字典 ----------

// DictItem 字典项（type 分组：如 rule-severity；label 展示中文，value 为编码落库）
type DictItem struct {
	ID      int64  `json:"id,omitempty"`
	Type    string `json:"type"`
	Label   string `json:"label"`
	Value   string `json:"value"`
	Sort    int    `json:"sort"`
	Enabled bool   `json:"enabled"`
}

// DictType 字典类型汇总（类型页：类型编码 + 展示名 + 项数）
type DictType struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// 系统内置字典类型的展示名（未知类型回退编码本身）
var dictTypeNames = map[string]string{
	"rule-severity": "规则严重级",
}

// seedDicts 首启种子：规则严重级中文映射（编码即内置规则口径）
func (s *Store) seedDicts() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dicts`).Scan(&n); err != nil || n > 0 {
		return err
	}
	seed := []DictItem{
		{Type: "rule-severity", Label: "严重", Value: "critical", Sort: 1, Enabled: true},
		{Type: "rule-severity", Label: "高", Value: "high", Sort: 2, Enabled: true},
		{Type: "rule-severity", Label: "中", Value: "medium", Sort: 3, Enabled: true},
		{Type: "rule-severity", Label: "低", Value: "low", Sort: 4, Enabled: true},
	}
	for _, d := range seed {
		if err := s.SaveDict(&d, "seed"); err != nil {
			return err
		}
	}
	return nil
}

// ListDictTypes 类型汇总（有项才出现）
func (s *Store) ListDictTypes() ([]DictType, error) {
	rows, err := s.db.Query(`SELECT dict_type, COUNT(*) FROM dicts GROUP BY dict_type ORDER BY dict_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DictType
	for rows.Next() {
		t := DictType{}
		if err := rows.Scan(&t.Type, &t.Count); err != nil {
			return nil, err
		}
		t.Name = dictTypeNames[t.Type]
		if t.Name == "" {
			t.Name = t.Type
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListDicts 某类型的字典项（仅启用的开关由调用方控制；排序 sort,id）
func (s *Store) ListDicts(dictType string, onlyEnabled bool) ([]DictItem, error) {
	sb := strings.Builder{}
	sb.WriteString(`SELECT id,dict_type,label,value,sort,enabled FROM dicts WHERE dict_type=?`)
	if onlyEnabled {
		sb.WriteString(` AND enabled=1`)
	}
	sb.WriteString(` ORDER BY sort,id`)
	rows, err := s.db.Query(sb.String(), dictType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DictItem
	for rows.Next() {
		d := DictItem{}
		var en int
		if err := rows.Scan(&d.ID, &d.Type, &d.Label, &d.Value, &d.Sort, &en); err != nil {
			return nil, err
		}
		d.Enabled = en == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDict 新增或更新（ID 为空新增；同类型下 value 唯一）
func (s *Store) SaveDict(d *DictItem, actor string) error {
	if d.Type == "" || d.Label == "" || d.Value == "" {
		return errors.New("type/label/value 必填")
	}
	if d.ID == 0 {
		res, err := s.db.Exec(
			`INSERT INTO dicts(dict_type,label,value,sort,enabled,created_at) VALUES(?,?,?,?,?,?)`,
			d.Type, d.Label, d.Value, d.Sort, b2i(d.Enabled), now())
		if err != nil {
			return fmt.Errorf("同类型下 value 需唯一: %w", err)
		}
		d.ID, _ = res.LastInsertId()
	} else {
		res, err := s.db.Exec(
			`UPDATE dicts SET dict_type=?,label=?,value=?,sort=?,enabled=? WHERE id=?`,
			d.Type, d.Label, d.Value, d.Sort, b2i(d.Enabled), d.ID)
		if err != nil {
			return fmt.Errorf("同类型下 value 需唯一: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	action := "update"
	if d.ID == 0 {
		action = "create"
	}
	_ = s.Audit(actor, action, "dict/"+d.Type+"/"+d.Value, d.Label)
	return nil
}

// DeleteDict 删除字典项
func (s *Store) DeleteDict(id int64) error {
	res, err := s.db.Exec(`DELETE FROM dicts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- 用户 ----------

// SeedAdmin 首次种子管理员（已存在则跳过；bcrypt 存哈希）
func (s *Store) SeedAdmin(password string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcryptHash(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES('admin', ?, 'admin', ?)`,
		hash, now())
	return err
}

// CreateUser 建用户（admin 用）
func (s *Store) CreateUser(username, password, role string) error {
	hash, err := bcryptHash(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`,
		username, hash, role, now())
	return err
}

// GetUser 按用户名取
func (s *Store) GetUser(username string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT username, password_hash, role, subject FROM users WHERE username=?`, username).
		Scan(&u.Username, &u.PasswordHash, &u.Role, &u.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// UpdatePassword 本地账号改密（已 bcrypt 的哈希直接落库）
func (s *Store) UpdatePassword(username, passwordHash string) error {
	res, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE username=?`, passwordHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionTTLHours 会话时长（settings.session_ttl_hours；缺省/非法回退 12，范围 1-168）
func (s *Store) SessionTTLHours() int {
	var v int
	if _, err := fmt.Sscan(s.SettingGet("session_ttl_hours"), &v); err != nil || v < 1 || v > 168 {
		return 12
	}
	return v
}

// GetUserBySubject 按 OIDC sub 取（SSO 用户的唯一绑定键）
func (s *Store) GetUserBySubject(subject string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT username, password_hash, role, subject FROM users WHERE subject=?`, subject).
		Scan(&u.Username, &u.PasswordHash, &u.Role, &u.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// UpsertSSOUser SSO 登录落库：按 subject 找到则同步角色，否则建户。
// 用户名被本地账号（subject 为空）占用时拒绝——不按用户名绑定，防 IdP 同名接管本地账号。
// SSO 用户密码为随机值，本地密码登录不可用。
func (s *Store) UpsertSSOUser(username, subject, role string) (*User, error) {
	if u, err := s.GetUserBySubject(subject); err == nil {
		if u.Role != role {
			_, _ = s.db.Exec(`UPDATE users SET role=? WHERE username=?`, role, u.Username)
			u.Role = role
		}
		return u, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// 用户名占用检查：本地账号（subject 空）或其他 SSO 账号（sub 不同）都不让抢
	if existing, err := s.GetUser(username); err == nil {
		if existing.Subject != subject {
			return nil, fmt.Errorf("%w: 用户名 %s 已被%s占用", ErrConflict, username,
				map[bool]string{true: "本地账号", false: "其他 SSO 账号"}[existing.Subject == ""])
		}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	random, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	hash, err := bcryptHash(random)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, created_at, subject) VALUES(?,?,?,?,?)
		 ON CONFLICT(username) DO UPDATE SET subject=excluded.subject, role=excluded.role`,
		username, hash, role, now(), subject); err != nil {
		return nil, err
	}
	return &User{Username: username, Role: role, Subject: subject}, nil
}

// ---------- 设置（键值） ----------

// SeedRules 首启种子规则：规则表为空时把内置规则包导入为草稿（含演示用例），
// 新中心开箱即有可维护/可发布的内容，而非空白
func (s *Store) SeedRules(builtinYAML []byte) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&n); err != nil || n > 0 {
		return err
	}
	set, err := rules.Load(builtinYAML, nil)
	if err != nil {
		return fmt.Errorf("解析内置规则: %w", err)
	}
	for _, r := range set.Rules {
		draft := &Rule{
			RID: r.ID, Name: r.Name, Severity: r.Severity, Pattern: r.Pattern,
			Validate: r.Validate, Keywords: r.Keywords,
			IncludePaths: r.IncludePaths, ExcludePaths: r.ExcludePaths,
			Enabled: true, UpdatedBy: "seed",
		}
		if err := s.UpsertRule(draft, "seed"); err != nil {
			return err
		}
	}
	// 演示用例：让「用例回归门禁」与编辑器用例区开箱可演示
	demo := map[string][]TestCase{
		"cn-id-card": {
			{RuleRID: "cn-id-card", Input: "身份证号 11010519491231002X", ExpectMatch: true},
		},
		"cn-mobile": {
			{RuleRID: "cn-mobile", Input: "联系电话 13800138000", ExpectMatch: true},
			{RuleRID: "cn-mobile", Input: "工单号 2026093012345", ExpectMatch: false},
		},
		"aliyun-access-key-id": {
			{RuleRID: "aliyun-access-key-id", Input: "LTAI5tFakeKeyForDemo00k", ExpectMatch: true},
		},
	}
	for rid, cases := range demo {
		if _, err := s.GetRule(rid); err == nil {
			if err := s.ReplaceCases(rid, cases); err != nil {
				return err
			}
		}
	}
	_ = s.Audit("seed", "create", "rules/builtin", fmt.Sprintf("首启导入内置规则 %d 条", len(set.Rules)))
	return nil
}

// SettingGet 读设置（不存在返回空串）
func (s *Store) SettingGet(key string) string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v
}

// SettingSet 写设置（空串即停用该配置项）
func (s *Store) SettingSet(key, value string) {
	_, _ = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
}

// ---------- 规则 ----------

func (s *Store) ListRules(q string, enabled *bool) ([]*Rule, error) {
	sb := strings.Builder{}
	args := []any{}
	sb.WriteString(`SELECT rid,name,severity,pattern,validate,keywords,include_paths,exclude_paths,enabled,description,updated_by,updated_at FROM rules WHERE 1=1`)
	if q != "" {
		sb.WriteString(` AND (rid LIKE ? OR name LIKE ?)`)
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	if enabled != nil {
		sb.WriteString(` AND enabled=?`)
		args = append(args, *enabled)
	}
	sb.WriteString(` ORDER BY rid`)
	rows, err := s.db.Query(sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Rule
	for rows.Next() {
		r := &Rule{}
		var kw, inc, exc string
		var en int
		if err := rows.Scan(&r.RID, &r.Name, &r.Severity, &r.Pattern, &r.Validate, &kw, &inc, &exc, &en, &r.Description, &r.UpdatedBy, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.Keywords = splitCSV(kw)
		r.IncludePaths = splitCSV(inc)
		r.ExcludePaths = splitCSV(exc)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRule(rid string) (*Rule, error) {
	list, err := s.ListRules("", nil)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		if r.RID == rid {
			return r, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) UpsertRule(r *Rule, actor string) error {
	if _, err := s.db.Exec(
		`INSERT INTO rules(rid,name,severity,pattern,validate,keywords,include_paths,exclude_paths,enabled,description,updated_by,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(rid) DO UPDATE SET name=excluded.name,severity=excluded.severity,pattern=excluded.pattern,
		   validate=excluded.validate,keywords=excluded.keywords,include_paths=excluded.include_paths,
		   exclude_paths=excluded.exclude_paths,enabled=excluded.enabled,description=excluded.description,
		   updated_by=excluded.updated_by,updated_at=excluded.updated_at`,
		r.RID, r.Name, r.Severity, r.Pattern, r.Validate, joinCSV(r.Keywords),
		joinCSV(r.IncludePaths), joinCSV(r.ExcludePaths), b2i(r.Enabled), r.Description,
		actor, now()); err != nil {
		return err
	}
	return nil
}

func (s *Store) DeleteRule(rid string) error {
	res, err := s.db.Exec(`DELETE FROM rules WHERE rid=?`, rid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.db.Exec(`DELETE FROM test_cases WHERE rule_rid=?`, rid)
	return nil
}

// ---------- 用例 ----------

func (s *Store) ListCases(rid string) ([]TestCase, error) {
	rows, err := s.db.Query(`SELECT id,rule_rid,input,expect_match FROM test_cases WHERE rule_rid=? ORDER BY sort,id`, rid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TestCase
	for rows.Next() {
		c := TestCase{}
		var em int
		if err := rows.Scan(&c.ID, &c.RuleRID, &c.Input, &em); err != nil {
			return nil, err
		}
		c.ExpectMatch = em == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceCases 整组替换某规则的用例
func (s *Store) ReplaceCases(rid string, cases []TestCase) error {
	if _, err := s.db.Exec(`DELETE FROM test_cases WHERE rule_rid=?`, rid); err != nil {
		return err
	}
	for i, c := range cases {
		if _, err := s.db.Exec(`INSERT INTO test_cases(rule_rid,input,expect_match,sort) VALUES(?,?,?,?)`,
			rid, c.Input, b2i(c.ExpectMatch), i); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 发布 ----------

// Publish 发布当前启用规则为不可变版本：先跑全部用例回归（失败即拒绝），
// 再生成版本号/快照/校验和落库。返回新版本。
func (s *Store) Publish(changelog, actor string) (*rules.Pack, error) {
	enabled := true
	rl, err := s.ListRules("", &enabled)
	if err != nil {
		return nil, err
	}
	if len(rl) == 0 {
		return nil, errors.New("没有启用中的规则，拒绝发布空包")
	}
	// 用例回归：任何一条期望不符即拒绝发布（规则质量的门禁）
	var failures []string
	for _, r := range rl {
		cases, err := s.ListCases(r.RID)
		if err != nil {
			return nil, err
		}
		for _, c := range cases {
			hits, err := rules.TryMatch(r.Pattern, r.Validate, c.Input)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: 规则自身配置错误: %v", r.RID, err))
				continue
			}
			if (len(hits) > 0) != c.ExpectMatch {
				failures = append(failures, fmt.Sprintf("%s: 用例「%s」期望%v，实际%v",
					r.RID, short(c.Input), c.ExpectMatch, len(hits) > 0))
			}
		}
	}
	if len(failures) > 0 {
		return nil, &PublishRejected{Failures: failures}
	}

	nowT := time.Now()
	version := rules.NewPackVersion(nowT, s.countPacksOn(nowT))
	pack := &rules.Pack{Version: version, GeneratedAt: now()}
	for _, r := range rl {
		pack.Rules = append(pack.Rules, &rules.Rule{
			ID: r.RID, Name: r.Name, Severity: r.Severity, Pattern: r.Pattern,
			Validate: r.Validate, Keywords: r.Keywords,
			IncludePaths: r.IncludePaths, ExcludePaths: r.ExcludePaths,
		})
	}
	pack.Sha256 = pack.ComputeChecksum()
	yamlData, err := yamlMarshal(struct {
		Version string        `yaml:"version"`
		Sha256  string        `yaml:"sha256"`
		Rules   []*rules.Rule `yaml:"rules"`
	}{pack.Version, pack.Sha256, pack.Rules})
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO packs(version,sha256,changelog,published_by,published_at,rules_yaml) VALUES(?,?,?,?,?,?)`,
		pack.Version, pack.Sha256, changelog, actor, now(), string(yamlData)); err != nil {
		return nil, err
	}
	_ = s.Audit(actor, "publish", "pack/"+version, changelog)
	return pack, nil
}

// PublishRejected 用例回归失败（携带逐条原因）
type PublishRejected struct{ Failures []string }

func (e *PublishRejected) Error() string {
	return "用例回归未通过，已拒绝发布:\n" + strings.Join(e.Failures, "\n")
}

func (s *Store) countPacksOn(t time.Time) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM packs WHERE version LIKE ?`, t.Format("2006.01.02")+"-%").Scan(&n)
	return n
}

// LatestPack 最新已发布包（按时间倒序第一行）
func (s *Store) LatestPack() (*PackRow, error) {
	row := s.db.QueryRow(`SELECT version,sha256,changelog,published_by,published_at,rules_yaml FROM packs ORDER BY published_at DESC, version DESC LIMIT 1`)
	return scanPack(row)
}

// GetPack 指定版本
func (s *Store) GetPack(version string) (*PackRow, error) {
	row := s.db.QueryRow(`SELECT version,sha256,changelog,published_by,published_at,rules_yaml FROM packs WHERE version=?`, version)
	return scanPack(row)
}

func scanPack(row *sql.Row) (*PackRow, error) {
	p := &PackRow{}
	err := row.Scan(&p.Version, &p.Sha256, &p.Changelog, &p.PublishedBy, &p.PublishedAt, &p.RulesYAML)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// ListPacks 版本列表（新→旧）
func (s *Store) ListPacks() ([]PackRow, error) {
	rows, err := s.db.Query(`SELECT version,sha256,changelog,published_by,published_at,'' FROM packs ORDER BY published_at DESC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackRow
	for rows.Next() {
		p := PackRow{}
		if err := rows.Scan(&p.Version, &p.Sha256, &p.Changelog, &p.PublishedBy, &p.PublishedAt, &p.RulesYAML); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------- API 令牌 ----------

// CreateToken 生成读令牌：明文一次性返回，库中只存 sha256
func (s *Store) CreateToken(name, actor string) (string, error) {
	plain, err := randomToken(24)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(plain))
	if _, err := s.db.Exec(`INSERT INTO api_tokens(name,token_hash,created_at) VALUES(?,?,?)`,
		name, hex.EncodeToString(h[:]), now()); err != nil {
		return "", err
	}
	_ = s.Audit(actor, "create-token", "token/"+name, "")
	return plain, nil
}

// CheckToken 校验读令牌（命中更新 last_used）
func (s *Store) CheckToken(plain string) bool {
	h := sha256.Sum256([]byte(plain))
	var id int64
	err := s.db.QueryRow(`SELECT id FROM api_tokens WHERE token_hash=?`, hex.EncodeToString(h[:])).Scan(&id)
	if err != nil {
		return false
	}
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used_at=? WHERE id=?`, now(), id)
	return true
}

// ListTokens / DeleteToken 令牌管理
func (s *Store) ListTokens() ([]Token, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at,last_used_at FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t := Token{}
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteToken(id int64) error {
	_, err := s.db.Exec(`DELETE FROM api_tokens WHERE id=?`, id)
	return err
}

// ---------- 审计 ----------

// Audit 追加审计（写操作统一收口）
func (s *Store) Audit(actor, action, entity, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit(at,actor,action,entity,detail) VALUES(?,?,?,?,?)`,
		now(), actor, action, entity, detail)
	return err
}

// ListAudit 审计列表（新→旧）
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id,at,actor,action,entity,detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		a := AuditEntry{}
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Entity, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- 助手 ----------

func now() string { return time.Now().Format(time.RFC3339) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func joinCSV(ss []string) string { return strings.Join(ss, ",") }

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func short(s string) string {
	r := []rune(s)
	if len(r) > 24 {
		return string(r[:24]) + "…"
	}
	return s
}

const tokenAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = tokenAlphabet[int(b)%len(tokenAlphabet)]
	}
	return string(out), nil
}
