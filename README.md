# LeakGoose 看门鹅·泄

敏感信息扫描器：**凭据向 + 中国个保法 PII 向**规则库，扫描在本地执行（代码不出仓），规则 YAML 配置化。

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## 为什么不用 gitleaks？

gitleaks 覆盖通用凭据模式扫描；LeakGoose 在此之上补三块：

1. **中国合规规则库**：身份证号（GB11643 校验位验真）、手机号（在网号段验真）、银行卡号（Luhn 验真）——PII 规则一律配算法验真，把误报压到可用水平
2. **规则配置化叠加**：内置规则包 + 项目级 YAML 叠加（同 id 整体替换内置规则，用于收窄路径/调整严重级）
3. **基线机制**：存量已知发现按指纹（规则+文件+内容哈希）登记，增量新发现才阻断——行号漂移不影响基线匹配

## 安装

从 [Releases](https://github.com/lucassylux/leakgoose/releases) 下载对应平台二进制（linux/darwin/windows × amd64/arm64，Release 内嵌完整规则中心 UI），或源码构建：

```bash
go build -o leakgoose .                 # 纯扫描器（规则中心为占位页）
# 带完整规则中心 UI：先构建前端再编译（//go:embed 内嵌 web/dist）
cd web && npm ci && npm run build && cd .. && go build -o leakgoose .
```

依赖：history 模式需要系统 `git`；dir/stdin 模式零依赖。

## 快速开始

```bash
leakgoose scan                    # 当前仓库全历史扫描（默认 table 输出、命中脱敏）
leakgoose scan --mode dir ./src   # 目录快照
cat app.log | leakgoose scan --mode stdin
leakgoose rules                   # 查看已加载规则
```

退出码：`0` 干净 / `1` 有达到阈值的发现 / `2` 配置或执行错误。

## 规则配置

项目根放 `.leakgoose/rules.yaml` 叠加内置规则（`-r/--rules` 可指定其它路径，可多次）：

```yaml
rules:
  # 新增项目自有规则
  - id: my-company-token
    name: 内部平台令牌
    severity: critical
    pattern: 'COMPANY-[A-Za-z0-9]{32}'
    keywords: ['company']            # 可选：全文关键字预筛（性能优化）
  # 同 id 整体替换内置规则：收窄路径（演示种子数据的手机号按政策豁免）
  - id: cn-mobile
    name: 中国大陆手机号（号段验真）
    severity: high
    pattern: '(?<!\d)1[3-9]\d{9}(?!\d)'
    validate: builtin:cn-mobile-segment
    exclude-paths: ['sql/**', '**/it-init*.sql']
```

- `pattern`：[regexp2](https://github.com/dlclark/regexp2) 语法（支持前后瞻断言 `(?<!...)`)
- `validate`：验真函数 `builtin:id-card-checksum` / `builtin:luhn` / `builtin:cn-mobile-segment`（PII 规则强烈建议）
- 路径通配支持 `**` 与 `*`（`include-paths` / `exclude-paths`）

**行内豁免**：命中行追加注释 `leakgoose:allow`（建议附原因），该行全部规则豁免。

## 基线（存量问题登记）

```bash
leakgoose scan --save-baseline .leakgoose/baseline.json   # 把本轮发现写入基线
leakgoose scan -b .leakgoose/baseline.json                # 之后：命中基线不阻断，新发现阻断
```

基线文件随仓库提交，评审可见、可回滚；指纹 = 规则 + 文件 + 内容哈希（行号漂移不影响）。

## CI 集成

```yaml
- name: 敏感信息扫描（leakgoose，全历史 + 项目规则 + 基线）
  run: |
    curl -fsSL -o leakgoose.tar.gz \
      https://github.com/lucassylux/leakgoose/releases/download/v0.2.0/leakgoose_0.2.0_linux_amd64.tar.gz
    echo "<checksums.txt 中的 sha256>  leakgoose.tar.gz" | sha256sum -c
    tar xzf leakgoose.tar.gz leakgoose && install -m755 leakgoose /usr/local/bin/
    leakgoose scan --mode history --fail-severity high
```

`--fail-severity critical|high|medium|low|all` 控制阻断阈值（默认 all：任何发现都阻断）；低于阈值的发现只展示。

规则走中心下发时，CI 先拉包再扫（见下节）：

```yaml
- name: 拉取中心规则包（钉版本 + sha256 校验）
  run: |
    curl -fsSL -H "Authorization: Bearer $RULES_TOKEN" -o .leakgoose/center-pack.yaml \
      "${LEAKGOOSE_CENTER}/api/packs/<版本>.yaml"
- name: 敏感信息扫描（中心包 + 仓库叠加 + 基线）
  run: leakgoose scan --mode history --fail-severity high \
    -r .leakgoose/center-pack.yaml -r .leakgoose/rules.yaml -b .leakgoose/baseline.json
```

## 规则中心（v0.2+，可选）

同一份二进制内置规则中心 Web 服务：页面集中维护规则、版本化发布，CI 拉取使用——规则变更即时生效，不必升级二进制：

```bash
leakgoose center serve -listen :8280 -db center.db
# 首次启动自动创建 admin，随机初始密码打印在日志（仅此一次，登录后可改）
```

- **零外部依赖**：SQLite 单文件存储 + 前端已内嵌（源码构建带 UI 见「安装」）
- **规则草稿 + 实时沙箱**：编辑即测（与扫描引擎同源，所测即所得）
- **用例回归门禁**：每条规则可配「应命中 / 不应命中」用例，发布前全量回归，期望不符直接拒绝发布并逐条列出
- **版本化规则包**：发布生成不可变版本（`YYYY.MM.DD-N`）+ sha256，YAML 快照随版本留存，可回溯可回滚
- **审计日志**：规则变更、发布、令牌操作全记录
- **角色与令牌**：admin / editor / viewer 三角色；CI 用独立读令牌（Bearer，明文仅创建时显示一次）

CI 侧拉取：

```bash
leakgoose rules sync https://center.internal:8280/api/packs/latest --token "$RULES_TOKEN" \
  -o .leakgoose/center-pack.yaml          # latest：跟随最新发布
leakgoose rules sync https://center.internal:8280/api/packs/2026.09.30-1.yaml --token "$RULES_TOKEN"
# 钉版本：URL 带具体版本号，规则变更不漂移；两者响应均含 sha256 可核对
```

## SSO 登录（OIDC，v0.3+，可选）

规则中心可作为 OIDC 客户端接入统一身份认证中心（如 [WatchGoose](https://github.com/lucassylux/watchgoose)），授权码 + PKCE 流程：

配置有两条路：**「系统设置」页维护**（admin 登录后所见，改完即时生效，推荐），或环境变量首启注入（写入 settings 表，仅首次）：

```bash
# 环境变量首启注入（适合 systemd/容器；之后可在设置页改）
OIDC_ISSUER=http://localhost:8080 \        # WatchGoose 的 issuer
OIDC_CLIENT_ID=leakgoose-center \           # 管理台「应用接入」注册（PKCE 公开客户端可无 secret）
OIDC_ALLOWED_USERS=admin,terence \          # 白名单：空 = SSO 整套休眠，仅本地账号登录
leakgoose center serve -listen :8280 -db center.db
```

- 登录页自动出现「SSO 登录」按钮（未配置不显示，本地密码登录不受影响）
- **账号绑定按 OIDC `sub`**（非用户名）：IdP 侧同名账号无法接管本地账号，撞名直接拒绝
- SSO 用户本地密码为随机值，不可本地登录；角色以名单为准，每次登录同步
- 反代部署回调地址不对时设 `OIDC_REDIRECT_BASE=https://rules.example.com`
- WatchGoose 侧注册要点：授权模式 `authorization_code`，范围 `openid profile email`，强制 PKCE，回调 `http://<中心地址>/oidc/callback`

## 内置规则一览

凭据向：阿里云 AK / 腾讯云 SecretId / AWS AKID / GitHub / GitLab / Slack / Google / npm 令牌 / PEM 私钥块 / URL 内嵌口令 / 口令赋值 / JWT。
PII 向：身份证号（校验位）/ 手机号（号段）/ 银行卡号（Luhn）。详见 [rules/builtin.yaml](rules/builtin.yaml)。

## 路线图

- v0.2（已完成）：规则中心（`center serve` + 内嵌 Web UI + 版本化规则包 + `rules sync`）
- v0.3（已完成）：SSO 登录（OIDC 授权码 + PKCE，对接 WatchGoose 等标准 Provider）
- 下一步：SARIF 输出（GitHub Code Scanning）、增量 diff 模式（PR 扫描）、GitHub Action 封装、可选结果上报审计
- v1.0：规则生态（社区 PR 规则）

## License

Apache-2.0 © The LeakGoose Authors
