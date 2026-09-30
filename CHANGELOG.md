# Changelog

## v0.2.0（2026-09-30）

### 新增

- **规则中心**：`leakgoose center serve` 单命令起 Web 服务，同一份二进制双角色（扫描 CLI + 规则服务器）
  - SQLite 单文件存储（纯 Go 驱动，零 CGO）+ 前端内嵌（`//go:embed`），无外部依赖
  - 规则草稿 CRUD 与实时测试沙箱（与扫描引擎同源编译，所测即所得）
  - 用例管理与发布门禁：发布前全量用例回归，期望不符拒绝发布（HTTP 422 逐条列出失败项）
  - 版本化不可变规则包：`YYYY.MM.DD-N` 版本号 + sha256 校验，YAML 快照随版本留存
  - 审计日志（规则变更 / 发布 / 令牌操作）、admin / editor / viewer 三角色、CI 读令牌（Bearer）
- **`leakgoose rules sync`**：从规则中心拉取规则包（`latest` 跟随最新发布或 URL 钉版本；输出前核对 sha256）
- 规则中心 Web UI：登录页 + 侧边栏后台（规则维护 / 发布与版本 / 审计日志 / 接入与令牌），深浅色主题

### 修复

- `password-assignment` 内置规则加负向前瞻：值内含 secret/password/token/key 关键词的多为配置键名或描述文案而非真口令，误报显著下降（已在 watchgoose 仓库实测）
- `rules sync` 位置参数在前导致 flag 解析失败的问题（参数重排后二次解析）

## v0.1.0（2026-09-29）

- 首个发布版本
- `leakgoose scan`：history（git 全历史）/ dir（目录快照）/ stdin 三模式，命中脱敏展示
- 规则体系：内置规则包 + 项目级 YAML 叠加（同 id 整体替换），regexp2 语法（支持前后瞻）
- PII 验真函数：身份证 GB11643 校验位、银行卡 Luhn、手机号在网号段——算法验真压误报
- 基线机制：存量发现按指纹（规则 + 文件 + 内容哈希）登记，增量新发现才阻断
- 15 条内置规则（凭据向 + 中国个保法 PII 向），6 平台二进制 + checksums 发布
