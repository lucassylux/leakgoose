// LeakGoose：敏感信息扫描器——凭据 + 中国个保法 PII 规则库。
// 形态：扫描在本地（代码不出仓），规则 YAML 配置化（内置包 + 项目叠加），git 全历史/目录/管道输入。
// 退出码：0 干净 / 1 有发现（按 --fail-severity 阈值）/ 2 配置或执行错误。
package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/lucassylux/leakgoose/internal/baseline"
	"github.com/lucassylux/leakgoose/internal/center"
	"github.com/lucassylux/leakgoose/internal/report"
	"github.com/lucassylux/leakgoose/internal/rules"
	"github.com/lucassylux/leakgoose/internal/scan"
)

//go:embed rules/builtin.yaml
var builtinRules embed.FS

var version = "dev" // 构建期 -ldflags "-X main.version=..." 注入

const usageText = `leakgoose — 敏感信息扫描器（凭据 + 中国个保法 PII）

用法:
  leakgoose scan [选项] [路径]        扫描（默认路径 .，模式默认 history）
  leakgoose rules [选项]              列出已加载规则（含叠加效果）
  leakgoose rules sync <URL> [选项]   从规则中心拉取规则包（校验和核验后落为规则文件）
  leakgoose center serve [选项]       启动规则中心服务端（Web 维护 + 规则包分发 API）
  leakgoose version                   版本

scan 选项:
  --mode history|dir|stdin   输入源：git 全历史 / 目录快照 / 标准输入（默认 history）
  -r, --rules FILE           项目规则叠加文件，可多次指定（同 id 整体替换内置规则）
  --no-builtin               只用叠加规则，不加载内置包
  -b, --baseline FILE        基线文件（命中基线的发现不阻断）
      --save-baseline FILE   把本轮全部发现写入基线（存量问题登记）
      --fail-severity LEVEL  阻断阈值：critical|high|medium|low|all（默认 all=任何发现都阻断）
  -f, --format table|json    输出格式（默认 table）
      --redact=false         关闭命中内容脱敏（默认脱敏：前3后2）
      --max-file-mb N        单文件扫描上限 MB（默认 5，目录模式）

退出码: 0 干净 / 1 有达到阈值的发现 / 2 配置或执行错误

行内豁免: 在命中行追加注释 leakgoose:allow（建议附原因），该行所有规则豁免
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "rules":
		if len(os.Args) > 2 && os.Args[2] == "sync" {
			os.Exit(runSync(os.Args[3:]))
		}
		os.Exit(runRules(os.Args[2:]))
	case "center":
		if len(os.Args) > 2 && os.Args[2] == "serve" {
			os.Exit(runCenterServe(os.Args[3:]))
		}
		fmt.Fprint(os.Stderr, "用法: leakgoose center serve [--db FILE] [--listen ADDR] [--admin-password PW]\n")
		os.Exit(2)
	case "version":
		fmt.Println("leakgoose", version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
}

type scanOptions struct {
	mode         string
	ruleFiles    []string
	noBuiltin    bool
	baselinePath string
	saveBaseline string
	failSeverity string
	format       string
	redact       bool
	maxFileMB    int
}

func runScan(args []string) int {
	var opts scanOptions
	var ruleFiles multiFlag
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.StringVar(&opts.mode, "mode", "history", "输入源: history|dir|stdin")
	fs.Var(&ruleFiles, "rules", "项目规则叠加文件（可多次）")
	fs.Var(&ruleFiles, "r", "项目规则叠加文件（可多次）")
	fs.BoolVar(&opts.noBuiltin, "no-builtin", false, "不加载内置规则")
	fs.StringVar(&opts.baselinePath, "baseline", "", "基线文件")
	fs.StringVar(&opts.baselinePath, "b", "", "基线文件（简写）")
	fs.StringVar(&opts.saveBaseline, "save-baseline", "", "把本轮发现写入基线")
	fs.StringVar(&opts.failSeverity, "fail-severity", "all", "阻断阈值 critical|high|medium|low|all")
	fs.StringVar(&opts.format, "format", "table", "输出 table|json")
	fs.StringVar(&opts.format, "f", "table", "输出 table|json（简写）")
	fs.BoolVar(&opts.redact, "redact", true, "命中内容脱敏展示（--redact=false 关闭）")
	fs.IntVar(&opts.maxFileMB, "max-file-mb", 5, "单文件扫描上限 MB")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Go flag 在首个位置参数处停止解析：路径之后若还跟着 flag 样式参数会被静默吞掉，
	// 这里显式报错提示正确顺序（flag 全部放在路径之前）
	if fs.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "leakgoose: 未识别的参数 %v（flag 需放在扫描路径之前：leakgoose scan [flags] [路径]）\n", fs.Args()[1:])
		return 2
	}
	opts.ruleFiles = ruleFiles

	builtin, err := loadBuiltin(opts.noBuiltin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}
	rs, err := rules.Load(builtin, opts.ruleFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}

	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	var findings []scan.Finding
	switch opts.mode {
	case "history":
		findings, err = scan.ScanHistory(rs, path)
	case "dir":
		findings, err = scan.ScanDir(rs, path, int64(opts.maxFileMB)*1024*1024)
	case "stdin":
		findings, err = scan.ScanStdin(rs, os.Stdin)
	default:
		fmt.Fprintf(os.Stderr, "leakgoose: --mode 非法: %s（可选 history|dir|stdin）\n", opts.mode)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}

	if opts.saveBaseline != "" {
		if err := baseline.Save(opts.saveBaseline, findings); err != nil {
			fmt.Fprintf(os.Stderr, "leakgoose: 写基线失败: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "已把 %d 处发现写入基线 %s\n", len(findings), opts.saveBaseline)
	}

	suppressedCount := 0
	if opts.baselinePath != "" {
		var base map[string]bool
		base, err = baseline.Load(opts.baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
			return 2
		}
		findings, suppressedCount = baseline.Filter(findings, base)
	}

	switch opts.format {
	case "table":
		report.Table(os.Stdout, findings, opts.redact, opts.baselinePath != "", suppressedCount)
	case "json":
		if err := report.JSON(os.Stdout, findings, opts.redact); err != nil {
			fmt.Fprintf(os.Stderr, "leakgoose: JSON 输出失败: %v\n", err)
			return 2
		}
	default:
		fmt.Fprintf(os.Stderr, "leakgoose: --format 非法: %s（可选 table|json）\n", opts.format)
		return 2
	}

	// 阻断阈值：达到阈值的发现才影响退出码；低于阈值只展示
	threshold, ok := severityThreshold(opts.failSeverity)
	if !ok {
		fmt.Fprintf(os.Stderr, "leakgoose: --fail-severity 非法: %s（可选 critical|high|medium|low|all）\n", opts.failSeverity)
		return 2
	}
	for _, f := range findings {
		if rules.SeverityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

func severityThreshold(s string) (int, bool) {
	switch s {
	case "critical":
		return 4, true
	case "high":
		return 3, true
	case "medium":
		return 2, true
	case "low":
		return 1, true
	case "all", "":
		return 1, true
	}
	return 0, false
}

func runRules(args []string) int {
	var opts scanOptions
	var ruleFiles multiFlag
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.Var(&ruleFiles, "rules", "项目规则叠加文件（可多次）")
	fs.Var(&ruleFiles, "r", "项目规则叠加文件（可多次）")
	fs.BoolVar(&opts.noBuiltin, "no-builtin", false, "不加载内置规则")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	builtin, err := loadBuiltin(opts.noBuiltin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}
	rs, err := rules.Load(builtin, ruleFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}
	fmt.Printf("%-26s %-9s %s\n", "ID", "SEVERITY", "NAME")
	for _, r := range rs.Rules {
		fmt.Printf("%-26s %-9s %s\n", r.ID, r.Severity, r.Name)
	}
	fmt.Printf("共 %d 条规则\n", len(rs.Rules))
	return 0
}

func loadBuiltin(noBuiltin bool) ([]byte, error) {
	if noBuiltin {
		return nil, nil
	}
	return builtinRules.ReadFile("rules/builtin.yaml")
}

// reorderFlags Go flag 的经典坑兜底：位置参数出现在 flag 之前时 Parse 会提前停止、
// 把后续 flag 全吞成位置参数。Parse 失败（多余位置参数）时把首个非 - 开头参数移到末尾重试，
// 兼容 "sync URL --token T" / "scan . --mode dir" 这类自然写法。
func reorderArgs(args []string) []string {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			out := append([]string{}, args[:i]...)
			out = append(out, args[i+1:]...)
			return append(out, a)
		}
	}
	return args
}

// multiFlag 支持重复的字符串参数（-r a.yaml -r b.yaml）
type multiFlag []string

func (m *multiFlag) String() string { return strconv.Itoa(len(*m)) + " 个文件" }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

//go:embed all:web/dist
var centerUI embed.FS

// runCenterServe 规则中心服务端：默认 :8280 + center.db；首次启动种子 admin
// （口令取 --admin-password 或环境变量 LEAKGOOSE_CENTER_ADMIN_PASSWORD，缺省自动生成一次性打印）
func runCenterServe(args []string) int {
	fs := flag.NewFlagSet("center serve", flag.ContinueOnError)
	dbPath := fs.String("db", "center.db", "SQLite 库文件")
	listen := fs.String("listen", ":8280", "监听地址")
	uiDir := fs.String("ui-dir", "", "前端静态目录（默认用内嵌 dist；本地开发指到 web/dist）")
	adminPw := fs.String("admin-password", os.Getenv("LEAKGOOSE_CENTER_ADMIN_PASSWORD"), "管理员初始口令（仅首次建库生效）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	store, generated, err := center.Open(*dbPath, *adminPw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 打开库失败: %v\n", err)
		return 2
	}
	defer store.Close()
	if generated != "" {
		fmt.Printf("=== 首次启动：管理员账号 admin，初始口令（仅此一次显示，请立即登录）: %s ===\n", generated)
	}
	// 首启种子：规则表为空时导入内置规则包为草稿（含演示用例）
	if builtinYAML, err := loadBuiltin(false); err == nil {
		if err := store.SeedRules(builtinYAML); err != nil {
			fmt.Fprintf(os.Stderr, "leakgoose: 种子规则导入失败: %v\n", err)
		}
	}
	var uifs = center.SubFS(centerUI, "web/dist")
	if *uiDir != "" {
		uifs = center.DirFS(*uiDir)
	}
	srv := center.NewServer(store, uifs)
	fmt.Printf("leakgoose center %s 监听 %s（库: %s）\n", version, *listen, *dbPath)
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 服务退出: %v\n", err)
		return 2
	}
	return 0
}

// runSync 从规则中心拉取规则包：sha256 核验后写成规则文件（scan -r 直接可用）
func runSync(args []string) int {
	fs := flag.NewFlagSet("rules sync", flag.ContinueOnError)
	token := fs.String("token", os.Getenv("LEAKGOOSE_CENTER_TOKEN"), "读令牌（或环境变量 LEAKGOOSE_CENTER_TOKEN）")
	out := fs.String("o", ".leakgoose/center-pack.yaml", "落盘路径")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		// 位置参数在前导致 flag 未被解析：重排（首个非 - 参数移末尾）后再试一次
		_ = fs.Parse(reorderArgs(args))
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "用法: leakgoose rules sync <包地址，如 https://center.internal/api/packs/latest> [--token T] [-o FILE]")
		return 2
	}
	url := fs.Arg(0)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: %v\n", err)
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 拉取失败: %v\n", err)
		return 2
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 读取响应失败: %v\n", err)
		return 2
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "leakgoose: 拉取失败 http=%d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 2
	}
	pack, err := center.ParsePackJSON(body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 响应不是合法规则包: %v\n", err)
		return 2
	}
	if !pack.Verify() {
		fmt.Fprintf(os.Stderr, "leakgoose: 校验和不匹配（包声明 %s）——传输被篡改或两端版本不一致，拒绝落盘\n", pack.Sha256)
		return 2
	}
	if err := center.WritePackFile(pack, *out); err != nil {
		fmt.Fprintf(os.Stderr, "leakgoose: 写文件失败: %v\n", err)
		return 2
	}
	fmt.Printf("已同步规则包 %s（%d 条规则，sha256 %s）→ %s\n", pack.Version, len(pack.Rules), pack.Sha256[:12], *out)
	return 0
}
