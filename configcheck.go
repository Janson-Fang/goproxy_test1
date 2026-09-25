package main

// `-config-check`：只读地判断「这份配置库能不能被本二进制加载」。
//
// 为什么需要它：
// 升级路径上原来只跑一次 `<新二进制> -version` —— 那只能证明「这个文件能跑起来」，
// 证明不了「它能读现在这份配置」。而破坏性配置变更（v0.6 强制登录、v0.7 mode+cidrs、
// v0.8 内联 acl 改命名列表、v0.9 配置源换 SQLite）的行为都是**拒绝启动并打印迁移映射**，
// 于是一次升级的失效模式很容易变成「文件换上去、服务起不来、只能人工回退」——
// 而真正该发生的只是「上传被拒 + 告诉你该怎么改」。
//
// 判据只有一句话：**把启动时读配置那一段原样跑一遍，但不写任何东西**。
// 所以它给出的失败原因与真启动时给出的**是同一份**（含迁移映射）。这是它值得信赖的
// 唯一理由 —— 如果它自己另写一套判断，那只是多了一个会漂移的副本。
//
// 三处调用：
//   - 上传时：立刻告诉操作者「这个新版本读不了现在这份配置」，此时文件还没生效；
//   - 安装前：真正换文件之前再确认一次（上传之后配置可能已经被改过）；
//   - `-upgrade-apply`：root 那条路自己也要判，不能只信控制台判过。
//
// 回退（`-upgrade-rollback`）**刻意不检查**：回退是应急出口，而「旧二进制读不了
// 新配置」恰恰是它最常见的场景，拦住它等于把出口焊死。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// configCheckTimeout 是「拿一个二进制试读一次配置库」的超时。
	// 比 -version 的 10 秒宽：这一步要开一次 SQLite 连接，而配置库可能正被
	// 运行中的服务持有（连接级 busy_timeout 是 5 秒）。
	configCheckTimeout = 20 * time.Second

	// configCheckOutputLimit 是失败时回给用户/界面/日志的输出上限。
	//
	// 比 truncateForMsg 的 400 字节宽得多，因为**迁移映射必须完整**：它是一份
	// 八行左右的改法说明，截断之后就从「照它改就行」变成「猜」——
	// 那正是这个功能要消灭的东西。
	configCheckOutputLimit = 4000
)

// errConfigCheckUnsupported 表示「这个二进制不认识 -config-check」。
//
// 早于 v0.15.0 的版本都是这样，而**降级装一个旧版本是完全正常的操作**。
// 调用方必须把它当作「跳过预检」而不是「预检失败」：否则一次正常的降级会被
// 自己的检查拦住，而拦住它的理由是「你没带这个开关」，与配置毫无关系。
var errConfigCheckUnsupported = errors.New("该二进制不认识 -config-check（早于 v0.15.0），跳过配置预检")

// errConfigCheckFailed 是给退出码与日志用的短错误。
//
// 失败原因本身通常是多行的迁移映射，由调用方直接打到 stderr 给人读；
// 塞进 slog 会被 JSON 转义成一整行 \n，反而没法看。
var errConfigCheckFailed = errors.New("配置预检未通过（原因见上一段）")

// checkConfigUsable 只读地走一遍启动时的配置路径。
//
// 返回的 note 是「通过」时的一句话说明（带上读到了什么，让人知道这次检查不是空转）。
func checkConfigUsable(configDB string) (string, error) {
	if strings.TrimSpace(configDB) == "" {
		return "", errors.New("没有指定配置库路径（-c）")
	}

	// (1) -c 指在旧的 config.json 上：升级最常见的误操作，判词与启动时同一句。
	if fi, err := os.Stat(configDB); err == nil && !fi.IsDir() && !isSQLiteFile(configDB) {
		return "", errConfigDBLooksLikeJSON(configDB)
	}

	// (2) 库还不存在时**不要建它**（见 openConfigStoreReadOnly 的注释）。
	// 这时启动会做的是「建库 + 从同目录的 config.json 导入一次」，所以这里改为
	// 只校验那份种子 —— 而种子的旧写法拦截，正是历史上真正拦住过升级的那件事。
	if _, err := os.Stat(configDB); errors.Is(err, os.ErrNotExist) {
		note, err := checkSeedJSON(configDB, "配置库还不存在（启动时会创建）")
		if err != nil {
			return "", err
		}
		return note, nil
	}

	// (3) 只读打开，并自己判 schema 版本（只读打开不跑 migrate，理由见那里）。
	st, err := openConfigStoreReadOnly(configDB)
	if err != nil {
		return "", err
	}
	defer st.Close()

	cur, err := st.schemaVersionRO()
	if err != nil {
		return "", err
	}
	if cur == "" {
		return "", fmt.Errorf(
			"%s 不像是 goproxy 的配置库（缺 meta 表或没有 schema 版本行）：确认一下 -c 指向的文件",
			configDB)
	}
	if cur != strconv.Itoa(configSchemaVersion) {
		// 与 migrate 报同一句话 —— 预检的全部价值就在于「它说的就是启动时会说的」。
		return "", errSchemaMismatch(cur)
	}

	// (4) 空库 → 校验将要被导入的种子；非空 → 原样走一遍读配置那一段。
	empty, err := st.isEmpty()
	if err != nil {
		return "", err
	}
	if empty {
		return checkSeedJSON(configDB, "库还是空的（启动时会从同目录的 config.json 导入一次）")
	}

	// 与 readConfigFile 完全同一段：读出 → 补顶层与路由默认值 → validate。
	// 少了任何一步都会与真启动判得不一样（比如 applyRouteDefaults 缺席时，
	// 少写 path_prefix 的路由会在这里假失败）。
	_, cfg, err := st.read()
	if err != nil {
		return "", err
	}
	cfg.applyTopDefaults()
	cfg.applyRouteDefaults()
	if err := cfg.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("配置可以加载：%d 条路由 / %d 份命名名单 / %d 个默认端口",
		len(cfg.Routes), len(cfg.IPLists), len(cfg.DefaultPorts)), nil
}

// checkSeedJSON 校验「将要被导入的那份 config.json」。
//
// 库为空时启动的真正动作是导入它，所以预检必须看它 —— 只看库（空的）会得出
// 「一切正常」，而实际启动会当场失败。这是这条检查里最容易被写漏的一格。
func checkSeedJSON(configDB, lead string) (string, error) {
	seed := filepath.Join(filepath.Dir(configDB), "config.json")
	raw, err := os.ReadFile(seed)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return lead + "，同目录也没有 config.json（首次启动会用一份空配置，之后到控制台里配）", nil
		}
		return "", fmt.Errorf("读 %s 失败: %w", seed, err)
	}
	if err := validateConfigJSON(raw, filepath.Dir(configDB)); err != nil {
		return "", fmt.Errorf("%s，而那份 %s 通不过校验：\n%w", lead, seed, err)
	}
	return lead + "，并用同目录的 config.json 初始化（那份已校验通过）", nil
}

// runConfigCheck 是 `-config-check` 的命令行实现。
func runConfigCheck(configDB string) error {
	note, err := checkConfigUsable(configDB)
	if err != nil {
		// 原样打到 stderr 给人读：这里通常是一份多行的迁移映射。
		fmt.Fprintln(os.Stderr, err)
		return errConfigCheckFailed
	}
	fmt.Println("配置预检通过：" + note)
	return nil
}

// checkBinaryConfigUsable 拿一个「还没生效的」二进制去试读当前配置库。
//
// bin 是暂存的新二进制：它自己带着 -config-check，所以这次判断用的是**新版本的
// 校验逻辑**——这正是要问的问题（旧版本当然读得懂旧配置，那没有意义）。
func checkBinaryConfigUsable(ctx context.Context, bin, configDB string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, configCheckTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, bin, "-c", configDB, "-config-check").CombinedOutput()
	text := strings.TrimSpace(string(out))

	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("配置预检超时（超过 %s）：新二进制没能在时限内读完配置库。%s",
				configCheckTimeout, truncateForConfigCheck(text))
		}
		// 这个二进制不认识我们的调用方式 —— 跳过，不是失败。
		//
		// 认它的特征是 flag 包的标准报错。**刻意不去比对flag 名**：老二进制报的是
		// 第一个不认识的开关（`-c` 在 `-config-check` 前面，所以它可能报 -c），
		// 而这里真正要判的是「它的 flag 解析器拒绝了我们的调用」。
		// 判成「跳过」而不是「失败」的理由是：预检不该有能力拦住一次升级，
		// 它只是一个额外的确认；解析不了就把话说清楚然后放行（上面已记日志）。
		if strings.Contains(text, "flag provided but not defined") {
			return "", errConfigCheckUnsupported
		}
		return "", fmt.Errorf("配置预检失败：%s", truncateForConfigCheck(text))
	}
	return text, nil
}

// truncateForConfigCheck 裁短输出，但**保留换行** —— 迁移映射是多行说明，
// 压成一行之后界面与日志里都会变得难读。上限也刻意比 truncateForMsg 宽得多。
func truncateForConfigCheck(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(没有输出)"
	}
	if len(s) > configCheckOutputLimit {
		return s[:configCheckOutputLimit] + "\n…（输出过长，已截断）"
	}
	return s
}

// configPreflight 是一次配置预检的结果。
//
// 三种结局分开表示，因为它们对调用方意味着完全不同的事：
//   - Skipped：新二进制不认识这个开关（降级到旧版本），**放行**；
//   - Problem 非空：配置读不了，默认拦住（除非调用方拿到 force）；
//   - 否则通过，Note 是那句「读到了什么」。
type configPreflight struct {
	Skipped bool
	Note    string
	Problem error
}

// preflightConfig 是「换文件之前的那一问」。
//
// 只做判断与记录，**不决定放不放行**：放行策略属于调用方 ——
// 控制台那条路要回 409 并把迁移映射给到界面，命令行那条路要打 stderr 并给退出码。
// 两处共用这一个函数，是为了让「界面判过」与「root 又判一次」用的是同一套判据。
func preflightConfig(ctx context.Context, bin, configDB string) configPreflight {
	note, err := checkBinaryConfigUsable(ctx, bin, configDB)
	switch {
	case err == nil:
		slog.Info("升级：配置预检通过", "bin", bin, "note", note)
		return configPreflight{Note: note}
	case errors.Is(err, errConfigCheckUnsupported):
		// 降级到旧版本时会走到这里。跳过的理由是「那个版本没有这个开关」，
		// 与配置无关，所以不能拦。
		slog.Warn("升级：跳过配置预检", "bin", bin, "reason", err.Error())
		return configPreflight{Skipped: true}
	default:
		slog.Warn("升级：配置预检未通过", "bin", bin, "err", err)
		return configPreflight{Problem: err}
	}
}
