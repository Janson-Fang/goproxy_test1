package main

// ============================================================================
// 升级模块（控制台「升级」页的后端）
//
// 两条更新源：
//
//      GitHub Releases：与 install.sh 完全同一套约定（资源命名、SHA256SUMS-<arch>.txt、
//                  镜像通道），所以界面上装出来的东西和跑一遍 install.sh 一致；
//上传文件         内网 / 离线环境：把二进制（或发布用的 tar.gz）直接传上来。
//
// 三条设计原则：
//
//  1. **动磁盘之前先验证**。校验和只证明「字节没坏」，证明不了「它能在这台机器上
//     跑起来」（下错架构的包哈希也是对的），所以换掉线上二进制之前真的执行一次
//     `新文件 -version`：这一步和 install.sh 第 7 节做的事完全相同。
//  2. **换了就要能换回来**。旧二进制一律先备份成 <exe>.old（与 install.sh 同名），
//     界面上有「回退上一版」，命令行里 install.sh 给出的回滚命令也能直接照抄。
//  3. **不依赖任何外部命令**。下载 / 校验 / 解包全用标准库，升级过程不需要
//     curl、tar、sha256sum 存在。
// ============================================================================

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// upgradeMaxStagedBytes 是暂存二进制的上限。发布包里的二进制目前约 12MB，
	// 给到 256MiB 是留足余量，同时挡掉「上传了一个系统镜像 / 数据库文件」这类事故。
	upgradeMaxStagedBytes = 256 << 20

	// upgradeRestartDelay 是「响应写完」到「替换进程」之间的等待。
	// syscall.Exec 会把当前进程镜像整个换掉，在那之前响应必须已经落到连接上，
	// 否则浏览器只会看到一个连接被重置：升级明明成功了却像是失败。
	upgradeRestartDelay = 1200 * time.Millisecond

	// upgradeVerifyTimeout 是执行 `新二进制 -version` 的超时。
	upgradeVerifyTimeout = 10 * time.Second
)

// ---------------------------------------------------------------------------
// 版本号解析与比较
// ---------------------------------------------------------------------------

// buildVersion 是从版本串里解析出来的可比较版本。
//
// 版本串来自 git describe（见 Makefile）：正好在 tag 上是 v0.9.1，tag 之后
// 还有提交是 v0.9.1-3-gabc1234，工作区脏是 v0.9.1-dirty，没有 tag 时是裸
// 提交号。不是所有这些都能比大小，所以解析失败时 OK=false，调用方必须
// 显式处理「比不了」这件事，而不是当它相等。
type buildVersion struct {
	Major   int
	Minor   int
	Patch   int
	Commits int
	Dirty   bool
	// Raw 是原始串，界面直接显示它（比拆开的三段数字有信息量）。
	Raw string
	OK  bool
}

// describeRe 匹配 git describe 的版本部分（v 前缀可选，允许 -N-gSHA 尾巴）。
var describeRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-fA-F]+)?$`)

func parseBuildVersion(raw string) buildVersion {
	v := buildVersion{Raw: strings.TrimSpace(raw)}
	s := strings.TrimSpace(raw)
	if s == "" || s == "dev" || s == "none" {
		return v
	}
	if strings.HasSuffix(s, "-dirty") {
		v.Dirty = true
		s = strings.TrimSuffix(s, "-dirty")
	}
	m := describeRe.FindStringSubmatch(s)
	if m == nil {
		return v
	}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	if m[4] != "" {
		v.Commits, _ = strconv.Atoi(m[4])
	}
	v.OK = true
	return v
}

// compareBuild 比较两个版本：-1 表示 a 更旧，0 表示同一版，1 表示 a 更新。
//
// 语义刻意不是「字符串比大小」，也不是「只比三段数字」：
//   - 只比三段数字：`v0.9.1-3-gabc1234`（tag 之后还有 3 个提交）会被判成等于
//     v0.9.1，界面就会显示「已是最新」，可它其实比 v0.9.1 新；
//   - 只比字符串：v0.10.0 会被判成比 v0.9.1 旧（'1' < '9'），这是最糟的一种错。
//
// 所以先按三段数字比（数字语义），三段相同再比 tag 之后的提交数。
func compareBuild(a, b buildVersion) int {
	if !a.OK || !b.OK {
		return 0
	}
	if c := compareInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := compareInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := compareInt(a.Patch, b.Patch); c != 0 {
		return c
	}
	return compareInt(a.Commits, b.Commits)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// 运行环境：怎么换、换完之后怎么起
// ---------------------------------------------------------------------------

// restartStrategy 说明「二进制换完之后新版本怎么跑起来」。
type restartStrategy string

const (
	// strategyReexec：Unix 上原地 exec 换进程镜像。PID 不变，不依赖任何服务
	// 管理器：手工起的 ./goproxy、systemd、supervisord 都能用。
	strategyReexec restartStrategy = "reexec"
	// strategySpawn：Windows 上没法 exec 自己（运行中的 exe 有独占锁），
	// 只能起一个新进程再退出自己。
	strategySpawn restartStrategy = "spawn"
	// strategyUnsupported：例如用 go run 起的进程，或目录不可写。
	strategyUnsupported restartStrategy = "unsupported"
)

type upgradeEnv struct {
	Exe      string
	Dir      string
	Strategy restartStrategy
	// Service 只是展示用（systemd | none）：重启方式不由它决定，
	// 但「这个实例是谁在管」会影响用户对「升级后会不会掉线」的判断。
	Service string
	// Writable 表示进程能写二进制所在目录，也就是能自己把文件换掉。
	Writable bool
	// StageDir 是「现在就能写」的暂存目录。Writable=false 时它落在状态目录里，
	// 由 root 用 -upgrade-apply 应用（托管升级）。空表示连暂存都做不到。
	StageDir string
	// Delegated 表示这次升级得由 root 代劳：控制台照旧负责下载、校验、
	// 跑一次 -version 验证，但最后那步「写 /usr/local/bin + 重启服务」需要权限。
	Delegated bool
	// Reason 非空表示整条升级路径都不通，内容是给人看的原因。
	Reason string
}

// supported 表示这台机器上能不能升级（含需要 root 代劳的托管方式）。
func (e upgradeEnv) supported() bool { return e.Reason == "" && e.Strategy != strategyUnsupported }

// canSwap 表示进程能自己把二进制换到位。false 而 supported() 为 true 时走托管。
func (e upgradeEnv) canSwap() bool { return e.supported() && e.Writable }

// detectUpgradeEnv 探测升级能力。
//
// 两种情况必须分开看，因为处置办法完全不同：
//
//   - 进程能写二进制所在目录：自己原地替换，一步到位（Writable）。
//   - 写不进去：install.sh 装出来的实例就是这一种（单元里 User=goproxy，
//     ReadWritePaths 只放行了 $STATE_DIR 与 $CONFIG_DIR，而 /usr/local/bin
//     是 root 的）。这时仍然可以下载、校验、验证，把结果暂存到配置库旁边的
//     upgrade/ 目录，再由 root 用 `goproxy -upgrade-apply` 应用（Delegated）。
//
// 只有「两边都写不进去」「go run 起的实例」「不支持的平台」才判为不支持。
func detectUpgradeEnv(exe, configDB string) upgradeEnv {
	env := upgradeEnv{Exe: exe, Service: detectServiceManager()}
	if exe == "" {
		env.Strategy = strategyUnsupported
		env.Reason = "拿不到当前进程的可执行文件路径（os.Executable 失败），无法升级。"
		return env
	}
	env.Dir = filepath.Dir(exe)

	switch runtime.GOOS {
	case "windows":
		env.Strategy = strategySpawn
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris":
		env.Strategy = strategyReexec
	default:
		env.Strategy = strategyUnsupported
		env.Reason = fmt.Sprintf("不支持的平台 %s/%s：请手工替换二进制。", runtime.GOOS, runtime.GOARCH)
		return env
	}

	if inBuildTempDir(env.Dir) {
		env.Strategy = strategyUnsupported
		env.Reason = fmt.Sprintf("当前进程运行在构建/临时目录（%s），看起来是 go run 起的："+
			"替换那里的文件不会生效。请先把二进制装到正式路径（make build 后放到 /usr/local/bin）再升级。", env.Dir)
		return env
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		env.Strategy = strategyUnsupported
		if err != nil {
			env.Reason = "当前可执行文件不可读：" + err.Error()
		} else {
			env.Reason = "当前可执行文件路径是个目录，无法替换。"
		}
		return env
	}

	if upgradeDirWritable(env.Dir) {
		env.Writable = true
		env.StageDir = env.Dir
		return env
	}

	// 二进制目录写不进去：看能不能把新版本暂存到状态目录，交给 root 应用。
	fallback := delegatedStageDir(configDB)
	if fallback == "" {
		env.Strategy = strategyUnsupported
		env.Reason = fmt.Sprintf("进程对 %s 没有写权限，也没有可用的状态目录来暂存新版本。", env.Dir)
		return env
	}
	if err := os.MkdirAll(fallback, 0o700); err != nil {
		env.Strategy = strategyUnsupported
		env.Reason = fmt.Sprintf("进程对 %s 没有写权限，也建不出暂存目录 %s：%v", env.Dir, fallback, err)
		return env
	}
	if !upgradeDirWritable(fallback) {
		env.Strategy = strategyUnsupported
		env.Reason = fmt.Sprintf("进程对 %s 与暂存目录 %s 都没有写权限，无法升级。", env.Dir, fallback)
		return env
	}
	env.Delegated = true
	env.StageDir = fallback
	return env
}

// delegatedStageDir 返回托管升级的暂存目录：配置库旁边的 upgrade/ 子目录。
//
// 不写死在 /var/lib，而是跟着 -c 走：install.sh 的单元里 ReadWritePaths 放行了
// $STATE_DIR 与 $CONFIG_DIR，而配置库所在目录必然可写（管理接口要写库，SQLite
// 还要在库旁边建 -wal / -shm），所以这个位置不需要任何额外授权。
func delegatedStageDir(configDB string) string {
	dir := strings.TrimSpace(configDB)
	if dir == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(abs), "upgrade")
}

// upgradeDirWritable 是 dirWritable 的间接层，给单测留一个注入点。
//
// 需要它是因为「二进制目录写不进去」这条分支在 Windows 上造不出来
// （目录的只读属性和 Unix 权限位不是一回事），而它恰好是最该覆盖的一条路。
var upgradeDirWritable = dirWritable

// inBuildTempDir 判断目录是不是「构建工具随手放的临时目录」。
//
// 只认两种：go run / go test 的 go-build* 目录，以及系统临时目录本身。
// 刻意不把「临时目录下面的一切」都算进去：那会误伤刻意装到 /tmp 下的实例，
// 也会让测试里用 t.TempDir() 造出来的目录统统变成「不支持自升级」，
// 而这条判断的代价是整条升级路径直接不可用。
func inBuildTempDir(dir string) bool {
	if tmp, err := filepath.Abs(os.TempDir()); err == nil {
		if abs, err := filepath.Abs(dir); err == nil && abs == tmp {
			return true
		}
	}
	return strings.Contains(filepath.ToSlash(dir), "/go-build")
}

// dirWritable 用「真的创建一个文件再删掉」来判断目录可写。
//
// 不用 os.Stat 的权限位：root 跑、只读挂载、ACL、容器里的 ReadWritePaths
// 这些情况权限位统统看不出来，而这个判断错了的代价是「升级到一半发现写不进去」。
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".goproxy-upgrade-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// detectServiceManager 粗略判断当前实例是不是 systemd 在管（只用展示）。
func detectServiceManager() string {
	for _, k := range []string{"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET"} {
		if os.Getenv(k) != "" {
			return "systemd"
		}
	}
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		return "systemd"
	}
	return "none"
}

// ---------------------------------------------------------------------------
// 二进制验证 / 备份 / 替换
// ---------------------------------------------------------------------------

// verifyBinary 执行目标二进制的 -version，用它自己的自述确认两件事：
// 「这是一个 goproxy」和「它能在这台机器上跑起来」。
//
// 光看文件头或校验和只能证明字节没坏，证明不了架构对不对：arm64 的包丢到
// amd64 上哈希照样是匹配的，只有真跑一次才会报 exec format error。
func verifyBinary(path string) (buildVersion, string, error) {
	return probeBinary(path, upgradeVerifyTimeout)
}

func probeBinary(path string, timeout time.Duration) (buildVersion, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return buildVersion{}, "", fmt.Errorf("执行 %s -version 失败（%v）：%s", filepath.Base(path), err, truncateForMsg(text))
	}
	// 输出形如：goproxy v0.9.1 (commit abc1234)
	m := versionOutRe.FindStringSubmatch(text)
	if m == nil {
		return buildVersion{}, "", fmt.Errorf("%s -version 的输出不是 goproxy 的格式：%s", filepath.Base(path), truncateForMsg(text))
	}
	return parseBuildVersion(m[1]), m[2], nil
}

var versionOutRe = regexp.MustCompile(`(?m)^goproxy\s+(\S+)\s+\(commit\s+(\S+)\)`)

// truncateForMsg 把子进程输出裁短：它是原样进 HTTP 响应和日志的，
// 一个疯狂的二进制完全可能吐几兆出来。
func truncateForMsg(s string) string {
	const max = 400
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + ""
	}
	if s == "" {
		return "(无输出)"
	}
	return s
}

// swapBinary 用 newPath 替换 exe，并把替换前的 exe 备份到 backupPath。
//
// 顺序：备份，然后把正在运行的旧文件改名挪开，最后把新文件 rename 到位。
//
//  1. 先备份：升级失败时要能有东西退回。
//  2. 「先挪开再放上去」而不是直接覆盖：Windows 上正在运行的 exe 带独占锁，
//     直接 rename 覆盖会 Access is denied，但**改名**是允许的；挪开之后目标
//     路径就空了，新文件可以落上去，而老进程继续持有旧 inode 把剩下的请求跑完。
//     Linux 上两种顺序都成立，所以统一走这一条，少一个平台分支就少一处能踩的坑。
//  3. 第二步失败要把旧文件放回原位：宁可升级失败，也不能留下「路径上什么都没有」
//     的状态：那个窗口里 systemd 重启服务只会得到 203/EXEC。
//
// newPath 必须和 exe 在同一个目录（同一个文件系统），否则 rename 会退化成
// 「复制 + 删除」，中间就有窗口了。
// parked 是「把旧文件挪到哪」的临时名字，调用方每次换一个新的（见 parkedPath）。
func swapBinary(exe, newPath, backupPath, parked string) error {
	st, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("读当前二进制失败：%w", err)
	}
	mode := st.Mode().Perm()
	if mode&0o111 == 0 {
		mode |= 0o755
	}
	if err := copyFile(exe, backupPath, mode); err != nil {
		return fmt.Errorf("备份当前二进制到 %s 失败：%w", backupPath, err)
	}

	if err := os.Rename(exe, parked); err != nil {
		return fmt.Errorf("移开当前二进制失败：%w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		if rerr := os.Rename(parked, exe); rerr != nil {
			return fmt.Errorf("写入新二进制失败（%v），且回滚也失败（%v）：%s 现在不存在，请手工把 %s 改回来",
				err, rerr, exe, parked)
		}
		return fmt.Errorf("写入新二进制失败，已回滚到原二进制：%w", err)
	}
	// 挪开的旧文件：Windows 上运行中的 exe 是删不掉的（有锁），删不掉就留着，
	// 下次启动由 cleanupUpgradeLeftovers 清掉，不影响任何功能。
	if err := os.Remove(parked); err != nil {
		slog.Debug("升级：旧二进制的临时文件未能删除，下次启动会清理", "path", parked, "err", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	// 先 fsync 再 rename 是「原子替换」的必要条件：否则断电后可能留下一个
	// 长度对但内容不全的新二进制。
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cleanupUpgradeLeftovers 清掉上次升级留下的中间文件。
//
// 这两个文件只可能出现在「升级进行中」这个很短的窗口里，所以启动时看到它们
// 就说明上次没能走完（进程被杀、断电、或者换完文件之后 exec 失败）。
// 留着它们的唯一后果是下次升级多一份歧义，所以直接清掉。
func cleanupUpgradeLeftovers(exe string) {
	if exe == "" {
		return
	}
	removeUpgradeFile(exe + ".staged")
	removeUpgradeFile(exe + ".rollback-staged")
	// 「挪开的旧映像」用的是带时间戳的名字（见 parkedPath）：Windows 上正在
	// 运行的那个映像删不掉，只能留在原地等下次启动清理，所以这里按前缀扫一遍，
	// 而不是只删一个固定的名字。
	dir, base := filepath.Split(exe)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := base + ".swap-old"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			removeUpgradeFile(filepath.Join(dir, e.Name()))
		}
	}
}

// removeUpgradeFile 删一个升级中间文件，删不掉只记日志。
//
// 这不是「懒得处理错误」：Windows 上正在运行的那个映像就是删不掉的，
// 那属于预期内的情况，下次启动会清掉，不该因此让升级失败。
func removeUpgradeFile(path string) {
	if err := os.Remove(path); err == nil {
		slog.Info("升级：清理上次遗留的临时文件", "path", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("升级：清理临时文件失败", "path", path, "err", err)
	}
}

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	// 解析软链接：要替换的是真正的文件，而不是那个指向它的软链接。
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}

// ---------------------------------------------------------------------------
// 管理器
// ---------------------------------------------------------------------------

// stagedBinary 是一份已经验证过、等着被换上去的二进制。
type stagedBinary struct {
	Path         string
	Size         int64
	SHA256       string
	Version      string
	Commit       string
	MTime        time.Time
	Source       string // github | upload
	Channel      string
	SumsVerified bool
	ArchiveSHA   string
}

type upgradeManager struct {
	exe string
	// configDB 是配置库路径：托管升级用它定位暂存目录（配置库旁边的 upgrade/），
	// root 用 -upgrade-apply 应用时也会算出同一个位置。
	configDB string
	source   *releaseSource

	// verify / restart / restartDelay 是留给单测的注入点。
	// 这三件事在测试进程里必须有替身：verify 会真的去执行「被验证的文件」，
	// restart 会把当前进程 exec 掉，后果分别是「测试依赖一个真实二进制」
	// 和「测试跑一半自己没了」。生产路径用默认值（见 newUpgradeManagerFor），
	// 那里有一致性测试兜着，不会被悄悄换掉。
	verify       func(path string) (buildVersion, string, error)
	restart      func(env upgradeEnv) error
	restartDelay time.Duration

	mu     sync.Mutex
	staged *stagedBinary
	last   *upgradeCheckResult

	// busy 保证同一时刻只有一个升级动作（检查 / 上传 / 安装 / 回退）。
	// 用 CAS 而不是加锁：拿到锁之后要做的可能是几十秒的下载，
	// 而「现在忙不忙」这个判断本身必须是瞬时的、不能被阻塞。
	busy atomic.Bool
}

// newUpgradeManager 给守护进程用：构造 + 清理上次升级留下的中间文件。
func newUpgradeManager(exe, configDB string) *upgradeManager {
	um := newUpgradeManagerFor(exe, configDB)
	cleanupUpgradeLeftovers(exe)
	return um
}

// newUpgradeManagerFor 只构造，不做任何清理。
//
// 分开的理由是 -upgrade-apply 那条路（root 应用暂存文件）不能清 .staged：
// 那正是它要装的东西。只有守护进程需要「启动即清理」。
func newUpgradeManagerFor(exe, configDB string) *upgradeManager {
	return &upgradeManager{
		exe:          exe,
		configDB:     configDB,
		source:       newReleaseSource(),
		verify:       verifyBinary,
		restart:      restartProcess,
		restartDelay: upgradeRestartDelay,
	}
}

func (um *upgradeManager) env() upgradeEnv { return detectUpgradeEnv(um.exe, um.configDB) }

// stagePath 返回这次升级的暂存路径，空串表示当前连暂存都做不到。
//
// 命名统一是 <StageDir>/<二进制文件名>.staged：二进制目录可写时 StageDir 就是
// 它自己，于是这个路径正好等于 <exe>.staged，rename 仍落在同一个文件系统内
// （原子替换的前提）；写不进去时 StageDir 是配置库旁边的 upgrade/，
// 交给 root 用 -upgrade-apply 应用。
func (um *upgradeManager) stagePath() string {
	env := um.env()
	if env.StageDir == "" {
		return ""
	}
	return filepath.Join(env.StageDir, filepath.Base(um.exe)+".staged")
}

// stagedCandidates 列出所有可能放着暂存文件的位置，按优先级排列。
//
// 必须扫两个而不是算一个：托管升级把文件放在状态目录里，而 root 用
// -upgrade-apply 应用时算出来的 Writable 是 true（root 哪儿都能写），
// 只按「当前可写位置」去找就会扑空。
func (um *upgradeManager) stagedCandidates() []string {
	primary := um.exe + ".staged"
	out := []string{primary}
	if d := delegatedStageDir(um.configDB); d != "" {
		alt := filepath.Join(d, filepath.Base(um.exe)+".staged")
		if alt != primary {
			out = append(out, alt)
		}
	}
	return out
}

// findStaged 返回实际存在的暂存文件路径，没有就返回空串。
func (um *upgradeManager) findStaged() string {
	for _, p := range um.stagedCandidates() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}
func (um *upgradeManager) backupPath() string { return um.exe + ".old" }

func (um *upgradeManager) begin() bool  { return um.busy.CompareAndSwap(false, true) }
func (um *upgradeManager) end()         { um.busy.Store(false) }
func (um *upgradeManager) isBusy() bool { return um.busy.Load() }

func (um *upgradeManager) setStaged(st *stagedBinary) {
	um.mu.Lock()
	um.staged = st
	um.mu.Unlock()
}

func (um *upgradeManager) currentStaged() *stagedBinary {
	um.mu.Lock()
	defer um.mu.Unlock()
	return um.staged
}

func (um *upgradeManager) setLastCheck(res *upgradeCheckResult) {
	um.mu.Lock()
	um.last = res
	um.mu.Unlock()
}

func (um *upgradeManager) lastCheck() *upgradeCheckResult {
	um.mu.Lock()
	defer um.mu.Unlock()
	return um.last
}

func (um *upgradeManager) stagedView() upgradeStagedView {
	if st := um.currentStaged(); st != nil {
		return upgradeStagedView{
			Present:      true,
			Path:         st.Path,
			Size:         st.Size,
			SHA256:       st.SHA256,
			Version:      st.Version,
			Commit:       st.Commit,
			MTime:        formatLogTime(st.MTime),
			Verified:     true,
			Source:       st.Source,
			Channel:      st.Channel,
			SumsVerified: st.SumsVerified,
		}
	}
	// 进程里没有记录（多半是刚重启过）但磁盘上还留着一份：只报存在性和大小。
	// sha256 / 自述版本不必为了显示再算一遍，真装的时候一定会重新验证，
	// 到时候才算才有意义。
	// 进程里没有记录（多半是刚重启过）但磁盘上还留着一份：只报存在性和大小。
	// sha256 / 自述版本不必为了显示再算一遍，真装的时候一定会重新验证，
	// 到时候才算才有意义。
	if path := um.findStaged(); path != "" {
		if fi, err := os.Stat(path); err == nil {
			return upgradeStagedView{
				Present: true,
				Path:    path,
				Size:    fi.Size(),
				MTime:   formatLogTime(fi.ModTime()),
			}
		}
	}
	return upgradeStagedView{}
}

func (um *upgradeManager) backupView() upgradeBackupView {
	fi, err := os.Stat(um.backupPath())
	if err != nil || fi.IsDir() {
		return upgradeBackupView{}
	}
	v := upgradeBackupView{
		Present: true,
		Path:    um.backupPath(),
		Size:    fi.Size(),
		MTime:   formatLogTime(fi.ModTime()),
	}
	// 顺带把备份的自述版本读出来：界面要回答的是「回退会退到哪一版」，
	// 一个字节数回答不了这个问题。
	if bv, commit, err := um.verify(um.backupPath()); err == nil {
		v.Version, v.Commit = bv.Raw, commit
	}
	return v
}

// parkedSeq 给同一进程内的每次替换发一个序号。
//
// 不能只靠时间戳：Windows 上 time.Now 的粒度可能粗到毫秒级，同一毫秒内
// 连做两次替换会算出同一个名字（写这个模块时实测踩到过）。
var parkedSeq atomic.Int64

// parkedPath 返回这次替换专用的「挪走」文件名。
//
// 刻意每次都不一样：Windows 上正在运行的映像文件是删不掉的，第一次替换会把
// 旧映像以这个名字留在磁盘上（它还锁在当前进程手里）。名字如果固定，同一个
// 进程里的第二次替换就会因为「rename 的目标正好是那个锁着的文件」而直接
// Access is denied：症状是「升级成功之后再点一次回退就失败」。
// 带后缀的遗留文件由下次启动时的 cleanupUpgradeLeftovers 收拾。
func (um *upgradeManager) parkedPath() string {
	return fmt.Sprintf("%s.swap-old-%d-%d-%d", um.exe, os.Getpid(), time.Now().UnixNano(), parkedSeq.Add(1))
}

// install 把暂存的二进制换到位。只负责「已经验证过的东西」的替换动作。
func (um *upgradeManager) install(env upgradeEnv, st *stagedBinary) error {
	// 只有「能自己写二进制目录」时才走到这里。托管升级（Delegated）由
	// handleUpgradeInstall / handleUpgradeRollback 在调用前分流，不会进来。
	if !env.canSwap() {
		return upgradeConflict("upgrade_needs_root",
			"当前进程不能直接替换二进制（"+filepath.Dir(env.Exe)+" 不可写），需要 root 应用。")
	}
	if st == nil || st.Path == "" {
		return upgradeConflict("upgrade_nothing_staged", "没有待安装的二进制：先上传一个，或先检查更新。")
	}
	if err := swapBinary(um.exe, st.Path, um.backupPath(), um.parkedPath()); err != nil {
		// 这里刻意把真实原因回给客户端（其余 500 都是藏起来的，见 writeErr）：
		// 「替换失败」的成因基本只有权限和路径两类，而这两类的处置办法完全不同，
		// 说一句「服务端内部错误」等于让人去翻日志猜。路径本来也已经出现在
		// GET /_goproxy/upgrade 的响应里，不构成新的信息披露。
		slog.Error("升级：替换二进制失败", "exe", um.exe, "staged", st.Path, "err", err)
		return &apiError{http.StatusInternalServerError, "upgrade_swap_failed", err.Error()}
	}
	um.setStaged(nil)
	return nil
}

// stageFromDisk 把「已经躺在暂存路径上」的文件验证一遍并登记。
//
// 上传接口负责把文件写到暂存路径，安装接口再走这里，分开的理由是
// 上传时验证一次（能立刻告诉用户文件不对），安装前再验证一次（防的是
// 「上传之后、安装之前」这段窗口里文件被换掉）。验证本身很便宜。
func (um *upgradeManager) stageFromDisk(expectedSHA string) (*stagedBinary, error) {
	path := um.findStaged()
	if path == "" {
		return nil, upgradeConflict("upgrade_nothing_staged", "服务端没有待安装的文件：请先在控制台上传一个二进制，或先检查更新。")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, upgradeConflict("upgrade_nothing_staged", "暂存路径是个目录，不能当作二进制安装。")
	}
	sha, err := hashFile(path)
	if err != nil {
		return nil, err
	}
	if want := strings.TrimSpace(expectedSHA); want != "" && !strings.EqualFold(want, sha) {
		return nil, upgradeConflict("upgrade_sha256_mismatch",
			fmt.Sprintf("暂存文件的 sha256 是 %s，与请求里的 %s 不一致，已拒绝安装（文件在上传后被改动过）。", sha, want))
	}
	bv, commit, err := um.verify(path)
	if err != nil {
		return nil, &apiError{http.StatusBadGateway, "upgrade_bad_binary", err.Error()}
	}
	st := &stagedBinary{
		Path: path, Size: fi.Size(), SHA256: sha,
		Version: bv.Raw, Commit: commit, MTime: fi.ModTime(),
		Source: "upload",
	}
	um.setStaged(st)
	return st, nil
}

// stageFromGitHub 从 GitHub Releases 取指定版本（空 = 最新）并落到暂存位。
func (um *upgradeManager) stageFromGitHub(ctx context.Context, want string, force bool) (*stagedBinary, *fetchResult, error) {
	info, err := um.source.latestRelease(ctx, want)
	if err != nil {
		return nil, nil, &apiError{http.StatusBadGateway, "upgrade_source_unreachable",
			"取不到发布信息：" + err.Error()}
	}
	newVer := parseBuildVersion(info.Tag)
	if !newVer.OK {
		return nil, nil, &apiError{http.StatusBadGateway, "upgrade_bad_release_tag",
			fmt.Sprintf("发布版本号 %q 解析不了，拒绝自动升级（可以指定一个具体版本，或改用上传文件）。", info.Tag)}
	}

	cur := parseBuildVersion(version)
	if cur.OK && compareBuild(cur, newVer) >= 0 && !force {
		return nil, nil, upgradeConflict("upgrade_already_current",
			fmt.Sprintf("当前 %s 已经不低于 %s，没有需要安装的更新。确实要重装同一版本，请带上 force。", version, info.Tag))
	}

	dest := um.stagePath()
	if dest == "" {
		return nil, nil, upgradeConflict("upgrade_unsupported",
			"没有可写的暂存位置（二进制目录与状态目录都写不进去），无法升级。")
	}
	res, err := um.source.fetchRelease(ctx, info, dest, upgradeMaxStagedBytes)
	if err != nil {
		_ = os.Remove(dest)
		return nil, nil, err
	}

	bv, commit, err := um.verify(dest)
	if err != nil {
		_ = os.Remove(dest)
		return nil, nil, &apiError{http.StatusBadGateway, "upgrade_bad_binary", err.Error()}
	}
	// 自述版本比发布 tag 还旧：最常见成因是加速镜像缓存了旧文件。
	// 装下去就会出现「升级成功了但版本没变」这种最费解的现象，所以直接拦住。
	if bv.OK && compareBuild(bv, newVer) < 0 {
		_ = os.Remove(dest)
		return nil, nil, &apiError{http.StatusBadGateway, "upgrade_stale_mirror",
			fmt.Sprintf("下载到的二进制自述版本是 %s，低于发布版本 %s（多半是加速镜像缓存着旧文件），已放弃安装。", bv.Raw, info.Tag)}
	}
	sha, err := hashFile(dest)
	if err != nil {
		_ = os.Remove(dest)
		return nil, nil, err
	}
	fi, err := os.Stat(dest)
	if err != nil {
		return nil, nil, err
	}
	st := &stagedBinary{
		Path: dest, Size: fi.Size(), SHA256: sha,
		Version: bv.Raw, Commit: commit, MTime: fi.ModTime(),
		Source: "github", Channel: res.Channel, SumsVerified: res.SumsVerified,
		ArchiveSHA: res.ArchiveSHA256,
	}
	um.setStaged(st)
	return st, res, nil
}

// restartSoon 在响应发出去之后替换进程。
func (um *upgradeManager) restartSoon(env upgradeEnv, from, to string) {
	time.Sleep(um.restartDelay)
	slog.Info("升级：替换进程", "from", from, "to", to, "strategy", env.Strategy, "exe", env.Exe)
	if err := um.restart(env); err != nil {
		slog.Error("升级：替换进程失败，新二进制已经就位但仍在跑旧进程",
			"err", err, "exe", env.Exe,
			"hint", "手动重启即可生效（systemd: systemctl restart goproxy）；要撤销这次升级用控制台的「回退上一版」")
	}
}

// ---------------------------------------------------------------------------
// HTTP 视图
// ---------------------------------------------------------------------------

type upgradeRuntimeView struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	Exe        string `json:"exe"`
	ExeDir     string `json:"exe_dir"`
	Service    string `json:"service"`
	Strategy   string `json:"restart_strategy"`
	Comparable bool   `json:"version_comparable"`
}

type upgradeSourceView struct {
	Repo      string   `json:"repo"`
	Mode      string   `json:"mode"`
	Channels  []string `json:"channels"`
	AssetName string   `json:"asset_name"`
	SumsName  string   `json:"sums_name"`
}

type upgradeStagedView struct {
	Present      bool   `json:"present"`
	Path         string `json:"path,omitempty"`
	Size         int64  `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Version      string `json:"version,omitempty"`
	Commit       string `json:"commit,omitempty"`
	MTime        string `json:"mtime,omitempty"`
	Verified     bool   `json:"verified"`
	Source       string `json:"source,omitempty"`
	Channel      string `json:"channel,omitempty"`
	SumsVerified bool   `json:"sums_verified"`
}

type upgradeBackupView struct {
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	MTime   string `json:"mtime,omitempty"`
}

type upgradeAssetView struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

type upgradeCheckResult struct {
	Current           string           `json:"current"`
	CurrentComparable bool             `json:"current_comparable"`
	Latest            string           `json:"latest"`
	LatestComparable  bool             `json:"latest_comparable"`
	UpdateAvailable   bool             `json:"update_available"`
	ReleaseURL        string           `json:"release_url"`
	Asset             upgradeAssetView `json:"asset"`
	Channel           string           `json:"channel"`
	SumsVerified      bool             `json:"sums_verified"`
	CheckedAt         string           `json:"checked_at"`
	Notes             string           `json:"notes,omitempty"`
}

type upgradeStateResponse struct {
	Runtime   upgradeRuntimeView  `json:"runtime"`
	Supported bool                `json:"supported"`
	Reason    string              `json:"reason,omitempty"`
	Writable  bool                `json:"writable"`
	Source    upgradeSourceView   `json:"source"`
	Staged    upgradeStagedView   `json:"staged"`
	Backup    upgradeBackupView   `json:"backup"`
	Busy      bool                `json:"busy"`
	LastCheck *upgradeCheckResult `json:"last_check,omitempty"`
	// NeedsRoot 表示升级 / 回退的最后一步必须由 root 做：进程能下载、能校验、
	// 能跑 -version 验证，但写不进二进制目录（install.sh 装出来的实例就是这种）。
	// 这时 StageDir 是暂存位置，ApplyCommand / RollbackCommand 是给人复制的命令。
	NeedsRoot       bool   `json:"needs_root"`
	StageDir        string `json:"stage_dir,omitempty"`
	ApplyCommand    string `json:"apply_command,omitempty"`
	RollbackCommand string `json:"rollback_command,omitempty"`
}

// upgradeInstallResult 是安装 / 回退成功后回给控制台的东西。
// 注意它是在**进程被替换之前**写出去的，所以里面的 restart 字段描述的是
// 接下来会发生什么，而不是已经发生了什么。
type upgradeInstallResult struct {
	OK           bool   `json:"ok"`
	From         string `json:"from"`
	To           string `json:"to"`
	SHA256       string `json:"sha256"`
	Backup       string `json:"backup"`
	Restart      string `json:"restart"`
	Service      string `json:"service"`
	Source       string `json:"source"`
	Verified     bool   `json:"verified"`
	Channel      string `json:"channel,omitempty"`
	SumsVerified bool   `json:"sums_verified"`
	// ArchiveSHA256 是发布包（tar.gz）的 sha256，也就是校验和文件里那一个。
	// 它和 SHA256 不是一回事：SHA256 是最终装上去那个二进制的哈希。
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
	// NeedsRoot 为 true 时这次「安装」只是把新版本暂存好了，还没换上去：
	// ApplyCommand 是下一步要在服务器上执行的 root 命令，StagedPath / StagedSHA256
	// 是那份待应用文件的落点与哈希，方便人工核对。
	NeedsRoot    bool   `json:"needs_root"`
	ApplyCommand string `json:"apply_command,omitempty"`
	StagedPath   string `json:"staged_path,omitempty"`
	StagedSHA256 string `json:"staged_sha256,omitempty"`
}

// ---------------------------------------------------------------------------
// 处理器
// ---------------------------------------------------------------------------

func upgradeConflict(code, msg string) *apiError {
	return &apiError{http.StatusConflict, code, msg}
}

// readOptionalJSON 读一个可选的 JSON 请求体：空 body 当作「没有参数」。
//
// 管理接口的 readBody 把空 body 当错误（对写配置的接口来说是对的：静默接受
// 一个空 PATCH 会让人以为改成功了）。升级这几个接口不一样
// `curl -X POST /_goproxy/upgrade/check` 不带 body 是完全合理的用法。
func readOptionalJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return badRequest("body_read_failed", "读取请求体失败: %v", err)
	}
	if len(raw) > maxBodyBytes {
		return &apiError{http.StatusRequestEntityTooLarge, "body_too_large", "请求体超过 1MiB"}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return badRequest("bad_json", "请求体不是合法 JSON：%v", err)
	}
	return nil
}

// actorLabel 给审计日志一个「谁干的」。
//
// adminGuard 只判断「能不能进」，不往 request 里塞身份；升级是这台机器上
// 后果最大的一个动作，日志里必须留下是谁触发的。
func actorLabel(user string, via authVia) string {
	if user != "" {
		return user
	}
	switch via {
	case viaBearer:
		return "(bearer token)"
	case viaSession:
		return "(session)"
	}
	return "(unknown)"
}

func (a *App) handleUpgradeState(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	cur := parseBuildVersion(version)
	pkg, sums := platformAssetNames()

	resp := upgradeStateResponse{
		Runtime: upgradeRuntimeView{
			Version:    version,
			Commit:     commit,
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
			Exe:        env.Exe,
			ExeDir:     env.Dir,
			Service:    env.Service,
			Strategy:   string(env.Strategy),
			Comparable: cur.OK,
		},
		Supported: env.supported(),
		Reason:    env.Reason,
		Writable:  env.Writable,
		Source: upgradeSourceView{
			Repo:      um.source.repo,
			Mode:      um.source.mode,
			Channels:  channelLabels(um.source.channels()),
			AssetName: pkg,
			SumsName:  sums,
		},
		Staged:    um.stagedView(),
		Backup:    um.backupView(),
		Busy:      um.isBusy(),
		LastCheck: um.lastCheck(),
	}
	if env.Delegated {
		// 能下载、能校验、能验证，但写不进二进制目录：把「以 root 应用」的命令给出来。
		resp.NeedsRoot = true
		resp.StageDir = env.StageDir
		resp.ApplyCommand = um.applyCommand(false)
		resp.RollbackCommand = um.applyCommand(true)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	var req struct {
		Version string `json:"version"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	ctx, cancel := context.WithTimeout(r.Context(), upgradeCheckTimeout)
	defer cancel()

	info, err := um.source.latestRelease(ctx, req.Version)
	if err != nil {
		writeErr(w, &apiError{http.StatusBadGateway, "upgrade_source_unreachable",
			"取不到发布信息：" + err.Error()})
		return
	}

	pkg, sumsName := platformAssetNames()
	cur := parseBuildVersion(version)
	lat := parseBuildVersion(info.Tag)
	res := &upgradeCheckResult{
		Current:           version,
		CurrentComparable: cur.OK,
		Latest:            info.Tag,
		LatestComparable:  lat.OK,
		// 当前版本比不了（dev / 裸提交号）时按「有更新」处理：
		// 那不是发布版本，给一条能升到正式版本的路径比说「已是最新」有用。
		UpdateAvailable: !cur.OK || (lat.OK && compareBuild(cur, lat) < 0),
		ReleaseURL:      info.HTMLURL,
		Asset:           upgradeAssetView{Name: pkg},
		CheckedAt:       formatLogTime(time.Now()),
		Notes:           info.Notes,
	}
	// 顺手把校验和文件拿下来：它是发布方给出的权威 sha256，也是 install.sh
	// 用来探测「哪个下载通道通」的探针（只有几十字节，秒级）。拿不到不算失败，
	// 只是这次检查给不出 sha256，界面上会标成「未校验」。
	if sum, ch, err := um.source.fetchSums(ctx, info.Tag, pkg, sumsName); err == nil {
		res.Asset.SHA256 = sum
		res.Channel = ch
		res.SumsVerified = true
	} else {
		slog.Warn("升级：取校验和文件失败，本次检查不提供 sha256", "tag", info.Tag, "err", err)
	}
	res.Asset.Size = um.source.assetSize(ctx, info, pkg, res.Channel)

	um.setLastCheck(res)
	writeJSON(w, http.StatusOK, res)
}

func (a *App) handleUpgradeUpload(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	src, name, err := openUploadedBinary(r)
	if err != nil {
		writeErr(w, err)
		return
	}

	// 落点由 stagePath 决定：二进制目录可写时就在它旁边（最后那一步 rename 才能
	// 落在同一个文件系统内）；写不进去时退到状态目录，由 root 用 -upgrade-apply 应用。
	stagePath := um.stagePath()
	if stagePath == "" {
		writeErr(w, upgradeConflict("upgrade_unsupported", "没有可写的暂存位置，无法接收上传。"))
		return
	}
	f, err := os.OpenFile(stagePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		writeErr(w, err)
		return
	}
	written, err := io.Copy(f, io.LimitReader(src, upgradeMaxStagedBytes+1))
	if err != nil {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, badRequest("upload_failed", "接收上传数据失败：%v", err))
		return
	}
	if written > upgradeMaxStagedBytes {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, &apiError{http.StatusRequestEntityTooLarge, "upload_too_large",
			fmt.Sprintf("文件超过上限 %d MiB", upgradeMaxStagedBytes>>20)})
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}

	// 上传的可能是原始二进制，也可能是发布用的 tar.gz（就是 README 里让人
	// 下载的那个包）。按魔数认，别让人先手动解包一遍。
	if isGzipFile(stagePath) {
		archive := stagePath + ".tar.gz"
		if err := os.Rename(stagePath, archive); err != nil {
			_ = os.Remove(stagePath)
			writeErr(w, err)
			return
		}
		if err := extractBinaryFromArchive(archive, stagePath, upgradeMaxStagedBytes); err != nil {
			_ = os.Remove(archive)
			_ = os.Remove(stagePath)
			writeErr(w, badRequest("bad_archive", "解包上传的 tar.gz 失败：%v", err))
			return
		}
		_ = os.Remove(archive)
	}

	st, err := um.stageFromDisk("")
	if err != nil {
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}
	slog.Info("升级：已接收上传的二进制", "actor", actor, "file", filepath.Base(name),
		"size", st.Size, "sha256", st.SHA256, "version", st.Version)
	writeJSON(w, http.StatusOK, um.stagedView())
}

func (a *App) handleUpgradeInstall(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}

	var req struct {
		Source  string `json:"source"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
		Force   bool   `json:"force"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.Source == "" {
		req.Source = "github"
	}
	if req.Source != "github" && req.Source != "upload" {
		writeErr(w, badRequest("bad_source", "source 只能是 github 或 upload，收到 %q", req.Source))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	from := version

	var (
		st  *stagedBinary
		res *fetchResult
		err error
	)
	if req.Source == "upload" {
		st, err = um.stageFromDisk(req.SHA256)
	} else {
		st, res, err = um.stageFromGitHub(r.Context(), req.Version, req.Force)
	}
	if err != nil {
		writeErr(w, err)
		return
	}

	// 托管：下载、校验、-version 验证都已经做完了，但进程写不进去二进制目录，
	// 最后那一步（写文件 + 重启服务）得由 root 来。这不是失败，所以回 200，
	// 把该执行的命令一并给出去；界面据此显示「等待 root 应用」。
	if !env.canSwap() {
		slog.Info("升级：已暂存，等待 root 应用", "actor", actor, "source", req.Source,
			"from", from, "to", st.Version, "staged", st.Path, "sha256", st.SHA256)
		out := upgradeInstallResult{
			OK: true, From: from, To: st.Version, SHA256: st.SHA256,
			Backup: filepath.Base(um.backupPath()), Restart: string(env.Strategy),
			Service: env.Service, Source: st.Source, Verified: true,
			Channel: st.Channel, SumsVerified: st.SumsVerified, ArchiveSHA256: st.ArchiveSHA,
			NeedsRoot: true, ApplyCommand: um.applyCommand(false),
			StagedPath: st.Path, StagedSHA256: st.SHA256,
		}
		if res != nil {
			out.Channel = res.Channel
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	slog.Info("升级：开始安装", "actor", actor, "source", req.Source,
		"from", from, "to", st.Version, "sha256", st.SHA256, "sums_verified", st.SumsVerified)
	if err := um.install(env, st); err != nil {
		writeErr(w, err)
		return
	}
	out := upgradeInstallResult{
		OK: true, From: from, To: st.Version, SHA256: st.SHA256,
		Backup: filepath.Base(um.backupPath()), Restart: string(env.Strategy),
		Service: env.Service, Source: st.Source, Verified: true,
		Channel: st.Channel, SumsVerified: st.SumsVerified, ArchiveSHA256: st.ArchiveSHA,
	}
	if res != nil {
		out.Channel = res.Channel
	}
	writeJSON(w, http.StatusOK, out)

	// 最后一步：把当前进程换成新二进制。放在响应之后，因为 syscall.Exec
	// 会把进程镜像整个换掉，响应必须已经发出去。
	go um.restartSoon(env, from, st.Version)
}

func (a *App) handleUpgradeRollback(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	backupPath := um.backupPath()
	if _, err := os.Stat(backupPath); err != nil {
		writeErr(w, upgradeConflict("upgrade_no_backup",
			"没有可回退的备份（"+filepath.Base(backupPath)+" 不存在）：只有在本机做过一次升级之后才会有备份。"))
		return
	}

	// 托管：进程写不进去二进制目录，回退同样得由 root 应用。这里只把命令给出，
	// 因为回退走的是和升级完全相同的替换路径（同一份 <exe>.old）。
	if !env.canSwap() {
		slog.Info("升级：回退需要 root 应用", "actor", actor, "from", version)
		writeJSON(w, http.StatusOK, upgradeInstallResult{
			OK: true, From: version, To: um.backupView().Version,
			Backup: filepath.Base(backupPath), Restart: string(env.Strategy),
			Service: env.Service, Source: "rollback", Verified: true,
			NeedsRoot: true, ApplyCommand: um.applyCommand(true),
		})
		return
	}

	// 先把备份复制成一份暂存，再走和正常升级完全相同的替换流程。
	// 不直接拿备份文件去 rename 的两个理由：备份要留着（否则回退一次就没了，
	// 想再切回去还得重下），以及「暂存」这条路径上的验证逻辑可以复用。
	stagedPath := um.stagePath()
	if err := copyFile(backupPath, stagedPath, 0o755); err != nil {
		writeErr(w, err)
		return
	}
	st, err := um.stageFromDisk("")
	if err != nil {
		_ = os.Remove(stagedPath)
		writeErr(w, err)
		return
	}

	slog.Info("升级：回退到上一版", "actor", actor, "from", version, "to", st.Version, "sha256", st.SHA256)
	if err := um.install(env, st); err != nil {
		writeErr(w, err)
		return
	}

	writeJSON(w, http.StatusOK, upgradeInstallResult{
		OK: true, From: version, To: st.Version, SHA256: st.SHA256,
		Backup: filepath.Base(backupPath), Restart: string(env.Strategy),
		Service: env.Service, Source: "rollback", Verified: true,
	})
	go um.restartSoon(env, version, st.Version)
}

// openUploadedBinary 从请求里取出要安装的字节流。
//
// 两种提交方式都支持，都是为了「用 curl 也能升级」：
//   - multipart/form-data，字段名 file（浏览器表单，也是控制台在用的）
//   - 请求体就是文件本身（curl --data-binary @goproxy-linux-amd64.tar.gz）
func openUploadedBinary(r *http.Request) (io.Reader, string, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, "", badRequest("bad_multipart", "解析 multipart 请求失败：%v", err)
		}
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, "", badRequest("no_file_part", "multipart 请求里没有找到文件字段（字段名用 file）")
			}
			if err != nil {
				return nil, "", badRequest("bad_multipart", "读取上传数据失败：%v", err)
			}
			if part.FormName() == "file" && part.FileName() != "" {
				return part, part.FileName(), nil
			}
			_ = part.Close()
		}
	}
	if r.ContentLength == 0 {
		return nil, "", badRequest("empty_body",
			"请求体为空：请用 multipart 的 file 字段，或直接把二进制放在请求体里")
	}
	return r.Body, "", nil
}

// isGzipFile 看文件头是不是 gzip 魔数（1f 8b）。用来区分「原始二进制」和
// 「发布用的 tar.gz」，省掉「先自己解包再上传」这一步。
func isGzipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x1f && magic[1] == 0x8b
}

// ---------------------------------------------------------------------------
// 以 root 应用（托管升级的后半段）
//
// install.sh 装出来的实例里，服务以 goproxy 身份跑、/usr/local/bin 归 root，
// 所以进程自己能做的只有「下载 + 校验 + 验证 + 暂存」。最后那一步写文件、
// 重启服务需要权限，由这两条命令完成：
//
//goproxy -c <库> -upgrade-apply      应用暂存的新版本
//goproxy -c <库> -upgrade-rollback   回退到 <exe>.old
//
// 两条都复用升级模块自己的替换逻辑（同样的「先备份、再改名挪开、再放上去」、
// 同一份 <exe>.old），所以「界面点的」和「命令行做的」结果一致。
// ---------------------------------------------------------------------------

func runUpgradeApply(configDB string, rollback bool) error {
	exe := executablePath()
	if exe == "" {
		return errors.New("拿不到当前可执行文件路径，无法应用")
	}
	// 用 newUpgradeManagerFor：它不清 .staged，而 .staged 正是这次要装的东西。
	um := newUpgradeManagerFor(exe, configDB)

	src := um.findStaged()
	what := "暂存的新版本"
	if rollback {
		// 先把备份复制成一份「回退专用」的暂存文件，不能直接拿 <exe>.old 当源（见
		// prepareRollbackSource 的注释：直接当源会被 swapBinary 的第一步覆盖掉）。
		var err error
		src, err = prepareRollbackSource(exe, um.backupPath())
		if err != nil {
			return err
		}
		what = "备份的上一版"
	}
	if src == "" {
		return fmt.Errorf("没有可应用的%s：暂存文件不存在（先到控制台的「升级」页下载或上传）", what)
	}
	if fi, err := os.Stat(src); err != nil || fi.IsDir() {
		return fmt.Errorf("读%s失败：%v", what, err)
	}
	if !dirWritable(filepath.Dir(exe)) {
		return fmt.Errorf("没有写 %s 的权限，这条命令要用 root 跑（sudo）", filepath.Dir(exe))
	}

	// 换掉线上二进制之前再验证一次：校验和只证明字节没坏，跑得起来才算数。
	// 这一步和 install.sh 第 7 节是同一个道理。
	sha, err := hashFile(src)
	if err != nil {
		return err
	}
	bv, commit, err := verifyBinary(src)
	if err != nil {
		return fmt.Errorf("待应用的%s通不过验证，已放弃：%w", what, err)
	}
	if err := swapBinary(exe, src, um.backupPath(), um.parkedPath()); err != nil {
		if rollback {
			_ = os.Remove(src)
		}
		return err
	}
	slog.Info("升级：已应用", "what", what, "exe", exe, "version", bv.Raw, "commit", commit,
		"sha256", sha, "backup", um.backupPath())
	return restartServiceAfterApply()
}

// restartServiceAfterApply 让服务加载新版本。
//
// 只认 systemd（install.sh 的部署形态）：不是 systemd 环境时不做任何猜测，
// 把「请手动重启」留给操作者  二进制已经换好了，重启是唯一的下一步。
// prepareRollbackSource 把 <exe>.old 复制成一份「回退专用」的暂存文件并返回它的路径。
//
// 必须复制，不能直接拿备份当源：swapBinary 的第一步是「把当前二进制备份到
// backupPath」，源如果就是 backupPath，那一步会先把源覆盖成当前这一版，
// 于是最后装上去的还是原来那一版  现象是「回退成功了但版本没变」
// （真实端到端跑出来的坑，界面那条路早就是这么绕的）。
//
// 复制出来的那份会在 swap 时被 rename 走，正常路径不需要清理；失败时由调用方删。
func prepareRollbackSource(exe, backup string) (string, error) {
	if fi, err := os.Stat(backup); err != nil || fi.IsDir() {
		return "", fmt.Errorf("没有可回退的备份：%s 不存在（只有在本机做过一次升级之后才会有）", backup)
	}
	dst := filepath.Join(filepath.Dir(exe), filepath.Base(exe)+".rollback-staged")
	if err := copyFile(backup, dst, 0o755); err != nil {
		return "", fmt.Errorf("准备回退失败：%w", err)
	}
	return dst, nil
}

func restartServiceAfterApply() error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		slog.Warn("升级：不是 systemd 环境，二进制已替换，请手动重启服务以加载新版本")
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		slog.Warn("升级：找不到 systemctl，二进制已替换，请手动重启服务", "err", err)
		return nil
	}
	out, err := exec.Command("systemctl", "restart", "goproxy").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart goproxy 失败（%v）：%s（二进制已经换好了，可手动重启）",
			err, truncateForMsg(string(out)))
	}
	slog.Info("升级：已重启 systemd 服务 goproxy")
	return nil
}

// applyCommand 返回「以 root 应用」的命令，控制台把它显示出来让人复制。
func (um *upgradeManager) applyCommand(rollback bool) string {
	flag := "-upgrade-apply"
	if rollback {
		flag = "-upgrade-rollback"
	}
	return fmt.Sprintf("sudo %s -c %s %s", shellQuote(um.exe), shellQuote(um.configDB), flag)
}

// shellQuote 在必要时给路径加单引号，让复制出来的命令能直接用。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t'\"\\$&|;<>()") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
