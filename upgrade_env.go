package main

// 升级环境探测（detectUpgradeEnv）与二进制文件操作（verifyBinary / swapBinary / copyFile）。
// 从 upgrade.go 拆出，纯机械移动，逻辑未动。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

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

	if err := renameWithRetry(exe, parked); err != nil {
		return fmt.Errorf("移开当前二进制失败：%w", err)
	}
	if err := renameWithRetry(newPath, exe); err != nil {
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

// renameWithRetry 改名，失败时短暂重试几次。
//
// 为什么需要它：Windows 上刚被写入或被扫描的文件会被**短暂**持有
// （杀毒实时防护、搜索索引、以及「刚被执行过的映像」），此时 rename 报
// `The process cannot access the file because it is being used by another process`。
// 这是端到端跑出来的：同一次替换在几秒内第一次失败、第二次成功 ——
// 也就是说它**不是**「Windows 不允许改名运行中的 exe」（实测允许），
// 而是一个瞬时的共享冲突。
//
// 加这个重试的理由是它出现在升级路径上：失败一次的表现是「升级失败」
// 加一句看不懂的英文错误，而操作者能做的往往就是「再点一次」。
// 重试本来就是这件正确的事，只是不该由人来点。
//
// 只重试共享冲突这一类错误，别的错误（路径不存在、权限）立刻返回 ——
// 那些重试一百次也不会变好。
func renameWithRetry(src, dst string) error {
	const attempts = 5
	var err error
	for i := 0; i < attempts; i++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		if !isTransientLock(err) {
			return err
		}
		time.Sleep(time.Duration(120*(i+1)) * time.Millisecond)
	}
	return err
}

// isTransientLock 判断这个错误是不是「文件被短暂占用」。
//
// 认 Windows 的错误码（32 = ERROR_SHARING_VIOLATION，33 = ERROR_LOCK_VIOLATION）
// 以及 Unix 侧的 EBUSY。字符串匹配只在 Windows 上兜底：syscall.Errno 能直接比，
// 但这里刻意不引入平台分支文件 —— 一个字符串包含判断足够表达意图，也不会
// 因为平台差异把该重试的失败漏掉。
func isTransientLock(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch int(errno) {
		case 32, 33, 11, 16: // Windows 共享冲突/锁冲突；EAGAIN；EBUSY
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "being used by another process") ||
		strings.Contains(msg, "sharing violation") ||
		strings.Contains(msg, "resource busy")
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
