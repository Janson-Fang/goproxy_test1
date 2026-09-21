package main

// upgradeManager：暂存、下载、校验、安装、回退、重启。
// 从 upgrade.go 拆出，纯机械移动，逻辑未动。

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 管理器
// ---------------------------------------------------------------------------

// stagedBinary 是一份已经验证过、等着被换上去的二进制。
type stagedBinary struct {
	Path    string
	Size    int64
	SHA256  string
	Version string
	Commit  string
	MTime   time.Time
	Source  string // upload | rollback
}

type upgradeManager struct {
	exe string
	// configDB 是配置库路径：托管升级用它定位暂存目录（配置库旁边的 upgrade/），
	// root 用 -upgrade-apply 应用时也会算出同一个位置。
	configDB string

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

	// busy 保证同一时刻只有一个升级动作（上传 / 安装 / 回退）。
	// 用 CAS 而不是加锁：拿到锁之后要做的可能是几十秒的写入与校验，
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

func (um *upgradeManager) stagedView() upgradeStagedView {
	if st := um.currentStaged(); st != nil {
		return upgradeStagedView{
			Present:  true,
			Path:     st.Path,
			Size:     st.Size,
			SHA256:   st.SHA256,
			Version:  st.Version,
			Commit:   st.Commit,
			MTime:    formatLogTime(st.MTime),
			Verified: true,
			Source:   st.Source,
		}
	}
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
		return nil, upgradeConflict("upgrade_nothing_staged", "服务端没有待安装的文件：请先在控制台上传一个二进制。")
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
