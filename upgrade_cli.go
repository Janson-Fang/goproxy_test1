package main

// 命令行入口：-upgrade-apply / -upgrade-rollback（runUpgradeApply 等）。
// 从 upgrade.go 拆出，纯机械移动，逻辑未动。

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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
