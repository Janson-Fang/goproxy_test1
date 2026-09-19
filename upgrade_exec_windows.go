//go:build windows

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// restartProcess 在 Windows 上只能「起一个新进程，再退出自己」。
//
// Windows 既没有 exec 这种替换进程镜像的操作，运行中的 exe 又不能覆盖，
// 所以顺序上依赖 swapBinary 先做完的事：旧文件被改名挪到一边，路径上放的
// 是新二进制，这时才能从同一个路径启动新进程。
//
// 这条路的固有权衡，写在这里免得以后有人以为它是无损的：
//
//   - 新进程要等旧进程释放端口才能真正起来，而这里是「先 Start 再退出自己」。
//     实测这个窗口足够（子进程要初始化 Go runtime 才会去 bind），但理论上仍
//     存在「子进程先到 bind、被旧进程的 SO_EXCLUSIVEADDRUSE 顶掉」的可能。
//   - 退出自己之后就没人能观察子进程是否起来了，所以这一步是「尽力而为」：
//     真的起不来时由用户按控制台的提示手动处理（二进制已经换好了，界面上
//     还有「回退上一版」这一条退路）。
//
// Linux 上用 syscall.Exec 没有这些问题，这也是 install.sh 只支持 Linux 的原因之一。
func restartProcess(env upgradeEnv) error {
	cmd := exec.Command(env.Exe, os.Args[1:]...)
	cmd.Dir = env.Dir
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// DETACHED_PROCESS（0x00000008）：不继承当前控制台。
	// 不这么做的话，从 cmd 窗口起的实例会随着窗口关闭把新进程一起带走。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动新进程 %s 失败：%w", env.Exe, err)
	}
	slog.Info("升级：新进程已启动，当前进程退出", "exe", env.Exe, "pid", cmd.Process.Pid)
	// 直接把进程换掉：继续留在旧镜像里跑，端口和日志都会和新进程打架。
	os.Exit(0)
	return nil
}
