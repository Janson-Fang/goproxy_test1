//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// restartProcess 用 syscall.Exec 把当前进程镜像原地换成刚装上去的二进制。
//
// 为什么不「退出让服务管理器拉起来」：
//
//   - 手工 ./goproxy 起的实例没有服务管理器，退出就真的下线了；
//   - systemd 那套要依赖 Restart=always 的写法（install.sh 写是这么写的，
//     但用户自己改过单元文件的话就不成立了）；
//   - 原地 exec 的 PID 不变，systemd 完全察觉不到这次替换，也就不用去动
//     任何服务配置。
//
// 成功后这个函数不会返回：当前进程的地址空间已经被新二进制替换掉了。
// 端口会在新镜像里重新绑定，中间的窗口就是一次 exec 的时间。
func restartProcess(env upgradeEnv) error {
	argv := os.Args
	if len(argv) == 0 {
		argv = []string{env.Exe}
	}
	// argv[0] 用绝对路径：WorkingDirectory 或 PATH 变了也不会找错文件。
	argv[0] = env.Exe
	if err := syscall.Exec(env.Exe, argv, os.Environ()); err != nil {
		// 走到这里说明 exec 失败，也就是新二进制根本起不来
		// （架构不对、缺动态库、被 SELinux 拦下之类）。
		// 这时候：systemd 管的实例直接退出，让 Restart=always 用新文件再拉一次
		// （起不来会被 StartLimit 挡住并标记 failed，备份的 .old 还在，能回退）；
		// 其它情况留在原进程里：服务不掉，日志里说清楚要手工重启。
		if env.Service == "systemd" {
			fmt.Fprintf(os.Stderr, "升级：exec 新二进制失败（%v），退出进程交给 systemd 重启\n", err)
			os.Exit(0)
		}
		return fmt.Errorf("exec %s 失败：%w", env.Exe, err)
	}
	return nil
}
