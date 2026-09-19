package main

// 版本号解析与比较（parseBuildVersion / compareBuild）。
// 从 upgrade.go 拆出，纯机械移动，逻辑未动。

import (
	"regexp"
	"strconv"
	"strings"
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
