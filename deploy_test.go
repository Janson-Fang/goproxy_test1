package main

// 部署文件之间的不变量。
//
// install.sh / Dockerfile / docker-compose.yml 分处三个地方，改了一处忘了另一处
// 是很典型的失误，而后果要到线上真正操作时才暴露 —— 最典型的就是「删除路由」
// 直接报错：
//
//	attempt to write a readonly database
//
// 根因是管理接口要写配置数据库（SQLite），而三个部署路径各自都可能让配置目录
// 变成不可写：
//
//	· systemd  ProtectSystem=strict 把 /etc 挂成只读，ReadWritePaths 没放行配置目录
//	· systemd  放行了，但目录还是 root:root 0755 —— ReadWritePaths 只改挂载属性，
//	           不改 Unix 权限，以 goproxy 身份跑的服务照样写不进去
//	· Docker   容器以 uid 10001 跑，镜像里的 /etc/goproxy 是 root:root
//	· Docker   把配置挂成了**单个文件** —— SQLite 要在库文件旁边建 -wal / -shm，
//	           单文件挂载会让这些兄弟文件落在容器临时层里；而旧版（v0.8.x）的
//	           配置写回还会撞上 rename 挂载点的 EBUSY
//
// 一条纪律：**注释不算数**。install.sh 的注释里到处都在提 $CONFIG_DIR，
// compose 里也有注释掉的 ports 示例 —— 拿 strings.Contains 扫全文会被注释命中，
// 测试恒过、等于没测。这个坑在 TestDeploymentFilesMentionTLSPorts 上真踩过一次。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// effectiveLines 读文件并去掉注释行与空行，只留真正生效的行。
func effectiveLines(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		// 这里用 Fatalf 而不是 Skipf：这些文件是守卫对象，缺失就该报错。
		t.Fatalf("读不到 %s: %v —— 它是本测试的守卫对象，不能缺失", file, err)
	}
	return stripComments(strings.Split(string(b), "\n"))
}

func stripComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

var heredocRE = regexp.MustCompile(`<<-?["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)

// extractHeredoc 取出 install.sh 里 `<<EOF ... EOF` 之间的内容。
//
// 单独抽出来断言，是为了让检查落在「实际会写进单元文件的那几行」上 ——
// 而不是整份脚本。install.sh 的注释里提 $CONFIG_DIR 的地方太多了，
// 不抽出来就分不清「配置目录真在放行列表里」还是「只是注释里说了一句」。
func extractHeredoc(t *testing.T, file, tag string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("读不到 %s: %v", file, err)
	}
	lines := strings.Split(string(b), "\n")

	start := -1
	for i, line := range lines {
		if m := heredocRE.FindStringSubmatch(line); m != nil && m[1] == tag {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s 里找不到 heredoc <<%s", file, tag)
	}
	for i := start; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == tag {
			return strings.Join(lines[start:i], "\n")
		}
	}
	t.Fatalf("%s 里的 heredoc <<%s 没有结束标记", file, tag)
	return ""
}

// systemd 那条路：单元文件必须放行配置目录。
func TestInstallUnitAllowsConfigDirWrite(t *testing.T) {
	body := extractHeredoc(t, "install.sh", "EOF")

	var rw string
	for _, line := range stripComments(strings.Split(body, "\n")) {
		if strings.HasPrefix(line, "ReadWritePaths=") {
			rw = line
		}
	}
	if rw == "" {
		t.Fatal("systemd 单元里没有 ReadWritePaths —— ProtectSystem=strict 下整个文件系统只读，" +
			"管理接口改不了配置")
	}
	for _, want := range []string{"$STATE_DIR", "$CONFIG_DIR"} {
		if !strings.Contains(rw, want) {
			t.Errorf("ReadWritePaths 里缺 %s：%q\n"+
				"  漏掉 $CONFIG_DIR 的后果就是「删除路由」报 attempt to write a readonly database"+
				"（SQLite 要在库文件旁边建 -wal / -shm，放行的必须是整个目录）", want, rw)
		}
	}
}

// 光放行挂载还不够：systemd 不改 Unix 权限，服务账号仍需要目录写权限。
func TestInstallChownsConfigDirToServiceUser(t *testing.T) {
	for _, line := range effectiveLines(t, "install.sh") {
		if strings.Contains(line, "chown") &&
			strings.Contains(line, "$CONFIG_DIR") &&
			strings.Contains(line, "goproxy") {
			return
		}
	}
	t.Error("install.sh 没有把 $CONFIG_DIR 的属主交给 goproxy。\n" +
		"  ReadWritePaths 只解除只读挂载，不改权限：目录还是 root:root 0755 的话，\n" +
		"  以 goproxy 身份跑的服务写不进配置库，报 permission denied")
}

// 数据库那几个文件也要过属主。
//
// 目录可写不等于文件可写：goproxy.db 如果是 root:root 0644（比如安装脚本以
// root 身份导入时生成的），服务正在写入时要建 goproxy.db-wal，
// 报出来的错还看不出跟权限有关。
func TestInstallChownsConfigDBFiles(t *testing.T) {
	lines := effectiveLines(t, "install.sh")

	// 1) 得有一个把库文件列进去的循环
	var loop string
	for _, line := range lines {
		if strings.HasPrefix(line, "for ") && strings.Contains(line, "goproxy.db") {
			loop = line
			break
		}
	}
	if loop == "" {
		t.Fatal("install.sh 没有对配置数据库文件过属主。\n" +
			"  目录属主改了、目录里那个 root:root 0644 的库文件没改的话，\n" +
			"  服务读得到、写不进去")
	}
	// -wal / -shm 必须一起：它们正是「写入时现建」的那两个文件，
	// 漏掉的话库文件本身可写也没用 —— 建兄弟文件照样 permission denied。
	for _, want := range []string{"goproxy.db-wal", "goproxy.db-shm"} {
		if !strings.Contains(loop, want) {
			t.Errorf("%s 没有一起过属主。SQLite 写入时要现建它，漏了照样写不进去：%q", want, loop)
		}
	}

	// 2) 循环体里要真的 chown，不能只是把文件名列出来
	for _, line := range lines {
		if strings.Contains(line, "chown") && strings.Contains(line, `"$CONFIG_DIR/$f"`) {
			return
		}
	}
	t.Error(`那个 for 循环里没有 chown "$CONFIG_DIR/$f" —— 列了文件名却没改属主`)
}

// Docker 那条路之一：镜像里配置目录得归非 root 用户。
func TestDockerfileMakesConfigDirWritable(t *testing.T) {
	for _, line := range effectiveLines(t, "Dockerfile") {
		if strings.Contains(line, "chown") && strings.Contains(line, "/etc/goproxy") {
			return
		}
	}
	t.Error("Dockerfile 没把 /etc/goproxy 的属主交给 goproxy。\n" +
		"  容器以 uid 10001 跑，镜像里的目录是 root:root 0755，改配置会 permission denied")
}

// Docker 那条路之二：必须挂目录，不能挂单个文件。
func TestComposeMountsConfigDirNotFile(t *testing.T) {
	sawConfigDir := false
	for _, line := range effectiveLines(t, "docker-compose.yml") {
		// 只看 volumes 里的条目："- <src>:<dst>[:mode]"
		if !strings.HasPrefix(line, "- ") || !strings.Contains(line, "/etc/goproxy") {
			continue
		}
		spec := strings.TrimPrefix(line, "- ")
		parts := strings.Split(spec, ":")
		if len(parts) < 2 {
			continue
		}
		src, dst := parts[0], parts[1]

		if strings.HasSuffix(src, ".json") {
			t.Errorf("docker-compose.yml 把单个文件挂到了 %s：%q\n"+
				"  SQLite 要在库文件旁边建 -wal / -shm，单文件挂载会让那些兄弟文件落在\n"+
				"  容器临时层里（容器一重建就丢，库可能不完整）；旧版配置写回还会撞上\n"+
				"  rename 挂载点的 EBUSY —— 改成 :rw 也没用。要挂目录。", dst, line)
		}
		if dst == "/etc/goproxy" {
			sawConfigDir = true
		}
	}
	if !sawConfigDir {
		t.Error("docker-compose.yml 没有把配置目录挂到 /etc/goproxy —— " +
			"管理接口要往配置库里写字，而数据库还需要在它旁边建 -wal / -shm")
	}
}

// 容器的 ENTRYPOINT 必须指向配置数据库，而不是那份示例 config.json。
//
// 指错也不会当场报错 —— 会在容器里安静地建一个同名的**新库**，
// 而外面挂进来的配置全都没人读，现象是「改了配置重启，一点没变」。
// 真实意图是让 config.json 只当第一次启动的种子（见 Dockerfile 的说明）。
func TestDockerEntrypointPointsAtConfigDB(t *testing.T) {
	var entry string
	for _, line := range effectiveLines(t, "Dockerfile") {
		if strings.HasPrefix(line, "ENTRYPOINT") {
			entry = line
		}
	}
	if entry == "" {
		t.Fatal("Dockerfile 里没有 ENTRYPOINT")
	}
	if !strings.Contains(entry, "/etc/goproxy/goproxy.db") {
		t.Errorf("ENTRYPOINT 应当指向配置数据库：%q\n"+
			"  指向 config.json 的话，容器里会另建一个新库，挂进来的配置没人读", entry)
	}
	// 而 config.json 仍然要留在镜像里：库为空时启动会自动把它导入一次，
	// 这正是不需要在构建期预先编译出一个二进制数据库的原因。
	var seeds bool
	for _, line := range effectiveLines(t, "Dockerfile") {
		if strings.HasPrefix(line, "COPY") && strings.Contains(line, "config.example.json") &&
			strings.Contains(line, "/etc/goproxy/config.json") {
			seeds = true
		}
	}
	if !seeds {
		t.Error("Dockerfile 没有把 config.example.json 放进 /etc/goproxy/config.json —— " +
			"那样首次启动的库里什么都没有，控制台连一条路由都看不到")
	}
}

// renderUnit 把 heredoc 里的变量换成实际的安装值，得到最终会写进
// /etc/systemd/system/goproxy.service 的内容。
func renderUnit(t *testing.T) string {
	t.Helper()
	s := extractHeredoc(t, "install.sh", "EOF")
	for _, kv := range [][2]string{
		{"$BIN_DIR", "/usr/local/bin"},
		{"$CONFIG_DIR", "/etc/goproxy"},
		{"$CONFIG_DB", "/etc/goproxy/goproxy.db"},
		// $SERVICE_CONFIG 是 install.sh 按「装出来的二进制支不支持 SQLite
		// 配置源」算出来的：支持就是库文件，不支持（v0.8.x 及更早）就是
		// config.json。这里按新版渲染，也就是库文件的路径。
		{"$SERVICE_CONFIG", "/etc/goproxy/goproxy.db"},
		{"$STATE_DIR", "/var/lib/goproxy"},
	} {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	return s
}

// 单元文件的语法错误在 install.sh 里完全看不出来，但一旦写坏，systemd 会拒绝
// 加载整个单元 —— 服务直接起不来，而且报错信息在 deploy 那一刻才出现。
// 这里把渲染后的内容按 systemd 的语法结构过一遍，顺便挡住 heredoc 被改坏。
func TestInstallRendersWellFormedUnit(t *testing.T) {
	unit := renderUnit(t)
	lines := stripComments(strings.Split(unit, "\n"))
	if len(lines) == 0 {
		t.Fatal("渲染出来的单元是空的")
	}

	// 语法：只允许段头（[Unit]）和 key=value 两种行
	sectionRE := regexp.MustCompile(`^\[[A-Za-z]+\]$`)
	kvRE := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*=.*$`)
	for _, line := range lines {
		if sectionRE.MatchString(line) || kvRE.MatchString(line) {
			continue
		}
		t.Errorf("不是合法的 systemd 指令行：%q\n"+
			"  heredoc 结构被改坏的话，systemd 会拒绝加载整个单元", line)
	}

	for _, section := range []string{"[Unit]", "[Service]", "[Install]"} {
		if !strings.Contains(unit, section) {
			t.Errorf("渲染出来的单元缺 %s 段", section)
		}
	}

	// 变量没被替换掉 = install.sh 在 set -u 下会当场中止
	var leftover []string
	for _, line := range lines {
		if strings.Contains(line, "$") {
			leftover = append(leftover, line)
		}
	}
	if len(leftover) > 0 {
		t.Errorf("渲染后仍残留 $：用到了没定义的变量，install.sh 是 set -u，会直接中止：\n  %s",
			strings.Join(leftover, "\n  "))
	}

	var execStart string
	for _, line := range lines {
		if strings.HasPrefix(line, "ExecStart=") {
			execStart = line
		}
	}
	if want := "ExecStart=/usr/local/bin/goproxy -c /etc/goproxy/goproxy.db"; execStart != want {
		t.Errorf("ExecStart 不对：\n  实际 %q\n  期望 %q\n"+
			"  指向 config.json 的话，服务起来看到的是一个空库（或另建的新库），"+
			"而配置文件里那些路由一条都不会生效", execStart, want)
	}
	if !strings.Contains(unit, "User=goproxy") {
		t.Error("单元里没有 User=goproxy —— 服务会以 root 跑，降权就白做了")
	}
}

// 装「旧版二进制」这条路必须留着，而且不能只靠注释标榜。
//
// 脚本是给最新版写的，但 VERSION= 允许装任意历史版本（固定版本也是脚本推荐的
// 用法，因为 latest 解析依赖网络），而且 Release 刚发出来之前 latest 还停在
// 上一个 tag 上。v0.8.x 及更早的二进制没有 -config-import，`-c` 指的也是 JSON
// 文件 —— 硬按库流程走，对它们调 -config-import 会直接报
// 「flag provided but not defined」：现象是「装不上」，原因却是版本不匹配。
//
// 所以脚本要按**装出来的那个二进制的能力**分流。这条测试在 install-smoke 之前
// 先兜一道：那边要靠真 Linux 才能跑到，本地跑不了；而这里的三个不变量坏掉的话，
// 那边一定失败，且报错很难指向真正的原因。
func TestInstallFallsBackForLegacyBinaries(t *testing.T) {
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("读不到 install.sh: %v", err)
	}
	text := string(raw)
	lines := effectiveLines(t, "install.sh")

	// 1. 靠 -h 的自述探测，而不是在脚本里自己比版本号 ——
	//    比版本号要在 shell 里重新实现一遍「v0.9.0 > v0.8.0」的语义比较，
	//    而 flags 是二进制自己说的，永远是对的。
	if !strings.Contains(text, `"$BIN_DIR/goproxy" -h`) {
		t.Error("install.sh 没有用 -h 探测二进制支持哪些开关")
	}
	var onUsageProbe bool
	for _, line := range lines {
		if strings.HasPrefix(line, "case ") && strings.Contains(line, "USAGE_PROBE") {
			onUsageProbe = true
		}
	}
	if !onUsageProbe {
		t.Error("探测结果没有落到生效分支上（没找到对 USAGE_PROBE 的 case）—— 只探测不判断等于没探测")
	}
	if !strings.Contains(text, "*-config-import*") {
		t.Error("没有按 -config-import 判断支持与否：这是 SQLite 配置源的唯一开关，用它当判据最直接")
	}

	// 2. 单元文件必须经 $SERVICE_CONFIG 间接取配置路径。
	//    写死 $CONFIG_DB 的话，装旧版时 ExecStart 会指向一个永远不存在的库 → 服务起不来。
	unit := extractHeredoc(t, "install.sh", "EOF")
	if !strings.Contains(unit, "-c $SERVICE_CONFIG") {
		t.Errorf("单元文件的 ExecStart 没走 $SERVICE_CONFIG：\n%s\n"+
			"  写死 $CONFIG_DB 的话，装 v0.8.x 及更早的二进制时服务会起不来", unit)
	}

	// 3. 两条路各有自己的收尾提示，不能互相冒充：
	//    装旧版说「配置库」等于告诉人去看一个不存在的文件。
	var mentionDB, mentionFile, legacyKeep bool
	for _, line := range lines {
		if strings.Contains(line, `"  配置库    $CONFIG_DB"`) {
			mentionDB = true
		}
		if strings.Contains(line, `"  配置文件  $CONFIG_FILE"`) {
			mentionFile = true
		}
		if strings.Contains(line, `$CONFIG_FILE 已存在，保持不动`) {
			legacyKeep = true
		}
	}
	if !mentionDB || !mentionFile {
		t.Errorf("收尾提示没有按配置源分流（提到配置库=%v，提到配置文件=%v）", mentionDB, mentionFile)
	}
	if !legacyKeep {
		t.Error("旧版分支没有「$CONFIG_FILE 已存在就保持不动」——" +
			"少了它，一次重跑安装就会把用户的配置文件按示例覆盖掉")
	}
}

// install.sh 必须真的把种子配置**导入**数据库，而不是只把它摆在那儿。
//
// 只摆着不动的话，服务起来会看到空库 —— 只要同目录里那份文件还在，启动时的
// 自动导入其实也会兜住，但那一步只在「库为空」时执行一次，而安装脚本需要的是
// 现场就能看到导入结果、失败能停在安装阶段。所以这里要求走显式的
// -config-import，而不是指望运行时兜底。
func TestInstallImportsSeedConfigIntoDB(t *testing.T) {
	for _, line := range effectiveLines(t, "install.sh") {
		if strings.Contains(line, "-config-import") && strings.Contains(line, "$CONFIG_DB") {
			return
		}
	}
	t.Error("install.sh 没有用 -config-import 把种子配置导入 $CONFIG_DB。\n" +
		"  少了这一步，安装完启动服务会看到空库，装完就有路由可用的预期落空")
}

// 重跑安装脚本不能拿那份已经过时的 config.json 覆盖库里的真实配置。
//
// config.json 只在第一次导入时被读过，之后控制台里的所有修改都只落在库里。
// 少了这道判断，升级一次就把用户改过的路由全部回退成安装时那份示例配置 ——
// 而且现场看不出任何异常（库是新导入的，导入还成功了）。
func TestInstallDoesNotReimportOverExistingDB(t *testing.T) {
	lines := effectiveLines(t, "install.sh")

	guard := -1
	importAt := -1
	for i, line := range lines {
		if guard < 0 && strings.Contains(line, `-e "$CONFIG_DB"`) && strings.HasPrefix(line, "if ") {
			guard = i
		}
		if importAt < 0 && strings.Contains(line, "-config-import") && strings.Contains(line, "$CONFIG_DB") {
			importAt = i
		}
	}
	if guard < 0 {
		t.Fatal("install.sh 里没有 `if [ -e \"$CONFIG_DB\" ]` 这道判断 —— " +
			"重跑安装会无条件导入，把库里的配置覆盖掉")
	}
	if importAt < 0 {
		t.Fatal("install.sh 里没有找到 -config-import（见上一条用例）")
	}
	if importAt < guard {
		t.Error("导入发生在「库已存在」判断之前 —— 判断形同虚设，重跑安装仍会覆盖")
	}
}
