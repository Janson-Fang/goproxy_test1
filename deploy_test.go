package main

// 部署文件之间的不变量。
//
// install.sh / Dockerfile / docker-compose.yml 分处三个地方，改了一处忘了另一处
// 是很典型的失误，而后果要到线上真正操作时才暴露 —— 最典型的就是「删除路由」
// 直接报错：
//
//	open /etc/goproxy/config.json.tmp: read-only file system
//
// 根因是管理接口改配置走的是原子写（写 config.json.tmp 再 rename 覆盖），
// 而三个部署路径各自都可能把配置目录变成不可写：
//
//	· systemd  ProtectSystem=strict 把 /etc 挂成只读，ReadWritePaths 没放行配置目录
//	· systemd  放行了，但目录还是 root:root 0755 —— ReadWritePaths 只改挂载属性，
//	           不改 Unix 权限，以 goproxy 身份跑的服务照样建不出 .tmp
//	· Docker   容器以 uid 10001 跑，镜像里的 /etc/goproxy 是 root:root
//	· Docker   把配置挂成了**单个文件** —— 那个文件成了挂载点，而原子写的最后
//	           一步是 rename 覆盖它，内核在 vfs_rename 里禁止 rename 到挂载点，
//	           直接返回 EBUSY。注意这种情况下改成 :rw 也没用，只是换个错误信息。
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
				"  漏掉 $CONFIG_DIR 的后果就是「删除路由」报 config.json.tmp: read-only file system", want, rw)
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
		"  以 goproxy 身份跑的服务建不出 config.json.tmp，报 permission denied")
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
				"  那个文件会成为容器里的挂载点，而原子写的最后一步是 rename 覆盖它，\n"+
				"  内核在 vfs_rename 里禁止 rename 到挂载点（EBUSY）—— 改成 :rw 也没用，\n"+
				"  只会把 read-only file system 换成 device or resource busy。要挂目录。", dst, line)
		}
		if dst == "/etc/goproxy" {
			sawConfigDir = true
		}
	}
	if !sawConfigDir {
		t.Error("docker-compose.yml 没有把配置目录挂到 /etc/goproxy —— " +
			"管理接口需要在整个目录里原子写配置（.tmp + rename）")
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
	if want := "ExecStart=/usr/local/bin/goproxy -c /etc/goproxy/config.json"; execStart != want {
		t.Errorf("ExecStart 不对：\n  实际 %q\n  期望 %q", execStart, want)
	}
	if !strings.Contains(unit, "User=goproxy") {
		t.Error("单元里没有 User=goproxy —— 服务会以 root 跑，降权就白做了")
	}
}
