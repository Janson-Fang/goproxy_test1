package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// config.example.json 必须始终可加载。
//
// 它是用户照着抄的模板，也是 CI 打包进 tar 和镜像的文件。如果它自己都过不了
// validate（比如加了新字段却漏了必填项），那所有人第一次部署都会失败 ——
// 而且要等到读了 README、配好环境、跑起来才发现。
//
// 这个测试同时充当「新增配置字段时别忘了更新示例」的提醒。
func TestConfigExampleLoads(t *testing.T) {
	raw, cfg, err := parseConfigFile("config.example.json")
	if err != nil {
		t.Fatalf("config.example.json 解析失败: %v", err)
	}
	cfg.applyTopDefaults()
	cfg.applyRouteDefaults()

	// manual 路由引用的证书文件在仓库里不存在（也不该存在 —— 私钥不能进版本库），
	// 所以这里先把这些引用清空再校验其余部分，只验结构与字段合法性。
	for i := range cfg.Routes {
		if cfg.Routes[i].routeTLSMode() == TLSModeManual {
			cfg.Routes[i].TLSMode = TLSModeOff
			cfg.Routes[i].CertFile = ""
			cfg.Routes[i].KeyFile = ""
		}
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("config.example.json 未通过校验: %v", err)
	}

	if len(raw) == 0 {
		t.Fatal("config.example.json 是空文件")
	}
	if len(cfg.Routes) == 0 {
		t.Fatal("config.example.json 里没有任何路由")
	}
	if !cfg.TLS.Enabled {
		t.Error("config.example.json 应当示范 TLS 配置（tls.enabled=true）")
	}
}

// 示例里手动证书引用的路径必须是「相对 cert_dir 的相对路径」，
// 不能是绝对路径 —— 绝对路径绑死在某一台机器上，别人抄过去必然报错。
func TestConfigExampleUsesRelativeCertPaths(t *testing.T) {
	_, cfg, err := parseConfigFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyTopDefaults()
	cfg.applyRouteDefaults()

	found := 0
	for _, r := range cfg.Routes {
		if r.CertFile != "" {
			found++
			if filepath.IsAbs(r.CertFile) {
				t.Errorf("路由 %s 的 cert_file 不该用绝对路径: %s", r.ID, r.CertFile)
			}
		}
		if r.KeyFile != "" && filepath.IsAbs(r.KeyFile) {
			t.Errorf("路由 %s 的 key_file 不该用绝对路径: %s", r.ID, r.KeyFile)
		}
	}
	if found == 0 {
		t.Error("示例应当至少有一条 manual 路由，让用户知道怎么挂本地证书")
	}
}

// Dockerfile / docker-compose 必须真的暴露 HTTPS 端口。
//
// 这两个文件分处不同位置，改了一处忘了另一处是很典型的失误，
// 而后果是「容器起来了但端口没映射」这种要排查很久的问题。
//
// 注意这里**只认生效的指令行，注释不算**：
// compose 里那段 `# - "443:443"`（bridge 网络的示例）就是个陷阱 ——
// 用 strings.Contains(s, "443") 会把它当成已暴露，测试恒过、等于没测。
// 这个疏漏真出现过一次，所以下面的断言必须逐行过滤注释。
func TestDeploymentFilesMentionTLSPorts(t *testing.T) {
	// Dockerfile 的 EXPOSE 是纯声明，任何时候都该带上 443。
	assertDirectiveContains(t, "Dockerfile", "EXPOSE", "443")

	// compose 分两种情况，判据完全不同：
	//   · host 网络（本仓库的默认）→ 不在 compose 里表达端口，无从要求 443；
	//   · bridge 网络 → 必须有生效的 ports 映射，且其中要含 443。
	// 也就是说这里要断言的是「**若**有端口映射，则它必须包含 443」，
	// 而不是「文件里某处出现过 443」。
	lines := activeLines(t, "docker-compose.yml")

	hostNet := false
	hasPorts, hasTLS := false, false
	inPorts := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "network_mode:"):
			hostNet = strings.Contains(l, "host")
		case strings.HasPrefix(l, "ports:"):
			inPorts, hasPorts = true, true
		case inPorts && strings.HasPrefix(l, "-"):
			if strings.Contains(l, "443") {
				hasTLS = true
			}
		}
	}

	if hostNet {
		if hasPorts {
			t.Error("docker-compose.yml 用了 host 网络就不该再有 ports 映射（二者语义冲突）")
		}
		return
	}
	if !hasPorts {
		t.Error("docker-compose.yml 既不是 host 网络、也没有 ports 映射 —— 容器将无法从外部访问")
		return
	}
	if !hasTLS {
		t.Error("docker-compose.yml 的 ports 映射里没有 443 —— TLS 需要真正暴露 HTTPS 端口")
	}
}

// activeLines 返回去掉注释与空行后的内容行（已 TrimSpace）。
func activeLines(t *testing.T, file string) []string {
	t.Helper()

	b, err := os.ReadFile(file)
	if err != nil {
		// 用 Errorf 而不是 Skipf：守卫测试在自己的对象不存在时必须报错。
		// 用 Skip 的话，文件被改名或误删都只是「跳过」，闸门形同虚设。
		t.Errorf("读不到 %s: %v —— 部署文件是本测试的守卫对象，不能缺失", file, err)
		return nil
	}

	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // 注释与空行不计
		}
		out = append(out, trimmed)
	}
	return out
}

// assertDirectiveContains 在文件中寻找「生效的、同时含 marker 与 want 的行」。
func assertDirectiveContains(t *testing.T, file, marker, want string) {
	t.Helper()

	for _, l := range activeLines(t, file) {
		if strings.Contains(l, marker) && strings.Contains(l, want) {
			return // 找到生效的指令，通过
		}
	}
	t.Errorf("%s 里没有「生效的」同时含 %s 与 %s 的指令行（注释不算）", file, marker, want)
}
