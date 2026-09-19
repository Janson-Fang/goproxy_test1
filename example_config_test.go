package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadExampleConfig 读并解析 config.example.json。
//
// 走 parseConfigJSON 而不是 loadConfig：示例文件是一份 JSON，不是配置数据库。
// 配置源换成 SQLite 之后，这两件事必须分清楚 —— 把 JSON 文件喂给
// loadConfig 会当成数据库去开，报的是「file is not a database」，
// 与「示例配错了」完全不是一回事。
func loadExampleConfig(t *testing.T) ([]byte, *Config) {
	t.Helper()
	raw, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatalf("读取 config.example.json 失败: %v", err)
	}
	cfg, err := parseConfigJSON(raw)
	if err != nil {
		t.Fatalf("config.example.json 解析失败: %v", err)
	}
	return raw, cfg
}

// config.example.json 必须始终可加载。
//
// 它是用户照着抄的模板，也是 CI 打包进 tar 和镜像的文件。如果它自己都过不了
// validate（比如加了新字段却漏了必填项），那所有人第一次部署都会失败 ——
// 而且要等到读了 README、配好环境、跑起来才发现。
//
// 这个测试同时充当「新增配置字段时别忘了更新示例」的提醒。
func TestConfigExampleLoads(t *testing.T) {
	raw, cfg := loadExampleConfig(t)
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
	_, cfg := loadExampleConfig(t)
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

// config.example.json 必须能走**真实的导入路径**进配置库。
//
// TestConfigExampleLoads 里「把 manual 证书引用清空再校验」那几行是在给示例开小灶：
// 它证明的是「示例结构合法」，不是「示例能被装进去」。而 v0.9.0 起 install.sh 与
// Docker 的首次安装都会把这份示例**原样导入**配置库，导入跑的是完整校验（fail-closed）
// —— 证书文件不存在（仓库里当然不该有私钥）就拒绝整份配置。结果是一键安装与
// 容器首启双双失败，而且只有 install-smoke 里 latest 那一格能暴露它：
// 其余矩阵项都固定在 v0.3.0，走的是不需要导入的旧分支。
//
// 所以这里按示例**实际被使用的方式**来测它。修这类问题的正确位置是示例自己
// （manual 演示路由保持 enabled=false），而不是放宽导入校验 —— 那道校验挡的是
// 真实的配置事故，松了它，用户的证书路径写错就要等到第一个请求才炸。
func TestConfigExampleImportsIntoDB(t *testing.T) {
	raw, _ := loadExampleConfig(t)
	db := tempConfigDB(t)
	seedRawConfig(t, db, raw) // 走 importJSON：默认值补齐 + 旧写法拦截 + 完整校验

	// 导入成功后读回来，确认示例的关键内容没有被导入过程丢掉
	_, cfg, err := parseConfigFile(db)
	if err != nil {
		t.Fatalf("从配置库读回失败: %v", err)
	}
	if len(cfg.Routes) == 0 {
		t.Fatal("示例导入后一条路由都没有")
	}
	if !cfg.TLS.Enabled {
		t.Error("导入后 tls.enabled 变成了 false —— 示例对 TLS 的示范被丢了")
	}
	for _, r := range cfg.Routes {
		if r.routeTLSMode() == TLSModeManual && r.enabled() {
			t.Errorf("路由 %s 是 manual 且 enabled：仓库里没有它引用的证书文件，"+
				"这样的示例会让一键安装/容器首启直接失败（应当先置 enabled=false）", r.ID)
		}
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
