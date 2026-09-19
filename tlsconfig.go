package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// TLS 模式取值。
const (
	// TLSModeOff 明文 HTTP。这是默认值 —— 不写 tls 配置的部署行为与
	// 引入 TLS 之前完全一致，升级不会改变任何现有部署的表现。
	TLSModeOff = "off"
	// TLSModeAuto 交给 ACME 自动签发与续期。
	TLSModeAuto = "auto"
	// TLSModeManual 从本地文件加载证书，变更后热重载。
	TLSModeManual = "manual"
)

// defaultHTTPPort / defaultHTTPSPort 是 ACME 挑战与明文重定向的落点。
//
// 这两个端口是**硬约束**，不是偏好：ACME 的 HTTP-01 挑战固定从 80 端口发起，
// TLS-ALPN-01 固定从 443 发起。所以监听在别的端口上的路由拿不到自动证书 ——
// 这一点在 validate 里会明确报错，而不是留到运行时才发现握手失败。
const (
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

// TLSConfig 是顶层 TLS 配置段。
//
// Enabled 是总闸：为 false（默认）时整个 TLS 子系统不启动，
// 所有路由按明文 HTTP 跑，与历史行为一致。
// 打开之后，路由默认走 auto，可以逐条覆盖成 manual 或 off。
type TLSConfig struct {
	// Enabled 是全局开关。不写即 false。
	Enabled bool `json:"enabled"`

	// ACME 自动签发相关配置。仅在 Enabled=true 时生效。
	ACME *ACMEConfig `json:"acme,omitempty"`

	// CertDir 手动证书的默认目录。路由只写 cert_file/key_file（相对路径）
	// 时，相对这个目录解析，省得每条路由都写一长串绝对路径。
	CertDir string `json:"cert_dir,omitempty"`

	// HTTPPort 明文端口，承担 ACME HTTP-01 挑战与 HTTP→HTTPS 重定向，默认 80。
	HTTPPort int `json:"http_port,omitempty"`

	// HTTPSPort 默认的 TLS 端口，默认 443。
	HTTPSPort int `json:"https_port,omitempty"`
}

// ACMEConfig 是 ACME（Let's Encrypt 或兼容 CA）的配置。
type ACMEConfig struct {
	// Email 注册邮箱。CA 用它发到期提醒，建议填真实的。
	Email string `json:"email,omitempty"`

	// DirectoryURL ACME 目录地址。留空走 Let's Encrypt 生产环境；
	// 换 ZeroSSL、内部 CA、或测试用的 Pebble 时改这里。
	DirectoryURL string `json:"directory_url,omitempty"`

	// Staging 为 true 时改用 Let's Encrypt 测试环境。
	//
	// 调试验证阶段务必打开：生产环境的签发配额很紧（每注册域名每周 50 张），
	// 反复重试很容易把配额烧掉，之后整整一周都签不出来。
	Staging bool `json:"staging,omitempty"`

	// CacheDir 证书缓存目录。**必须持久化** —— 每次重启都重新申请
	// 会很快撞上 CA 的频率限制。默认 "./data/certs"。
	CacheDir string `json:"cache_dir,omitempty"`

	// Hosts 允许申请证书的域名白名单。留空表示不限制（按路由的 host 申请）。
	//
	// 生产环境建议显式列出：SNI 是客户端可控的，不加限制的话
	// 任何人扫一遍 SNI 就能让本机替一堆不相干的域名去申请证书。
	Hosts []string `json:"hosts,omitempty"`
}

// letsEncrypt 的目录地址。
const (
	leProduction = "https://acme-v02.api.letsencrypt.org/directory"
	leStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// defaultACMEDir 是证书缓存的默认目录。
const defaultACMEDir = "data/certs"

// effectiveDirectoryURL 决定最终使用的 ACME 目录地址，优先级：
// Staging 开关 > 显式 DirectoryURL > Let's Encrypt 生产环境。
//
// 刻意让 Staging 压过 DirectoryURL：调试时手一抖开了 staging 却又留着
// 生产 URL 的话，按直觉应该是「安全的那个赢」。
func (a *ACMEConfig) effectiveDirectoryURL() string {
	if a == nil {
		return leProduction
	}
	if a.Staging {
		return leStaging
	}
	if u := strings.TrimSpace(a.DirectoryURL); u != "" {
		return u
	}
	return leProduction
}

func (a *ACMEConfig) cacheDir() string {
	if a == nil || strings.TrimSpace(a.CacheDir) == "" {
		return defaultACMEDir
	}
	return a.CacheDir
}

// applyTopDefaults 给 TLS 段补默认值。和其它顶层字段一样，**不回写文件**。
func (c *Config) applyTLSDefaults() {
	t := &c.TLS
	if t.HTTPPort == 0 {
		t.HTTPPort = defaultHTTPPort
	}
	if t.HTTPSPort == 0 {
		t.HTTPSPort = defaultHTTPSPort
	}
	if t.ACME == nil {
		t.ACME = &ACMEConfig{}
	}
	if strings.TrimSpace(t.ACME.CacheDir) == "" {
		t.ACME.CacheDir = defaultACMEDir
	}
}

// applyRouteTLSDefaults 给路由补 TLS 默认值。
//
// 这里有个刻意的设计：**只有全局开关打开时**，路由的默认模式才是 auto。
// 开关关着的时候默认 off，这样「升级到带 TLS 的版本」不会让任何现有
// 部署突然开始向 CA 申请证书。
func (c *Config) applyRouteTLSDefaults() {
	for i := range c.Routes {
		r := &c.Routes[i]
		if strings.TrimSpace(r.TLSMode) == "" {
			if c.TLS.Enabled {
				r.TLSMode = TLSModeAuto
			} else {
				r.TLSMode = TLSModeOff
			}
		}
		// RedirectHTTP 为 nil 时默认 true：开了 HTTPS 就应该把明文收掉。
		// 用指针是为了区分「没写」和「显式写了 false」。
		if r.RedirectHTTP == nil {
			on := true
			r.RedirectHTTP = &on
		}
	}
}

// redirectHTTP 报告该路由是否应该做 HTTP→HTTPS 跳转。
func (r RouteConfig) redirectHTTP() bool {
	return r.RedirectHTTP == nil || *r.RedirectHTTP
}

// routeTLSMode 返回规范化后的路由 TLS 模式。
func (r RouteConfig) routeTLSMode() string {
	return strings.ToLower(strings.TrimSpace(r.TLSMode))
}

// validateTLS 校验 TLS 相关配置。任何「运行时才发现」的错误都要在这里拦下。
func (c *Config) validateTLS() error {
	t := &c.TLS

	if !t.Enabled {
		// 总闸关着，但路由上写了 auto/manual —— 这几乎肯定是配置写错了
		// （用户以为已经开了 HTTPS，实际跑的是明文）。宁可报错也不要静默忽略：
		// 「以为有 HTTPS 其实没有」比「启动失败」危险得多。
		for i, r := range c.Routes {
			if m := r.routeTLSMode(); m == TLSModeAuto || m == TLSModeManual {
				return fmt.Errorf(
					"routes[%d] (%s): 配置了 tls_mode=%q 但顶层 tls.enabled 未开启；"+
						"请设 tls.enabled=true，或把这些路由改回 tls_mode=off", i, r.ID, m)
			}
		}
		return nil
	}

	if t.HTTPPort < 0 || t.HTTPPort > 65535 {
		return fmt.Errorf("tls.http_port 非法: %d", t.HTTPPort)
	}
	if t.HTTPSPort < 0 || t.HTTPSPort > 65535 {
		return fmt.Errorf("tls.https_port 非法: %d", t.HTTPSPort)
	}
	if t.HTTPPort != 0 && t.HTTPPort == t.HTTPSPort {
		return fmt.Errorf("tls.http_port 与 tls.https_port 不能相同（都是 %d）", t.HTTPPort)
	}

	if a := t.ACME; a != nil {
		if email := strings.TrimSpace(a.Email); email != "" && !strings.Contains(email, "@") {
			return fmt.Errorf("tls.acme.email 不像邮箱地址: %q", email)
		}
		if u := strings.TrimSpace(a.DirectoryURL); u != "" &&
			!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("tls.acme.directory_url 必须是 http(s) 地址，当前 %q", u)
		}
		for _, h := range a.Hosts {
			if strings.TrimSpace(h) == "" {
				return fmt.Errorf("tls.acme.hosts 里有空项")
			}
		}
	}

	// 逐条路由校验
	for i, r := range c.Routes {
		if !r.enabled() {
			continue
		}
		switch m := r.routeTLSMode(); m {
		case TLSModeOff:
			// 明文，无约束
		case TLSModeManual:
			if err := c.validateManualCert(i, r); err != nil {
				return err
			}
		case TLSModeAuto:
			if err := c.validateAutoCert(i, r); err != nil {
				return err
			}
		default:
			return fmt.Errorf("routes[%d] (%s): tls_mode 必须是 off|auto|manual，当前 %q", i, r.ID, r.TLSMode)
		}
	}

	return nil
}

// validateManualCert 检查手动证书文件是否可读、能否解析成合法密钥对。
//
// 这里真的去读文件并解析，而不是只判断「有没有填路径」：
// 证书配错（路径写错、链不全、key 不匹配）是最常见的 TLS 事故，
// 让它在写配置那一刻就报错，比等到第一个 HTTPS 请求打进来再炸好得多。
func (c *Config) validateManualCert(i int, r RouteConfig) error {
	certPath := c.certPath(r)
	keyPath := c.keyPath(r)
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("routes[%d] (%s): tls_mode=manual 必须同时配置 cert_file 与 key_file", i, r.ID)
	}
	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("routes[%d] (%s): 证书文件不可读 %s: %w", i, r.ID, certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("routes[%d] (%s): 私钥文件不可读 %s: %w", i, r.ID, keyPath, err)
	}
	// 交给 crypto/tls 做真实解析，能同时验出「文件损坏」「key 与证书不匹配」
	if _, err := loadKeyPairCert(certPath, keyPath); err != nil {
		return fmt.Errorf("routes[%d] (%s): 加载证书失败: %w", i, r.ID, err)
	}
	return nil
}

// validateAutoCert 检查能否为这条路由自动签发证书。
//
// 两道硬约束：
//
//  1. ACME 拿不到裸 IP 的证书。Let's Encrypt 明确不对 IP 地址签发，
//     所以 host 为空或写成 IP 的路由开 auto 必然失败。
//  2. HTTP-01 固定走 80，TLS-ALPN-01 固定走 443。路由监听在别的端口上时，
//     挑战回不来，签发必然超时。
func (c *Config) validateAutoCert(i int, r RouteConfig) error {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return fmt.Errorf(
			"routes[%d] (%s): tls_mode=auto 但 host 为空 —— ACME 无法为裸 IP 或任意域名签发证书；"+
				"请填具体域名，或改用 tls_mode=manual 挂一张自签证书", i, r.ID)
	}
	if net.ParseIP(strings.TrimPrefix(host, "*.")) != nil {
		return fmt.Errorf(
			"routes[%d] (%s): tls_mode=auto 但 host 是 IP 地址 (%s) —— "+
				"Let's Encrypt 不对裸 IP 签发证书，请改用域名或 tls_mode=manual", i, r.ID, host)
	}
	if strings.HasPrefix(host, "*.") {
		return fmt.Errorf(
			"routes[%d] (%s): tls_mode=auto 不支持通配域名 %s —— "+
				"通配证书需要 DNS-01 挑战，请改用 tls_mode=manual 挂通配证书", i, r.ID, host)
	}

	// 端口约束：listen_port=0 表示挂在所有端口上的路由，它至少会在
	// http_port/https_port 上被服务到，所以不拦；只有显式指定了
	// 非标准端口的才拦。
	if p := r.ListenPort; p != 0 && p != c.TLS.HTTPPort && p != c.TLS.HTTPSPort {
		return fmt.Errorf(
			"routes[%d] (%s): tls_mode=auto 但 listen_port=%d 既不是 %d 也不是 %d —— "+
				"ACME 的 HTTP-01 挑战固定走 %d、TLS-ALPN-01 固定走 %d，自定义端口上拿不到自动证书；"+
				"请改用 tls_mode=manual，或把 HTTPS 收敛到 %d",
			i, r.ID, p, c.TLS.HTTPPort, c.TLS.HTTPSPort, c.TLS.HTTPPort, c.TLS.HTTPSPort, c.TLS.HTTPSPort)
	}
	return nil
}

// certPath 解析证书文件路径：绝对路径原样用，相对路径相对 tls.cert_dir。
func (c *Config) certPath(r RouteConfig) string { return c.resolveCertPath(r.CertFile) }

func (c *Config) keyPath(r RouteConfig) string { return c.resolveCertPath(r.KeyFile) }

func (c *Config) resolveCertPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	dir := strings.TrimSpace(c.TLS.CertDir)
	if dir == "" {
		// 没配 cert_dir 时相对配置库所在目录解析 —— 进程的工作目录
		// 取决于怎么启动的（systemd / docker / 手动），拿它当基准太不稳。
		dir = c.baseDir
		if dir == "" {
			dir = "."
		}
	}
	return filepath.Join(dir, p)
}

// tlsPorts 返回需要跑 TLS 的端口集合。
//
// 规则是「端口级的」而不是「路由级的」：一个端口要么全明文要么全 TLS。
// 这样才能保证从某个端口进来的连接，加密与否只由端口决定，
// 不由客户端或某条路由的选择决定 —— 后者是 TLS 剥离的入口。
//
// 需要 TLS 的端口 = https_port（只要总闸开着就启）+ 所有承载了
// 非 off 模式路由的 listen_port。
func (c *Config) tlsPorts() map[int]bool {
	ports := make(map[int]bool)
	if !c.TLS.Enabled {
		return ports
	}
	// https_port 是 TLS 的默认落点，只要开关打开就让它支持 TLS：
	// 即使暂时没有 auto/manual 路由，先把 443 听着也更符合预期
	// （配置改到一半的中间态不会出现「443 上跑明文」这种惊悚结果）。
	if p := c.TLS.HTTPSPort; p > 0 {
		ports[p] = true
	}
	for _, r := range c.Routes {
		if !r.enabled() || r.ListenPort <= 0 {
			continue
		}
		if m := r.routeTLSMode(); m == TLSModeAuto || m == TLSModeManual {
			ports[r.ListenPort] = true
		}
	}
	return ports
}

// tlsConfigFor 为一个端口构造 tls.Config。
//
// 所有端口共用同一个 GetCertificate 回调（按 SNI 分发），
// 所以每条路由的证书各归各位，不需要按端口再分一套证书表。
func (c *Config) tlsConfigFor(m *tlsManager) *tls.Config {
	return &tls.Config{
		MinVersion:     minTLSVersion,
		GetCertificate: m.GetCertificate,
		// 显式注册 ALPN，顺序即优先级：先 HTTP/2 再 HTTP/1.1。
		// 这不只是性能问题 —— HTTP/2 是 TLS-ALPN-01 挑战的依据，
		// 如果客户端用 acme-tls/1 协议来询，得让 autocert 的
		// GetCertificate 接住（它在内部处理）。
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		// 用 ECDSA 优先的曲线，握手更快且前向安全性更好。
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}
