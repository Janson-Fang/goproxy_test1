package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 测试工具 ----------

// writeSelfSigned 生成一张自签证书并落盘，返回证书与私钥路径。
//
// 用自签而不是真实 CA：测试要验的是「我们的加载、分发、热重载逻辑对不对」，
// 那不是证书链的信任问题。自签能让测试离线跑、不依赖网络、不产生 CA 配额消耗。
func writeSelfSigned(t *testing.T, dir, base string, hosts ...string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("写证书失败: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("写私钥失败: %v", err)
	}

	return certPath, keyPath
}

// writeConfig 把配置写到临时文件并加载（走真实的 parse + 默认值 + 校验流程）。
func writeConfig(t *testing.T, cfg *Config) (*Config, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("序列化配置失败: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	return loaded, path
}

// ---------- 配置默认值与校验 ----------

// 不开总闸时，路由的 TLS 模式必须是 off —— 这是「升级不改变现有部署行为」的保证。
func TestTLSDisabledKeepsRoutesPlaintext(t *testing.T) {
	cfg := &Config{
		Routes: []RouteConfig{
			{ID: "a", Target: "http://127.0.0.1:9000"},
			{ID: "b", Target: "http://127.0.0.1:9001", Host: "example.com"},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	if loaded.TLS.Enabled {
		t.Fatal("没写 tls 配置时 TLS 应当是关闭的")
	}
	for _, r := range loaded.Routes {
		if got := r.routeTLSMode(); got != TLSModeOff {
			t.Errorf("路由 %s: 期望默认 tls_mode=off，实际 %q", r.ID, got)
		}
	}
	if got := loaded.tlsPorts(); len(got) != 0 {
		t.Errorf("TLS 未启用时不应当有 TLS 端口，实际 %v", got)
	}
}

// 总闸打开后，路由默认走 auto（除非显式覆盖成 off/manual）。
func TestTLSEnabledDefaultsRoutesToAuto(t *testing.T) {
	cfg := &Config{
		TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{Email: "a@b.com"}},
		Routes: []RouteConfig{
			{ID: "auto", Target: "http://127.0.0.1:9000", Host: "example.com"},
			{ID: "off", Target: "http://127.0.0.1:9001", Host: "x.com", TLSMode: TLSModeOff},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	if got := loaded.Routes[0].routeTLSMode(); got != TLSModeAuto {
		t.Errorf("总闸打开时未指定的路由应默认 auto，实际 %q", got)
	}
	if got := loaded.Routes[1].routeTLSMode(); got != TLSModeOff {
		t.Errorf("显式 off 的路由不该被改成 auto，实际 %q", got)
	}

	ports := loaded.tlsPorts()
	if !ports[defaultHTTPSPort] {
		t.Errorf("总闸打开时 %d 应当是 TLS 端口，实际 %v", defaultHTTPSPort, ports)
	}
}

// 总闸关着却给路由写了 auto/manual 必须报错。
//
// 这是最容易出事的一种配置错误：用户以为开了 HTTPS，实际跑的是明文。
// 静默忽略会让他带着「已经加密了」的错误认知上线。
func TestTLSModeWithoutGlobalSwitchIsRejected(t *testing.T) {
	for _, mode := range []string{TLSModeAuto, TLSModeManual} {
		cfg := &Config{
			Routes: []RouteConfig{
				{ID: "r", Target: "http://127.0.0.1:9000", Host: "example.com", TLSMode: mode},
			},
		}
		_, err := writeConfigErr(cfg)
		if err == nil {
			t.Fatalf("tls_mode=%s 但总闸关闭时应当报错", mode)
		}
		if !strings.Contains(err.Error(), "tls.enabled") {
			t.Errorf("tls_mode=%s: 错误信息应当提示开启 tls.enabled，实际: %v", mode, err)
		}
	}
}

// writeConfigErr 是 writeConfig 的「期望失败」版本。
func writeConfigErr(cfg *Config) (*Config, error) {
	dir, err := os.MkdirTemp("", "goproxy-cfg")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "config.json")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return loadConfig(path)
}

// ACME 拿不到裸 IP 和通配域名的证书，这两种必须在写配置时就拦住。
func TestAutoCertRejectsIPAndWildcard(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		{"裸 IP", "203.0.113.10", "不对裸 IP 签发"},
		{"通配域名", "*.example.com", "通配证书需要 DNS-01"},
		{"空 host", "", "host 为空"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{}},
				Routes: []RouteConfig{
					{ID: "r", Target: "http://127.0.0.1:9000", Host: tc.host, TLSMode: TLSModeAuto},
				},
			}
			_, err := writeConfigErr(cfg)
			if err == nil {
				t.Fatalf("host=%q 开 auto 应当报错", tc.host)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息应当包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// 自定义端口上开 auto 必须报错：ACME 挑战固定走 80/443，回不来就签不出。
func TestAutoCertRejectsCustomPort(t *testing.T) {
	cfg := &Config{
		TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{}},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "example.com", ListenPort: 8081, TLSMode: TLSModeAuto},
		},
	}
	_, err := writeConfigErr(cfg)
	if err == nil {
		t.Fatal("自定义端口上开 auto 应当报错")
	}
	if !strings.Contains(err.Error(), "8081") {
		t.Errorf("错误信息应当指出冲突的端口，实际: %v", err)
	}

	// 80 / 443 上应当放行
	for _, p := range []int{80, 443} {
		ok := &Config{
			TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{}},
			Routes: []RouteConfig{
				{ID: "r", Target: "http://127.0.0.1:9000", Host: "example.com", ListenPort: p, TLSMode: TLSModeAuto},
			},
		}
		if _, err := writeConfigErr(ok); err != nil {
			t.Errorf("端口 %d 上开 auto 不该报错，实际: %v", p, err)
		}
	}
}

// manual 模式必须真的读得到证书，且证书与私钥要配对。
func TestManualCertValidatedOnLoad(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "a", "a.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	if _, err := writeConfigErr(cfg); err != nil {
		t.Fatalf("合法的 manual 配置不该报错: %v", err)
	}

	// 路径写错
	cfg2 := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: filepath.Join(dir, "nope.crt"), KeyFile: keyPath},
		},
	}
	if _, err := writeConfigErr(cfg2); err == nil {
		t.Error("证书文件不存在时应当报错")
	}

	// 证书与私钥不配对：拿另一张证书的路径去配这把私钥
	otherCert, _ := writeSelfSigned(t, dir, "b", "b.example.com")
	cfg3 := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: otherCert, KeyFile: keyPath},
		},
	}
	if _, err := writeConfigErr(cfg3); err == nil {
		t.Error("证书与私钥不配对时应当报错")
	}

	// 只填了证书没填私钥
	cfg4 := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: certPath},
		},
	}
	if _, err := writeConfigErr(cfg4); err == nil {
		t.Error("manual 模式缺少 key_file 时应当报错")
	}
}

// 相对路径要相对 tls.cert_dir 解析。
func TestManualCertRelativePath(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSelfSigned(t, certDir, "site", "site.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true, CertDir: certDir},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "site.example.com",
				TLSMode: TLSModeManual, CertFile: "site.crt", KeyFile: "site.key"},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	gotCert := loaded.certPath(loaded.Routes[0])
	if gotCert != filepath.Join(certDir, "site.crt") {
		t.Errorf("相对路径解析错误: 期望 %s，实际 %s", filepath.Join(certDir, "site.crt"), gotCert)
	}
}

// cert_dir 留空时，相对配置文件所在目录解析。
func TestManualCertRelativeToConfigDir(t *testing.T) {
	// 证书必须和配置文件放在同一个目录，才能验证「相对配置文件解析」
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeSelfSigned(t, dir, "rel", "rel.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "rel.example.com",
				TLSMode: TLSModeManual, CertFile: "rel.crt", KeyFile: "rel.key"},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	got := loaded.certPath(loaded.Routes[0])
	want := filepath.Join(dir, "rel.crt")
	if got != want {
		t.Errorf("应当相对配置文件目录解析: 期望 %s，实际 %s", want, got)
	}
}

// ---------- SNI 分发 ----------

// 按 SNI 选对证书 —— 这是多域名共用一个 TLS 端口的基础。
func TestGetCertificateDispatchesBySNI(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := writeSelfSigned(t, dir, "a", "a.example.com")
	certB, keyB := writeSelfSigned(t, dir, "b", "b.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "a", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: certA, KeyFile: keyA},
			{ID: "b", Target: "http://127.0.0.1:9001", Host: "b.example.com",
				TLSMode: TLSModeManual, CertFile: certB, KeyFile: keyB},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	for _, tc := range []struct{ sni, want string }{
		{"a.example.com", "a.example.com"},
		{"b.example.com", "b.example.com"},
		{"A.EXAMPLE.COM", "a.example.com"}, // SNI 大小写不敏感
	} {
		cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.sni})
		if err != nil {
			t.Errorf("SNI=%s: 取证书失败: %v", tc.sni, err)
			continue
		}
		if cert == nil || cert.Leaf == nil {
			t.Errorf("SNI=%s: 没有返回证书", tc.sni)
			continue
		}
		if got := cert.Leaf.Subject.CommonName; got != tc.want {
			t.Errorf("SNI=%s: 拿到了错误的证书 %q，期望 %q", tc.sni, got, tc.want)
		}
	}
}

// 没有匹配的 SNI 时必须返回 nil，让握手失败 ——
// 绝不能兜一张别的域名的证书，那会让浏览器报「证书名不匹配」，
// 用户看到的现象是「站点被劫持」。
func TestGetCertificateNoMatchReturnsNil(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := writeSelfSigned(t, dir, "a", "a.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "a", Target: "http://127.0.0.1:9000", Host: "a.example.com",
				TLSMode: TLSModeManual, CertFile: certA, KeyFile: keyA},
		},
	}
	loaded, _ := writeConfig(t, cfg)
	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"})
	if err != nil {
		t.Fatalf("不该返回错误（应当返回 nil 让 tls 层报 handshake failure）: %v", err)
	}
	if cert != nil {
		t.Fatalf("未知域名不该兜出证书，实际拿到了 %v", cert.Leaf.Subject)
	}
}

// 通配证书要能匹配子域，但不匹配裸域本身。
func TestWildcardCertMatching(t *testing.T) {
	dir := t.TempDir()
	wc, wk := writeSelfSigned(t, dir, "wild", "*.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "w", Target: "http://127.0.0.1:9000", Host: "*.example.com",
				TLSMode: TLSModeManual, CertFile: wc, KeyFile: wk},
		},
	}
	loaded, _ := writeConfig(t, cfg)
	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	// 子域命中
	if cert, _ := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.example.com"}); cert == nil {
		t.Error("*.example.com 应当匹配 foo.example.com")
	}
	// 裸域不命中（通配语义如此）
	if cert, _ := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); cert != nil {
		t.Error("*.example.com 不应当匹配 example.com 本身")
	}
}

// ---------- 证书状态 ----------

func TestCertStatusReportsExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "s", "s.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "s", Target: "http://127.0.0.1:9000", Host: "s.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)
	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	sts := m.Status()
	if len(sts) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d", len(sts))
	}
	st := sts[0]
	if st.Source != "manual" {
		t.Errorf("来源应当是 manual，实际 %q", st.Source)
	}
	if len(st.Hosts) == 0 || st.Hosts[0] != "s.example.com" {
		t.Errorf("域名列表不对: %v", st.Hosts)
	}
	if st.DaysLeft < 300 {
		t.Errorf("自签证书有效期 365 天，剩余天数不该这么少: %d", st.DaysLeft)
	}
	if st.Expired || st.Expiring {
		t.Errorf("新签的证书不该是过期/临期状态: %+v", st)
	}
	if st.Error != "" {
		t.Errorf("正常证书不该带错误: %s", st.Error)
	}
	if st.Issuer == "" {
		t.Error("应当能读出签发者")
	}
}

// 证书热重载：文件换了之后，加载到的必须是新证书。
func TestManualCertHotReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "h", "h.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "h", Target: "http://127.0.0.1:9000", Host: "h.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)
	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	before, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "h.example.com"})
	if err != nil {
		t.Fatalf("初始取证书失败: %v", err)
	}
	beforeSerial := before.Leaf.SerialNumber

	// 覆盖成一张新证书。注意把 mtime 往前推，避免文件系统时间精度
	// 导致「写了但 mtime 没变」，那会让 changed() 判断不出变化。
	newCert, newKey := writeSelfSigned(t, dir, "h2", "h.example.com")
	cpCert, _ := os.ReadFile(newCert)
	cpKey, _ := os.ReadFile(newKey)
	if err := os.WriteFile(certPath, cpCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cpKey, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	m.reloadChanged()

	after, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "h.example.com"})
	if err != nil {
		t.Fatalf("重载后取证书失败: %v", err)
	}
	if after.Leaf.SerialNumber.Cmp(beforeSerial) == 0 {
		t.Error("证书文件已替换，但拿到的还是旧证书 —— 热重载没生效")
	}
}

// 重载失败时必须保留旧证书继续服务。
//
// 证书轮换的中间态（新文件还没写完整、权限不对）如果让正在用的证书变成空值，
// 站点会直接不可用 —— 用旧的（哪怕快过期）远比全站挂掉强。
func TestManualCertReloadFailureKeepsOldCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "k", "k.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "k", Target: "http://127.0.0.1:9000", Host: "k.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)
	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	good, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "k.example.com"})
	if err != nil {
		t.Fatalf("初始取证书失败: %v", err)
	}

	// 把证书文件写坏
	if err := os.WriteFile(certPath, []byte("not a certificate at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)

	m.reloadChanged()

	after, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "k.example.com"})
	if err != nil {
		t.Fatalf("重载失败后不该连旧证书都拿不到: %v", err)
	}
	if after.Leaf.SerialNumber.Cmp(good.Leaf.SerialNumber) != 0 {
		t.Error("重载失败后应当继续用旧证书")
	}

	// 但状态接口要把这个错误暴露出来，否则运维看不到「轮换没生效」
	found := false
	for _, st := range m.Status() {
		if st.Error != "" {
			found = true
		}
	}
	if !found {
		t.Error("重载失败应当在状态里留下错误信息")
	}
}

// ---------- HTTP→HTTPS 重定向 ----------

func TestWantsHTTPSRedirect(t *testing.T) {
	cases := []struct {
		mode     string
		redirect bool
		want     bool
	}{
		{TLSModeOff, true, false},     // 明文路由没有跳转的意义
		{TLSModeOff, false, false},    //
		{TLSModeAuto, true, true},     // 加密 + 要求跳转
		{TLSModeAuto, false, false},   // 加密但显式关掉了跳转
		{TLSModeManual, true, true},   //
		{TLSModeManual, false, false}, //
	}
	for _, tc := range cases {
		r := &Route{TLSMode: tc.mode, RedirectHTTP: tc.redirect}
		if got := r.wantsHTTPSRedirect(); got != tc.want {
			t.Errorf("mode=%s redirect=%v: 期望 %v，实际 %v", tc.mode, tc.redirect, tc.want, got)
		}
	}
}

// redirect_http 缺省为 true；显式 false 要能保持。
func TestRedirectHTTPDefaultAndOverride(t *testing.T) {
	cfg := &Config{
		TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{}},
		Routes: []RouteConfig{
			{ID: "default", Target: "http://127.0.0.1:9000", Host: "d.example.com"},
			{ID: "keep-plaintext", Target: "http://127.0.0.1:9001", Host: "p.example.com"},
		},
	}
	// 手动把第二条设成 false 再序列化，模拟用户显式写入
	off := false
	cfg.Routes[1].RedirectHTTP = &off

	loaded, _ := writeConfig(t, cfg)
	if !loaded.Routes[0].redirectHTTP() {
		t.Error("redirect_http 缺省应当是 true")
	}
	if loaded.Routes[1].redirectHTTP() {
		t.Error("显式 false 应当保持 false")
	}
}

// 端到端验一次：明文请求应当被 301 到 HTTPS，且路径与查询串都要带上。
func TestHTTPRedirectEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "r", "r.example.com")

	cfg := &Config{
		TLS: TLSConfig{Enabled: true, HTTPPort: 80, HTTPSPort: 443},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "r.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	app := newTestApp(t, loaded)

	// 造一个「明文端口进来的请求」
	req := httptest.NewRequest(http.MethodGet, "http://r.example.com/a/b?x=1&y=2", nil)
	ctx := withPort(req.Context(), defaultHTTPPort)
	ctx = withTLS(ctx, false)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	app.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("期望 301，实际 %d（body: %s）", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	want := "https://r.example.com/a/b?x=1&y=2"
	if loc != want {
		t.Errorf("跳转地址不对\n期望: %s\n实际: %s", want, loc)
	}
}

// 非 443 的 HTTPS 端口要在跳转地址里带上端口号。
//
// 注意路由不能钉死在 listen_port=8443：明文请求是从 8080 进来的，
// 钉死就匹配不到了。真实用法里这种「自定端口 + HTTPS」的组合，
// 路由应当用 listen_port=0 挂在所有端口上。
func TestHTTPRedirectIncludesNonStandardPort(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "p", "p.example.com")

	cfg := &Config{
		TLS:          TLSConfig{Enabled: true, HTTPPort: 18080, HTTPSPort: 18443},
		DefaultPorts: []int{18080, 18443},
		Routes: []RouteConfig{
			{ID: "p", Target: "http://127.0.0.1:9000", Host: "p.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	app := newTestApp(t, loaded)

	req := httptest.NewRequest(http.MethodGet, "http://p.example.com/", nil)
	ctx := withTLS(withPort(req.Context(), 18080), false)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	app.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("期望 301，实际 %d（body: %s）", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "https://p.example.com:18443/" {
		t.Errorf("非标准 HTTPS 端口应当出现在跳转地址里，实际: %s", loc)
	}
}

// 已经在 TLS 上的请求**不能**再跳转，否则就是无限重定向。
func TestNoRedirectOnTLSRequest(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "t", "t.example.com")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "t", Target: backend.URL, Host: "t.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	app := newTestApp(t, loaded)

	req := httptest.NewRequest(http.MethodGet, "https://t.example.com/", nil)
	ctx := withTLS(withPort(req.Context(), defaultHTTPSPort), true)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	app.handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusMovedPermanently {
		t.Fatal("TLS 请求不该被重定向 —— 会造成无限跳转")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("TLS 请求应当正常转发给后端，实际状态码 %d", rec.Code)
	}
}

// TLS 未启用时，明文请求照常转发，一个跳转都不该有。
func TestNoRedirectWhenTLSDisabled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	cfg := &Config{
		Routes: []RouteConfig{
			{ID: "plain", Target: backend.URL, Host: "plain.example.com"},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	app := newTestApp(t, loaded)

	req := httptest.NewRequest(http.MethodGet, "http://plain.example.com/", nil)
	ctx := withTLS(withPort(req.Context(), defaultHTTPPort), false)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	app.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("TLS 关闭时明文请求应当正常转发，实际状态码 %d", rec.Code)
	}
}

// ---------- 端口 spec ----------

// 端口级的 TLS 判定：只有明确需要的端口才跑 TLS。
func TestPortSpecsMarkTLSPorts(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "ps", "ps.example.com")

	cfg := &Config{
		TLS:          TLSConfig{Enabled: true},
		DefaultPorts: []int{80, 8081},
		Routes: []RouteConfig{
			{ID: "secure", Target: "http://127.0.0.1:9000", Host: "ps.example.com",
				TLSMode: TLSModeManual, CertFile: certPath, KeyFile: keyPath},
			{ID: "plain", Target: "http://127.0.0.1:9001", ListenPort: 8081, TLSMode: TLSModeOff},
		},
	}
	loaded, _ := writeConfig(t, cfg)

	m, err := newTLSManager(loaded)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}

	app := &App{}
	specs := app.portSpecs(loaded, m)

	byPort := make(map[int]portSpec, len(specs))
	for _, s := range specs {
		byPort[s.port] = s
	}

	// 443 是 TLS 默认落点，80 明文，8081 因为路由是 off 所以明文
	if !byPort[defaultHTTPSPort].tls.enabled {
		t.Errorf("默认 HTTPS 端口 %d 应当是 TLS", defaultHTTPSPort)
	}
	if byPort[defaultHTTPPort].tls.enabled {
		t.Errorf("明文端口 %d 不该是 TLS", defaultHTTPPort)
	}
	if byPort[8081].tls.enabled {
		t.Errorf("tls_mode=off 路由所在端口 8081 不该是 TLS")
	}
}

// ---------- ACME 目录地址 ----------

func TestACMEEffectiveDirectoryURL(t *testing.T) {
	cases := []struct {
		name string
		ac   ACMEConfig
		want string
	}{
		{"默认走生产", ACMEConfig{}, leProduction},
		{"staging 开关", ACMEConfig{Staging: true}, leStaging},
		{"自定义 CA", ACMEConfig{DirectoryURL: "https://acme.internal/dir"}, "https://acme.internal/dir"},
		// staging 优先于自定义 URL：调试验证时手一抖两个都配了，
		// 按直觉应该是「安全的那个赢」，而不是静默打到生产
		{"staging 压过自定义", ACMEConfig{Staging: true, DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory"}, leStaging},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ac.effectiveDirectoryURL(); got != tc.want {
				t.Errorf("期望 %s，实际 %s", tc.want, got)
			}
		})
	}
}

func TestACMEDefaultCacheDir(t *testing.T) {
	var ac ACMEConfig
	if got := ac.cacheDir(); got != defaultACMEDir {
		t.Errorf("默认缓存目录应当是 %s，实际 %s", defaultACMEDir, got)
	}
	ac.CacheDir = "/var/lib/goproxy/certs"
	if got := ac.cacheDir(); got != "/var/lib/goproxy/certs" {
		t.Errorf("显式配置的缓存目录没生效: %s", got)
	}
}

func TestACMEEmailValidation(t *testing.T) {
	bad := &Config{
		TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{Email: "not-an-email"}},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "e.example.com", TLSMode: TLSModeAuto},
		},
	}
	if _, err := writeConfigErr(bad); err == nil {
		t.Error("明显不是邮箱的 acme.email 应当报错")
	}

	ok := &Config{
		TLS: TLSConfig{Enabled: true, ACME: &ACMEConfig{Email: "ops@example.com"}},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "e.example.com", TLSMode: TLSModeAuto},
		},
	}
	if _, err := writeConfigErr(ok); err != nil {
		t.Errorf("合法邮箱不该报错: %v", err)
	}
}

// 未知的 tls_mode 必须报错，不能静默当作 off。
func TestUnknownTLSModeRejected(t *testing.T) {
	cfg := &Config{
		TLS: TLSConfig{Enabled: true},
		Routes: []RouteConfig{
			{ID: "r", Target: "http://127.0.0.1:9000", Host: "u.example.com", TLSMode: "selfsigned"},
		},
	}
	_, err := writeConfigErr(cfg)
	if err == nil {
		t.Fatal("未知的 tls_mode 应当报错")
	}
	if !strings.Contains(err.Error(), "off|auto|manual") {
		t.Errorf("错误信息应当列出合法取值，实际: %v", err)
	}
}

// newTestApp 构造一个可跑 handler 的 App。
//
// 必须把 metrics 和 logs 都建好：handler 的 defer 里会写访问日志、
// 各分支会打点，用一个裸 &App{} 会直接 nil panic。
func newTestApp(t *testing.T, cfg *Config) *App {
	t.Helper()
	a := &App{
		metrics: NewMetrics(),
		logs:    newLogBuffer(logRingSize),
	}
	tbl, err := buildTable(cfg, nil, newTransport())
	if err != nil {
		t.Fatalf("构建路由表失败: %v", err)
	}
	tbl.trusted = nil
	a.table.Store(tbl)
	a.tlsCfg.Store(cfg)

	m, err := newTLSManager(cfg)
	if err != nil {
		t.Fatalf("构建证书管理器失败: %v", err)
	}
	a.tlsmgr.Store(m)
	return a
}

// ---------- 辅助 ----------

// withPort / withTLS 给测试构造带 port/TLS 标记的 context。
// 生产环境里这两个值是 ListenerManager 通过 BaseContext 注入的。
func withPort(ctx context.Context, port int) context.Context {
	return context.WithValue(ctx, ctxKeyPort{}, port)
}

func withTLS(ctx context.Context, on bool) context.Context {
	return context.WithValue(ctx, ctxKeyTLS{}, on)
}

// copyForTest 是给 RouteConfig 做浅拷贝的小工具，供测试构造变体用。
func (r RouteConfig) copyForTest() *RouteConfig {
	cp := r
	return &cp
}
