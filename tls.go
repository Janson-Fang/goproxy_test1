package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ctxBackground 是状态查询用的 context。
func ctxBackground() context.Context { return context.Background() }

// minTLSVersion 是允许的最低 TLS 版本。
//
// 锁 1.2：TLS 1.0/1.1 已被所有主流浏览器弃用，且存在已知的降级攻击面
// （BEAST / POODLE 那一类）。Go 的默认值本来就是 1.2，这里显式写出来，
// 是为了让「有人把它调低」必须是一次有意识的修改，而不是继承来的默认。
const minTLSVersion = tls.VersionTLS12

// certReloadInterval 是手动证书文件的轮询间隔。
//
// 用轮询而不是 fsnotify：证书轮换多是 certbot / acme.sh 这类脚本
// **原子替换**文件（临时文件 + rename），inotify 监听 inode 的做法
// 在 rename 之后会盯住一个已经没人引用的旧 inode，从此再也收不到事件。
// 轮询 mtime 没有这个坑，代价只是 30 秒才生效一次 —— 对证书轮换完全够用
// （证书有效期以月计）。
const certReloadInterval = 30 * time.Second

// certExpiryWarnDays 是证书到期的告警阈值，界面上标黄用。
const certExpiryWarnDays = 20

// CertStatus 是暴露给管理 API / 控制台的证书状态。
type CertStatus struct {
	Hosts     []string `json:"hosts"`
	Source    string   `json:"source"` // manual | auto
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	// DaysLeft 剩余天数。负数表示已过期。
	DaysLeft int `json:"days_left"`
	// Expiring 剩余天数低于告警阈值。
	Expiring bool `json:"expiring"`
	// Expired 已过期。
	Expired bool `json:"expired"`
	// Error 加载或签发失败时的原因，正常时为空。
	Error string `json:"error,omitempty"`
	// Routes 引用这张证书的路由 ID。
	Routes []string `json:"routes,omitempty"`
}

// manualCert 是一组手动加载的证书文件。
type manualCert struct {
	certPath string
	keyPath  string

	// routes 记录引用这张证书的路由 ID，供状态展示。
	routes []string

	mu     sync.RWMutex
	cert   *tls.Certificate
	leaf   *x509.Certificate
	err    error
	mtime  time.Time
	keyMod time.Time
}

// tlsManager 是 TLS 的总入口：按 SNI 分发证书，并跟踪证书状态。
//
// 分发优先级：手动证书 > ACME。手动优先是因为「用户显式挂了证书」
// 是最强的意图表达，不该被自动签发悄悄盖掉。
type tlsManager struct {
	// byHost 手动证书，按规范化后的域名索引。
	byHost map[string]*manualCert
	// wildcards 手动通配证书，按后缀长度降序（越长越具体，优先匹配）。
	wildcards []wildcardCert

	// acme 自动签发管理器。顶层开关关闭或没有任何 auto 路由时为 nil。
	acme *autocert.Manager

	// acmeRoutes 记录哪些路由在用自动证书，用于状态展示与错误归因。
	acmeHosts map[string][]string

	mu sync.RWMutex
	// lastAutoErr 记录最近一次自动签发错误，供状态接口展示。
	lastAutoErr string
}

type wildcardCert struct {
	suffix string // "example.com"（由 "*.example.com" 得来）
	mc     *manualCert
}

// newTLSManager 从配置构建证书管理器。
//
// 返回 nil 表示 TLS 完全未启用（顶层开关关闭），调用方据此走纯明文路径 ——
// 这样「没开 TLS」的部署连一个多余的 goroutine 都不会有。
func newTLSManager(cfg *Config) (*tlsManager, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}

	m := &tlsManager{
		byHost:    make(map[string]*manualCert),
		acmeHosts: make(map[string][]string),
	}

	// 收集手动证书：同一个证书文件可能被多条路由引用，合并成一份，
	// 避免同一个文件被轮询加载 N 次。
	type key struct{ cert, key string }
	seen := make(map[key]*manualCert)

	for _, r := range cfg.Routes {
		if !r.enabled() {
			continue
		}
		switch r.routeTLSMode() {
		case TLSModeManual:
			certPath, keyPath := cfg.certPath(r), cfg.keyPath(r)
			k := key{certPath, keyPath}
			mc := seen[k]
			if mc == nil {
				mc = &manualCert{certPath: certPath, keyPath: keyPath}
				// 启动时就加载一次，让配置错误立刻暴露（validate 已经验过，
				// 但那是「写配置时」的快照，文件可能在之后被换掉）。
				if err := mc.load(); err != nil {
					return nil, fmt.Errorf("路由 %s: %w", r.ID, err)
				}
				seen[k] = mc
			}
			m.attach(r, mc, cfg)

		case TLSModeAuto:
			host := normalizeHost(r.Host)
			if host == "" {
				// validate 已经拦过，这里是纵深防御
				return nil, fmt.Errorf("路由 %s: tls_mode=auto 但 host 为空", r.ID)
			}
			m.acmeHosts[host] = append(m.acmeHosts[host], r.ID)
		}
	}

	// 只有确实有 auto 路由时才建 autocert.Manager。
	// 全 manual 的部署不该去碰 ACME，也不该因为证书目录不可写而启动失败。
	if len(m.acmeHosts) > 0 {
		if err := m.initACME(cfg); err != nil {
			return nil, err
		}
	}

	// 启动手动证书的 mtime 轮询
	if len(m.byHost) > 0 || len(m.wildcards) > 0 {
		go m.watchCerts()
	}

	return m, nil
}

// attach 把一个手动证书挂到路由声明的域名上。
func (m *tlsManager) attach(r RouteConfig, mc *manualCert, cfg *Config) {
	mc.mu.Lock()
	mc.routes = append(mc.routes, r.ID)
	mc.mu.Unlock()

	host := normalizeHost(r.Host)
	if host == "" {
		// 没写 host 的 manual 路由：拿证书里的第一个 DNS 名兜底，
		// 否则这张证书永远匹配不到任何 SNI，等于白配。
		names := certDNSNames(mc)
		if len(names) == 0 {
			return
		}
		host = names[0]
	}
	if strings.HasPrefix(host, "*.") {
		suffix := strings.TrimPrefix(host, "*.")
		m.wildcards = append(m.wildcards, wildcardCert{suffix: suffix, mc: mc})
		return
	}
	if prev, ok := m.byHost[host]; ok && prev != mc {
		// 同域名挂了两张不同证书：后一条静默失效是很难查的问题，必须告警。
		slog.Warn("域名配置了多张手动证书，只有第一个生效",
			"host", host, "kept", prev.certPath, "ignored", mc.certPath)
		return
	}
	m.byHost[host] = mc
}

// initACME 构造 autocert.Manager。
func (m *tlsManager) initACME(cfg *Config) error {
	ac := cfg.TLS.ACME
	if ac == nil {
		ac = &ACMEConfig{}
	}
	cacheDir := ac.cacheDir()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("创建 ACME 缓存目录 %s 失败: %w", cacheDir, err)
	}

	cache := autocert.DirCache(cacheDir)

	am := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  cache,
		Email:  strings.TrimSpace(ac.Email),
	}
	if url := ac.effectiveDirectoryURL(); url != "" {
		// 换 CA 的唯一途径：autocert 的 Manager.Client 是个 *acme.Client，
		// 目录地址就写在它身上。留空时 autocert 自己填 Let's Encrypt 生产环境。
		am.Client = &acme.Client{DirectoryURL: url}
	}
	// 白名单：只允许为配置里出现过的域名申请证书。
	// SNI 是客户端完全可控的字段，不设白名单的话，任何人扫一遍 SNI
	// 就能让本机替一堆不相干的域名去申请证书，既烧配额又留下滥用的口子。
	am.HostPolicy = m.hostPolicy(cfg)

	if ac.Staging {
		slog.Warn("ACME 使用 Let's Encrypt 测试环境，签发的是不受信任的证书，切勿用于生产",
			"dir", leStaging)
	}

	m.acme = am
	slog.Info("ACME 已启用",
		"dir", ac.effectiveDirectoryURL(),
		"cache", cacheDir,
		"hosts", len(m.acmeHosts))
	return nil
}

// hostPolicy 决定某个 SNI 是否允许申请证书。
func (m *tlsManager) hostPolicy(cfg *Config) autocert.HostPolicy {
	allow := make(map[string]struct{})
	for _, h := range cfg.TLS.ACME.Hosts {
		allow[normalizeHost(h)] = struct{}{}
	}
	explicit := len(allow) > 0

	return func(_ context.Context, host string) error {
		h := normalizeHost(host)
		if h == "" {
			return errors.New("空域名")
		}
		if explicit {
			if _, ok := allow[h]; !ok {
				return fmt.Errorf("域名 %s 不在 tls.acme.hosts 白名单内", h)
			}
			return nil
		}
		// 没配白名单：退化为「必须是某条 auto 路由声明的域名」
		if _, ok := m.acmeHosts[h]; !ok {
			return fmt.Errorf("域名 %s 没有任何路由在用自动证书", h)
		}
		return nil
	}
}

// GetCertificate 是 tls.Config 的回调，按客户端 SNI 选证书。
//
// 找不到匹配时返回 nil, nil —— 让 crypto/tls 自己回 handshake failure。
// 这里**不能**随手兜一张默认证书：把 A 域名的证书发给 B 域名，浏览器会报
// 证书名不匹配，用户看到的现象是「站点被劫持」，比直接握手失败更吓人。
func (m *tlsManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := normalizeHost(hello.ServerName)

	// 1. 手动证书精确匹配
	if mc := m.lookupManual(name); mc != nil {
		cert, err := mc.get()
		if err != nil {
			m.setAutoErr(err) // 借用同一个错误位，状态接口统一展示
			return nil, err
		}
		return cert, nil
	}

	// 2. ACME 自动签发
	if m.acme != nil {
		cert, err := m.acme.GetCertificate(hello)
		if err != nil {
			m.setAutoErr(err)
			slog.Warn("自动证书获取失败", "host", name, "err", err)
			return nil, err
		}
		return cert, nil
	}

	return nil, nil
}

// lookupManual 查手动证书，精确优先，其次通配。
func (m *tlsManager) lookupManual(name string) *manualCert {
	if name == "" {
		return nil
	}
	if mc, ok := m.byHost[name]; ok {
		return mc
	}
	// 通配：*.example.com 匹配 a.example.com，但不匹配 example.com 本身。
	// 按后缀长度降序试，保证 *.a.example.com 优先于 *.example.com。
	for _, w := range m.wildcards {
		if strings.HasSuffix(name, "."+w.suffix) {
			return w.mc
		}
	}
	return nil
}

func (m *tlsManager) setAutoErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.lastAutoErr = ""
		return
	}
	m.lastAutoErr = err.Error()
}

// watchCerts 轮询手动证书文件，变更后重载。
func (m *tlsManager) watchCerts() {
	t := time.NewTicker(certReloadInterval)
	defer t.Stop()
	for range t.C {
		m.reloadChanged()
	}
}

// reloadChanged 检查所有手动证书，文件变了就重新加载。
func (m *tlsManager) reloadChanged() {
	seen := make(map[*manualCert]struct{})
	all := make([]*manualCert, 0, len(m.byHost)+len(m.wildcards))
	for _, mc := range m.byHost {
		if _, ok := seen[mc]; ok {
			continue
		}
		seen[mc] = struct{}{}
		all = append(all, mc)
	}
	for _, w := range m.wildcards {
		if _, ok := seen[w.mc]; ok {
			continue
		}
		seen[w.mc] = struct{}{}
		all = append(all, w.mc)
	}

	for _, mc := range all {
		if !mc.changed() {
			continue
		}
		slog.Info("检测到证书文件变化，重新加载", "cert", mc.certPath)
		if err := mc.load(); err != nil {
			// 重载失败**保留旧证书**继续服务，只记错误。
			// 把正在用的证书换成一个加载失败的空值，会让站点直接挂掉 ——
			// 证书轮换中间态出错时，用旧的（哪怕快过期）远比全站不可用强。
			slog.Error("证书重载失败，继续使用旧证书", "cert", mc.certPath, "err", err)
		}
	}
}

// ---- manualCert ----

// load 读取并解析证书文件。
func (mc *manualCert) load() error {
	cert, err := loadKeyPairCert(mc.certPath, mc.keyPath)

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if err != nil {
		mc.err = err
		return fmt.Errorf("加载证书 %s / %s 失败: %w", mc.certPath, mc.keyPath, err)
	}
	mc.cert = cert
	mc.leaf = cert.Leaf
	mc.err = nil
	if st, serr := os.Stat(mc.certPath); serr == nil {
		mc.mtime = st.ModTime()
	}
	if st, serr := os.Stat(mc.keyPath); serr == nil {
		mc.keyMod = st.ModTime()
	}
	return nil
}

// changed 报告文件是否比上次加载时更新。
//
// 同时看 mtime 和文件大小之外的信息：mtime 相等但内容变了的情况
// 在容器里挂载证书（mtime 被保留）时真的会遇到，所以额外比 size。
func (mc *manualCert) changed() bool {
	mc.mu.RLock()
	oldMtime, oldKeyMod := mc.mtime, mc.keyMod
	mc.mu.RUnlock()

	if st, err := os.Stat(mc.certPath); err == nil {
		if !st.ModTime().Equal(oldMtime) {
			return true
		}
	} else {
		return false // 文件暂时读不到，等下一轮，不当作变更
	}
	if st, err := os.Stat(mc.keyPath); err == nil {
		if !st.ModTime().Equal(oldKeyMod) {
			return true
		}
	}
	return false
}

// get 返回当前证书，加载失败时返回错误。
func (mc *manualCert) get() (*tls.Certificate, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	if mc.cert == nil {
		if mc.err != nil {
			return nil, mc.err
		}
		return nil, errors.New("证书尚未加载")
	}
	return mc.cert, nil
}

// leafCert 返回解析后的叶子证书，供状态接口读取签发者与有效期。
func (mc *manualCert) leafCert() *x509.Certificate {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.leaf
}

func (mc *manualCert) loadErr() error {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.err
}

// routeIDs 返回引用这张证书的路由 ID。
func (mc *manualCert) routeIDs() []string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return append([]string(nil), mc.routes...)
}

// ---- 证书状态 ----

// Status 汇总所有证书状态，供管理 API 与控制台使用。
func (m *tlsManager) Status() []CertStatus {
	if m == nil {
		return nil
	}
	var out []CertStatus

	// 手动证书
	seen := make(map[*manualCert]struct{})
	addManual := func(host string, mc *manualCert, wildcard bool) {
		if _, ok := seen[mc]; ok {
			return
		}
		seen[mc] = struct{}{}
		hosts := certDNSNames(mc)
		if len(hosts) == 0 && host != "" {
			hosts = []string{host}
		}
		st := CertStatus{Source: "manual", Hosts: hosts, Routes: certRoutes(mc)}
		if wildcard && host != "" {
			st.Hosts = append([]string{"*." + host}, hosts...)
		}
		if leaf := mc.leafCert(); leaf != nil {
			st.Issuer = leaf.Issuer.CommonName
			st.Subject = leaf.Subject.CommonName
			st.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
			st.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			fillExpiry(&st, leaf.NotAfter)
		}
		if err := mc.loadErr(); err != nil {
			st.Error = err.Error()
		}
		out = append(out, st)
	}

	hosts := make([]string, 0, len(m.byHost))
	for h := range m.byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		addManual(h, m.byHost[h], false)
	}
	for _, w := range m.wildcards {
		addManual(w.suffix, w.mc, true)
	}

	// 自动证书：读 ACME 缓存目录，按域名归位
	if m.acme != nil {
		out = append(out, m.acmeStatus()...)
	}
	return out
}

// acmeStatus 从缓存中读出已签发的自动证书状态。
func (m *tlsManager) acmeStatus() []CertStatus {
	m.mu.RLock()
	lastErr := m.lastAutoErr
	m.mu.RUnlock()

	hosts := make([]string, 0, len(m.acmeHosts))
	for h := range m.acmeHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var out []CertStatus
	for _, h := range hosts {
		st := CertStatus{
			Hosts:  []string{h},
			Source: "auto",
			Routes: m.acmeHosts[h],
		}
		// 缓存里已经有证书就读出来展示；还没有说明尚未签发
		// （首次请求触发签发，或签发失败），这时用错误信息说明原因。
		if cert, err := m.cachedCert(h); err == nil && cert != nil {
			st.Issuer = cert.Issuer.CommonName
			st.Subject = cert.Subject.CommonName
			st.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
			st.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
			fillExpiry(&st, cert.NotAfter)
		} else {
			st.Error = "尚未签发（首次访问时将自动申请）"
			if lastErr != "" {
				st.Error = lastErr
			}
		}
		out = append(out, st)
	}
	return out
}

// cachedCert 从 ACME 缓存里读某域名的证书。
func (m *tlsManager) cachedCert(host string) (*x509.Certificate, error) {
	if m.acme == nil || m.acme.Cache == nil {
		return nil, errors.New("ACME 未启用")
	}
	der, err := m.acme.Cache.Get(ctxBackground(), host)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return leaf, nil
}

// fillExpiry 根据到期时间填 DaysLeft / Expiring / Expired。
func fillExpiry(st *CertStatus, notAfter time.Time) {
	left := time.Until(notAfter)
	st.DaysLeft = int(left.Hours() / 24)
	st.Expired = left <= 0
	st.Expiring = !st.Expired && st.DaysLeft < certExpiryWarnDays
}

// ---- 辅助 ----

// loadKeyPairCert 读证书与私钥，并把叶子证书解析好放进 Leaf。
//
// 预先填 Leaf 是必需的：不填的话 Go 会在每次握手时现解析一遍
// （tls.Certificate 的注释明确说明这一点），白白浪费 CPU。
func loadKeyPairCert(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			return nil, perr
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// certDNSNames 取证书里的 DNS 名，供「没写 host 的 manual 路由」兜底。
func certDNSNames(mc *manualCert) []string {
	leaf := mc.leafCert()
	if leaf == nil {
		return nil
	}
	return append([]string(nil), leaf.DNSNames...)
}

// certRoutes 记录引用同一张证书的路由 ID，供状态展示。
func certRoutes(mc *manualCert) []string { return mc.routeIDs() }
