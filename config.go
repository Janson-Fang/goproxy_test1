package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// defaultAdminAddr 是 admin_addr 留空时使用的默认值。
const defaultAdminAddr = "127.0.0.1:8080"

// Config 是配置文件的顶层结构。
// demo 阶段用 JSON 文件做配置源；正式版换成 SQLite 时，只需要替换
// loadConfig 的实现，下游的 buildTable / Route 结构完全不用动。
type Config struct {
	// DefaultPorts 是必定监听的端口，即使没有任何路由引用它们。
	// 默认 [80]。业务端口由路由的 listen_port 自动派生，不需要写在这里。
	DefaultPorts []int `json:"default_ports,omitempty"`

	// AdminAddr 管理端口。留空用默认值 127.0.0.1:8080；
	// 显式写 off / none / disabled 则彻底关闭管理端口。
	AdminAddr string `json:"admin_addr,omitempty"`

	// AdminUsers 是控制台的管理员账号列表。
	//
	// 每项含 username 与 bcrypt 的 password_hash（复用路由 Basic 认证那套字段，
	// 代码也复用同一套校验）。控制台登录页收「用户名 + 密码」，
	// 校验通过后换一个 HttpOnly 会话 Cookie，密码本身不进浏览器存储。
	//
	// 与 AdminToken 的关系（两者可同时存在，也可只用其一）：
	//   - AdminUsers 给**浏览器**用：有用户名、可按人区分、能在控制台里看到是谁登的
	//   - AdminToken 给**脚本/监控**用：Authorization: Bearer <token>，一个值搞定，
	//     适合 curl、Prometheus、CI 这类不方便维护 Cookie 的调用方
	// 两个都为空时管理接口完全打不开 —— 这是有意的：宁可打不开，
	// 也不能出现「没配凭据却谁都能改路由」这种状态。
	AdminUsers []AdminUser `json:"admin_users,omitempty"`

	// AdminToken 管理接口的访问令牌，用于 Authorization: Bearer。
	//
	// 历史说明：v0.5.0 及以前它还有第二个职责 —— 「回环地址免认证」是默认行为，
	// 这个字段只在管理端口监听非回环地址时才被要求。v0.6.0 起**回环不再免认证**，
	// 所有访问都必须带凭据（会话 Cookie 或 Bearer 令牌），这个字段退回它本来的定位：
	// 给脚本用的便捷凭据。
	AdminToken string `json:"admin_token,omitempty"`

	AccessLog bool `json:"access_log"`
	// TrustedProxies 里的项是 IP 或 CIDR。
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// TLS 是全局 TLS/ACME 配置。默认 enabled=false，即完全保持历史行为：
	// 所有端口跑明文 HTTP。打开后路由默认走 ACME 自动证书，可逐条覆盖。
	TLS TLSConfig `json:"tls,omitzero"`

	Routes []RouteConfig `json:"routes"`

	// cfgPath 是配置文件的路径，不序列化。
	//
	// 存它是为了解析证书文件里的相对路径：进程的工作目录取决于怎么启动的
	// （systemd 是 /、docker 是 /、手动是当前目录），拿它当基准太不稳，
	// 相对配置文件所在目录才符合直觉。
	cfgPath string `json:"-"`
}

type RouteConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Enabled 为 nil 时视为 true
	Enabled *bool `json:"enabled,omitempty"`

	// ListenPort 为 0 表示该路由不挑端口（挂到所有监听端口上）。
	// 非 0 表示只有从这个端口进来的请求才匹配它，且引擎会自动开这个端口的监听。
	ListenPort int `json:"listen_port"`

	// Host 支持精确域名（api.example.com）、通配（*.example.com）、空串（任意）。
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`

	Target       string `json:"target"`
	StripPrefix  bool   `json:"strip_prefix"`
	PreserveHost bool   `json:"preserve_host"`

	// ---- TLS（仅顶层 tls.enabled=true 时生效）----

	// TLSMode: off（明文）| auto（ACME 自动签发）| manual（挂本地证书）。
	// 留空时按顶层开关推导：开关打开→auto，关闭→off。
	TLSMode string `json:"tls_mode,omitempty"`
	// CertFile / KeyFile 是 manual 模式的证书与私钥路径。
	// 相对路径相对 tls.cert_dir 解析（没配 cert_dir 则相对配置文件所在目录）。
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// RedirectHTTP 控制该路由是否把 HTTP 请求 301 跳到 HTTPS。
	// 用指针是为了区分「没写」和「显式写了 false」—— 没写默认 true。
	RedirectHTTP *bool `json:"redirect_http,omitempty"`

	// TimeoutMs 为 0 时使用全局默认（60s）
	TimeoutMs int `json:"timeout_ms"`

	RateLimit *RateLimitConfig `json:"rate_limit,omitempty"`

	// CircuitBreaker 不配则不启用熔断
	CircuitBreaker *CBConfig `json:"circuit_breaker,omitempty"`
	// Auth 不配或 mode=none 则不做认证
	Auth *RouteAuthConfig `json:"auth,omitempty"`
	// ACL IP 白/黑名单，不配则不限制
	ACL *ACLConfig `json:"acl,omitempty"`
}

type RouteAuthConfig struct {
	// Mode: none（默认）| basic | jwt
	Mode  string           `json:"mode"`
	Realm string           `json:"realm"`
	Basic []BasicAuthEntry `json:"basic"`
	JWT   *JWTConfig       `json:"jwt"`
}

type ACLConfig struct {
	// Mode: none（默认）| allow（白名单）| deny（黑名单）
	Mode  string   `json:"mode"`
	CIDRs []string `json:"cidrs"`
}

type RateLimitConfig struct {
	RPS   float64 `json:"rps"`
	Burst float64 `json:"burst"`
	// Scope: ip（默认，按客户端 IP）/ global（整条路由共享一个桶）
	Scope string `json:"scope"`
}

func loadConfig(path string) (*Config, error) {
	_, cfg, err := readConfigFile(path)
	return cfg, err
}

// readConfigFile 读文件并返回「可运行的」配置（默认值已补齐）。
// raw 是文件原始字节，用于算 revision，或在写坏时原样回滚。
func readConfigFile(path string) (raw []byte, cfg *Config, err error) {
	raw, cfg, err = parseConfigFile(path)
	if err != nil {
		return nil, nil, err
	}
	// 两份默认值都要补：漏掉 applyRouteDefaults 的话，
	// 配置文件里少写 path_prefix 的路由会直接加载失败。
	cfg.applyTopDefaults()
	cfg.applyRouteDefaults()
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	return raw, cfg, nil
}

// parseConfigFile 只做「读 + 反序列化」，一个默认值都不补。
// 管理接口的写路径靠它知道「文件里究竟写了什么」。
func parseConfigFile(path string) (raw []byte, cfg *Config, err error) {
	raw, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	cfg = &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	// 证书相对路径的解析基准。反序列化完成后再设，避免被 JSON 里的同名字段覆盖。
	cfg.cfgPath = path
	return raw, cfg, nil
}

// applyTopDefaults 给顶层字段补默认值。
//
// 关键：这些值**绝不能回写文件**。否则一次保存就会把「admin_addr 留空」
// （意思是「用默认」）固化成 127.0.0.1:8080，用户再也没法用留空表达意图，
// 而且原本关闭状态的管理端口会被悄悄打开。
func (c *Config) applyTopDefaults() {
	if len(c.DefaultPorts) == 0 {
		c.DefaultPorts = []int{80}
	}
	if c.AdminAddr == "" {
		c.AdminAddr = defaultAdminAddr
	}
	c.applyTLSDefaults()
}

// applyRouteDefaults 给路由补默认值。这些回写文件是安全的，
// 而且是期望的：ID 和 path_prefix 固化后，界面按 ID 增删改才稳定。
func (c *Config) applyRouteDefaults() {
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.ID == "" {
			r.ID = fmt.Sprintf("route-%d", i)
		}
		if r.PathPrefix == "" {
			r.PathPrefix = "/"
		}
	}
	c.applyRouteTLSDefaults()
}

// validateWithDefaults 在「补过默认值」的副本上校验，不改动原对象。
// 写路径需要它：校验要按运行时语义来做（ID 和路径都会兜底），
// 但写回文件的必须是不含顶层默认值的版本。
func (c *Config) validateWithDefaults() error {
	cp := *c
	cp.Routes = append([]RouteConfig(nil), c.Routes...)
	cp.applyTopDefaults()
	cp.applyRouteDefaults()
	return cp.validate()
}

// applyDefaults 补齐全部默认值（顶层 + 路由），得到「可运行的」配置。
// 注意：顶层那部分只是为了内存里跑起来，不要回写文件，理由见 applyTopDefaults。
func (c *Config) applyDefaults() {
	c.applyTopDefaults()
	c.applyRouteDefaults()
}

// adminEnabled 报告是否应该监听管理端口。
func (c *Config) adminEnabled() bool { return !isOff(c.AdminAddr) }

// AdminUser 是控制台的一个管理员账号。
//
// 字段与路由 Basic 认证的 BasicAuthEntry 保持一致（username + bcrypt 的
// password_hash）—— 这不是巧合，是有意复用：同一套概念在项目里只该有一种写法，
// 否则用户得记住两套配置格式，代码里也会出现两份几乎相同的校验逻辑。
type AdminUser struct {
	Username     string `json:"username"`
	Password     string `json:"password"`      // 明文，仅测试用，启动会打警告
	PasswordHash string `json:"password_hash"` // bcrypt，推荐
}

// hasAdminCredentials 报告配置里是否至少存在一种可用的管理端凭据。
//
// 两者皆无时管理接口完全打不开。这是**故意**的：曾经的默认行为是
// 「回环免认证」，于是没配凭据的机器从本机看是好的、从外面看是被拒的，
// 同一个配置在不同来源下表现不一致，很难排查。现在没凭据就是彻底进不去，
// 启动日志会明确告诉你该怎么配。
func (c *Config) hasAdminCredentials() bool {
	return len(c.AdminUsers) > 0 || strings.TrimSpace(c.AdminToken) != ""
}

// isOff 识别用于「显式关闭」的哨兵值。
// 这里刻意用显式字面量而不是空串 —— 空串已经承担了「用默认值」的语义，
// 一个值扮两个角色迟早出事（install.sh 里 MIRROR=direct 就是这么挂的）。
func isOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "none", "disabled", "false":
		return true
	}
	return false
}

// addrPort 从 "host:port" 里取端口号，解析不出来返回 0。
func addrPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

// maxAdminUsers 是管理员账号数量上限。
//
// 管理端是单管理员场景的轻量实现，不存在角色/权限分级。
// 设上限是为了挡住「配置写错导致数组无限增长」这类事故：
// 每个账号都要在登录时做一次 bcrypt（几十到上百毫秒），
// 账号太多会让登录耗时线性增长，反而变成放大攻击面。
const maxAdminUsers = 32

// validateAdminUsers 校验管理员账号列表。
//
// 这里的规则与 Basic 认证那套**故意保持一致**（非空、唯一、hash 合法），
// 因为两者对 bcrypt 的要求完全相同。唯一的额外约束是数量上限 ——
// 路由的 Basic 账号是每请求比对的，管理端账号会在登录时逐个参与校验，
// 代价不一样，所以上限也不该照搬。
func (c *Config) validateAdminUsers() error {
	if len(c.AdminUsers) > maxAdminUsers {
		return fmt.Errorf("admin_users 最多 %d 个账号，当前 %d 个", maxAdminUsers, len(c.AdminUsers))
	}

	seen := make(map[string]struct{}, len(c.AdminUsers))
	for i, u := range c.AdminUsers {
		name := strings.TrimSpace(u.Username)
		if name == "" {
			return fmt.Errorf("admin_users[%d]: username 不能为空", i)
		}
		// 用户名统一按原样存储与比对（不做大小写折叠）：
		// 折叠会引入「Admin 和 admin 是同一个账号」这种需要额外解释的语义，
		// 而这里并没有避免撞名的需求 —— 配置是管理员自己写的。
		if _, dup := seen[name]; dup {
			return fmt.Errorf("admin_users[%d]: username %q 重复", i, name)
		}
		seen[name] = struct{}{}

		hash := u.PasswordHash
		if hash == "" {
			if u.Password == "" {
				return fmt.Errorf("admin_users[%d] (%s): 既没有 password 也没有 password_hash", i, name)
			}
			continue // 明文密码会在构建认证器时转成 bcrypt
		}
		// 校验是不是合法 bcrypt。配错了却以为在生效是最坏的情况：
		// 表面上「我明明设了密码」，实际没人能登录（或者更糟，谁都能登录）。
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("probe")); err != nil &&
			!errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return fmt.Errorf("admin_users[%d] (%s): password_hash 不是合法的 bcrypt: %w", i, name, err)
		}
	}

	// 管理端开着却一个凭据都没有 —— 直接拒绝启动太苛刻（用户可能正要进去配），
	// 但要明确告诉他：现在这个状态谁都进不去。启动流程会把这句话打出来。
	return nil
}

func (c *Config) validate() error {
	// trusted_proxies 每一项必须是 IP 或 CIDR。不在这里拦，
	// 写接口就会先把坏配置落盘、再在 reload 阶段失败。
	if _, err := c.trustedNets(); err != nil {
		return err
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	if err := c.validateAdminUsers(); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(c.Routes))
	for i, r := range c.Routes {
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("routes[%d]: id %q 重复", i, r.ID)
		}
		seen[r.ID] = struct{}{}

		if !strings.HasPrefix(r.PathPrefix, "/") {
			return fmt.Errorf("routes[%d] (%s): path_prefix 必须以 / 开头", i, r.ID)
		}
		if r.ListenPort < 0 || r.ListenPort > 65535 {
			return fmt.Errorf("routes[%d] (%s): listen_port 非法", i, r.ID)
		}
		u, err := url.Parse(r.Target)
		if err != nil {
			return fmt.Errorf("routes[%d] (%s): target 解析失败: %w", i, r.ID, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("routes[%d] (%s): target 必须是 http:// 或 https://，当前 %q", i, r.ID, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("routes[%d] (%s): target 缺少主机地址", i, r.ID)
		}
		if r.TimeoutMs < 0 {
			return fmt.Errorf("routes[%d] (%s): timeout_ms 不能为负", i, r.ID)
		}

		if a := r.Auth; a != nil {
			switch strings.ToLower(a.Mode) {
			case "", "none":
			case "basic":
				if len(a.Basic) == 0 {
					return fmt.Errorf("routes[%d] (%s): auth.mode=basic 但没有配置账号", i, r.ID)
				}
			case "jwt":
				if a.JWT == nil {
					return fmt.Errorf("routes[%d] (%s): auth.mode=jwt 但没有配置 jwt", i, r.ID)
				}
			default:
				return fmt.Errorf("routes[%d] (%s): auth.mode 必须是 none|basic|jwt，当前 %q", i, r.ID, a.Mode)
			}
		}

		if cb := r.CircuitBreaker; cb != nil {
			if cb.ErrorRate < 0 || cb.ErrorRate > 1 {
				return fmt.Errorf("routes[%d] (%s): circuit_breaker.error_rate 必须在 0~1", i, r.ID)
			}
			if cb.WindowSecs > 300 {
				return fmt.Errorf("routes[%d] (%s): circuit_breaker.window_secs 不能超过 300", i, r.ID)
			}
		}

		if acl := r.ACL; acl != nil {
			switch strings.ToLower(acl.Mode) {
			case "", "none", "allow", "deny":
			default:
				return fmt.Errorf("routes[%d] (%s): acl.mode 必须是 none|allow|deny，当前 %q", i, r.ID, acl.Mode)
			}
		}
	}

	// 路由端口不能和管理端口撞车。撞了会导致监听失败，
	// 而报错发生在 listeners.Sync 里，离配置错误很远，极难排查。
	if ap := addrPort(c.AdminAddr); ap > 0 {
		for _, p := range c.DefaultPorts {
			if p == ap {
				return fmt.Errorf("default_ports 中的 %d 与管理端口 %s 冲突", p, c.AdminAddr)
			}
		}
		for i, r := range c.Routes {
			if r.ListenPort == ap {
				return fmt.Errorf("routes[%d] (%s): listen_port %d 与管理端口冲突", i, r.ID, ap)
			}
		}
	}

	return nil
}

func (c *Config) trustedNets() ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, s := range c.TrustedProxies {
		if _, n, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		return nil, fmt.Errorf("trusted_proxies 项 %q 既不是 IP 也不是 CIDR", s)
	}
	return nets, nil
}

// allListenPorts 汇总需要监听的端口：默认端口 + 所有路由显式声明的端口。
//
// 启用 TLS 时还要带上 tls.https_port —— 它是 TLS 的默认落点，
// 即使没有任何路由把 listen_port 写成 443，也得听着。
// 漏掉它会让「host 匹配 + 默认端口」这类最常见的配置直接 404：
// 请求确实到了 443，但路由表里没有这个端口的索引桶，Match 只能返回空。
func (c *Config) allListenPorts() []int {
	set := make(map[int]struct{})
	for _, p := range c.DefaultPorts {
		if p > 0 && p <= 65535 {
			set[p] = struct{}{}
		}
	}
	if c.TLS.Enabled && c.TLS.HTTPSPort > 0 {
		set[c.TLS.HTTPSPort] = struct{}{}
	}
	for _, r := range c.Routes {
		if !r.enabled() {
			continue
		}
		if r.ListenPort > 0 {
			set[r.ListenPort] = struct{}{}
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func (r RouteConfig) enabled() bool { return r.Enabled == nil || *r.Enabled }

// ---------- 配置文件写入 ----------

// revisionOf 用文件字节的 sha256 作为配置版本号，供 ETag / If-Match 做乐观并发。
// 用它而不是 mtime：mtime 精度可能只有秒，同一秒内两次修改会撞车。
func revisionOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// saveConfig 原子写回配置文件：
//
//  1. 把现有内容备份到 <path>.bak
//  2. 写同目录临时文件并 fsync（保证内容真的落盘）
//  3. rename 覆盖 —— POSIX 上原子；Windows 上 Go 走 MoveFileEx 也是替换语义
//
// 直接截断重写是不可接受的：写到一半断电就会留下一个解析不了的配置，
// 而进程重启后读的就是这个文件。
func saveConfig(path string, cfg *Config) (raw []byte, rev string, err error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("序列化配置失败: %w", err)
	}
	b = append(b, '\n')

	// 备份失败不阻断主流程，但一定要留痕
	if old, rerr := os.ReadFile(path); rerr == nil && len(old) > 0 {
		if werr := os.WriteFile(path+".bak", old, 0o644); werr != nil {
			slog.Warn("配置备份写入失败", "path", path+".bak", "err", werr)
		}
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, "", fmt.Errorf("创建临时配置文件失败: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, "", fmt.Errorf("写临时配置文件失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, "", fmt.Errorf("临时配置文件 fsync 失败: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, "", fmt.Errorf("关闭临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, "", fmt.Errorf("替换配置文件失败: %w", err)
	}
	return b, revisionOf(b), nil
}
