package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
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

	// AdminToken 管理接口的访问令牌。
	// 从回环地址访问时不需要它；一旦管理端口监听了非回环地址，
	// 没有它所有外部请求一律拒绝 —— 这是防止管理接口裸奔的唯一闸门。
	AdminToken string `json:"admin_token,omitempty"`

	AccessLog bool `json:"access_log"`
	// TrustedProxies 里的项是 IP 或 CIDR。
	TrustedProxies []string      `json:"trusted_proxies,omitempty"`
	Routes         []RouteConfig `json:"routes"`
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

func (c *Config) validate() error {
	// trusted_proxies 每一项必须是 IP 或 CIDR。不在这里拦，
	// 写接口就会先把坏配置落盘、再在 reload 阶段失败。
	if _, err := c.trustedNets(); err != nil {
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
func (c *Config) allListenPorts() []int {
	set := make(map[int]struct{})
	for _, p := range c.DefaultPorts {
		if p > 0 && p <= 65535 {
			set[p] = struct{}{}
		}
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
