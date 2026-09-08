package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Config 是配置文件的顶层结构。
// demo 阶段用 JSON 文件做配置源；正式版换成 SQLite 时，只需要替换
// loadConfig 的实现，下游的 buildTable / Route 结构完全不用动。
type Config struct {
	// DefaultPorts 是必定监听的端口，即使没有任何路由引用它们。
	// 默认 [80]。业务端口由路由的 listen_port 自动派生，不需要写在这里。
	DefaultPorts []int `json:"default_ports"`

	// AdminAddr 管理端口，建议只监听 127.0.0.1。留空则禁用。
	AdminAddr string `json:"admin_addr"`

	AccessLog      bool          `json:"access_log"`
	TrustedProxies []string      `json:"trusted_proxies"`
	Routes         []RouteConfig `json:"routes"`
}

type RouteConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Enabled 为 nil 时视为 true
	Enabled *bool `json:"enabled"`

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

	RateLimit *RateLimitConfig `json:"rate_limit"`
}

type RateLimitConfig struct {
	RPS   float64 `json:"rps"`
	Burst float64 `json:"burst"`
	// Scope: ip（默认，按客户端 IP）/ global（整条路由共享一个桶）
	Scope string `json:"scope"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if len(c.DefaultPorts) == 0 {
		c.DefaultPorts = []int{80}
	}
	if c.AdminAddr == "" {
		c.AdminAddr = "127.0.0.1:8080"
	}
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

func (c *Config) validate() error {
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
