package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	// GlobalIPDeny 是全局黑名单：命中的来源在**所有**入口上一律拒绝，
	// 包括管理端口，也不受任何路由白名单的豁免。
	//
	// 它是三层名单里优先级最高的一层（见 acl.go 的 decideIP）。典型用途是
	// 发现攻击源之后立刻全网封禁 —— 紧急处置时不该还要逐个路由核对
	// 「我到底封干净了没有」。
	//
	// 留空/nil 表示没有全局封禁。写成 [] 也合法（等于没配），
	// 与白名单不同：空白名单会让所有人都进不来，是配置错误；
	// 空黑名单只是什么都不禁，没有危害。
	//
	// 注意它**作用于管理端口**。因此在控制台里保存一条会挡住自己的规则是
	// 危险的，写接口会先做一次自检并拒绝（见 admin_api.go 的 guardSelfLockout）。
	// 万一从别的途径写死了，仍然可以在本机用 goproxy -config-export 导出配置、
	// 改完再 -config-import 导回并重启来恢复。
	GlobalIPDeny []IPRule `json:"global_ip_deny,omitempty"`

	// IPLists 是可复用的命名地址列表库。
	//
	// 为什么要有它：路由级的白名单 / 黑名单以前只能内联写在每条路由里，
	// 于是「办公网」这一段网段会在 5 条路由里各写一遍 —— 改一次要改 5 处，
	// 漏一处就是一条路由的防护没跟上，而且肉眼看不出哪条漏了。
	// 现在地址列表建一次、路由按名字引用，改一处全场生效。
	//
	// 每条列表自带 kind（allow / deny），也就是**角色定义在列表上**：
	// 同一条列表在所有路由里扮演同一个角色，读配置时不必回到引用点去猜。
	// 想实现「A 路由把它当白名单、B 路由当黑名单」这种需求，就建两条同名不同
	// 前缀的列表 —— 那是两件不同的事，本就该是两个名字。
	//
	// 注意全局黑名单**不**在这里：它仍然只有一份内联的 GlobalIPDeny。
	// 全局名单作用于所有入口（含管理端口），是「紧急封禁」用的单一开关，
	// 拆成多份反而会让「我到底封干净了没有」这个最要紧的问题变难回答。
	IPLists []IPListDef `json:"ip_lists,omitempty"`

	// TLS 是全局 TLS/ACME 配置。默认 enabled=false，即完全保持历史行为：
	// 所有端口跑明文 HTTP。打开后路由默认走 ACME 自动证书，可逐条覆盖。
	TLS TLSConfig `json:"tls,omitzero"`

	Routes []RouteConfig `json:"routes"`

	// baseDir 是配置数据库所在的目录，不序列化。
	//
	// 存它是为了解析证书文件里的相对路径：进程的工作目录取决于怎么启动的
	// （systemd 是 /、docker 是 /、手动是当前目录），拿它当基准太不稳，
	// 相对配置库所在目录才符合直觉。
	//
	// 换成 SQLite 之前这里存的是「配置文件路径」，取它的 Dir 当基准 ——
	// 规则没变，只是基准物从 config.json 变成了 goproxy.db。
	baseDir string `json:"-"`
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
	// ACL 是这条路由引用的地址列表，不配则不按 IP 限制。
	//
	// 规则本身写在顶层的 ip_lists 里，这里只放名字。这样一个网段
	// 只需要维护一处，改完对所有引用它的路由一起生效。
	ACL *RouteACLConfig `json:"acl,omitempty"`
}

type RouteAuthConfig struct {
	// Mode: none（默认）| basic | jwt
	Mode  string           `json:"mode"`
	Realm string           `json:"realm"`
	Basic []BasicAuthEntry `json:"basic"`
	JWT   *JWTConfig       `json:"jwt"`
}

// 地址列表的两种角色。取值直接进 JSON，所以是短横线风格的英文小写。
const (
	// IPListKindAllow 白名单：**一旦被路由引用就只有一个含义 —— 只允许名单内的地址**。
	// 它是在收紧范围，不是在额外放行，所以不存在「和黑名单谁优先」的问题。
	IPListKindAllow = "allow"
	// IPListKindDeny 黑名单：在允许的范围内再剔掉若干地址。
	IPListKindDeny = "deny"
)

// IPListDef 是一份可复用的命名地址列表。
//
//	"ip_lists": [
//	  {"name": "办公网", "kind": "allow", "rules": ["10.0.0.0/8", {"cidr": "10.1.2.3", "note": "临时接入"}]},
//	  {"name": "爬虫",   "kind": "deny",  "rules": [{"cidr": "203.0.113.66", "note": "扫目录"}]}
//	]
//
// 注意 rules 里的字符串简写**只放地址本身**，备注要写就得用对象形式：
// 简写是整串当 CIDR 解析的，"203.0.113.66 扫目录" 会被当成一个非法地址
// （解析报错，而不是「把后半截当备注」）。
//
// Name 既是显示名也是引用键（路由的 acl.lists 里写的就是它）。用名字当键
// 而不是引入一套 id：配置文件是给人读的，"lists": ["办公网"] 比 "lists": ["l-3f2a"]
// 有用得多。代价是改名会牵动引用 —— 写接口为此提供了 ip_list_renames，
// 改名时由服务端把路由里的引用一起改写掉，所以控制台里改名永远是原子的。
//
// Rules 用 IPRule 而不是 []string：条目可以带备注，备注会出现在命中依据和
// 拦截日志里，回答「这个地址当初到底是为什么被封的」。
type IPListDef struct {
	Name string `json:"name"`
	// Kind 只能是 allow 或 deny。空串会在 validate 阶段被拒 ——
	// 不给默认值是因为默认成哪个都是猜，而猜错的后果是这个地址段被放行。
	Kind  string   `json:"kind"`
	Rules []IPRule `json:"rules,omitempty"`
}

// RouteACLConfig 是一条路由对地址列表的**引用**。
//
// v0.8.0 起只保留引用，不再支持内联写规则（旧的内联写法会被
// rejectLegacyACL 明确拦下，附迁移映射）。理由是内联和引用并存时，
// 「这条路由到底受哪几条规则管」要同时看两处，而漏看一处的后果是防护失效。
//
// 一份都不引用（Lists 为空）表示这条路由不做 IP 限制。
type RouteACLConfig struct {
	// Lists 是引用到的名单名，可以多个 —— 同一层的多份名单取并集。
	//
	// 两层的语义（判定顺序见 acl.go 的 decideIP）：
	//   allow 的名单们 → 划范围：至少命中其中之一才继续往下走
	//   deny  的名单们 → 开例外：命中任意一份就拒绝
	// 角色由名单自己的 kind 决定，引用点不重复声明，所以不会出现
	// 「同一份名单在 A 路由是白名单、在 B 路由是黑名单」这种要对照两处才看得懂的配置。
	Lists []string `json:"lists,omitempty"`
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

// readConfigFile 读出「可运行的」配置（默认值已补齐），并同时返回它的
// 规范化 JSON 字节 —— ETag 就是这份字节的哈希。
//
// 名字里的 File 是历史遗留：v0.9.0 起配置源是 SQLite，path 指的是数据库
// 文件。保留函数名与签名是为了让下游（reload、管理接口、各测试）一行不用改，
// 换的只是最底下那一层。
func readConfigFile(path string) (raw []byte, cfg *Config, err error) {
	raw, cfg, err = parseConfigFile(path)
	if err != nil {
		return nil, nil, err
	}
	// 两份默认值都要补：漏掉 applyRouteDefaults 的话，
	// 配置里少写 path_prefix 的路由会直接加载失败。
	cfg.applyTopDefaults()
	cfg.applyRouteDefaults()
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	return raw, cfg, nil
}

// parseConfigFile 读出配置，但**不补默认值、不做校验**。
// 管理接口的写路径靠它拿到「库里的原始内容」，改完之后自己补默认值再校验。
//
// 返回的 raw 是从表里组装出来的规范化 JSON，不是磁盘上的原始字节 ——
// 这反而是个改进：同一个语义的配置无论经过几次读写，算出的 revision 都一样。
func parseConfigFile(path string) (raw []byte, cfg *Config, err error) {
	st, err := storeFor(path)
	if err != nil {
		return nil, nil, err
	}
	raw, cfg, err = st.read()
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			return nil, nil, fmt.Errorf(
				"配置数据库 %s 里还没有任何配置。首次使用请导入一份配置："+
					"goproxy -config-import <config.json>，或把 config.json 放在它旁边后重启"+
					"（只在库为空时导入一次）", path)
		}
		return nil, nil, err
	}
	return raw, cfg, nil
}

// parseConfigJSON 从 JSON 字节解析配置：反序列化 + 旧写法拦截，不碰存储。
//
// 导入路径（首次种子、命令行 -config-import）和控制台示例配置的测试都走它 ——
// 这些场景手里就是一份 JSON，不该被拖去开数据库。
func parseConfigJSON(raw []byte) (*Config, error) {
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 JSON 失败: %w", err)
	}
	// 旧写法必须在这里就拦住，不能等到用了才发现在静默失效。
	if err := rejectLegacyACL(raw); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectLegacyACL 拦住两种已经不再支持的旧 acl 写法，并给出迁移映射：
//
//	v0.6.x  acl.mode + acl.cidrs      —— mode 二选一（要么白名单要么黑名单）
//	v0.7.x  acl.allow / acl.deny      —— 内联写规则，两份可并存
//	v0.8.0+ acl.lists                 —— 只引用顶层 ip_lists 里的命名名单
//
// 为什么必须显式报错，而不是让不认识的字段静默落空：旧配置里 acl.mode=allow
// 表达的是一条**白名单**。新结构没有 mode 字段，静默忽略的后果是白名单不再生效、
// 所有来源都能访问 —— 这是一次无声的安全降级。配置文件还在、启动日志也不报错，
// 但防护已经没了，比启动失败危险得多。
//
// 内联写法（allow / deny）同理：它们的规则**不会**被自动搬到 ip_lists 里去。
// 自动搬运要替用户决定「这份规则该叫什么名字」「多条路由里一样的规则要不要
// 合并成一份」，猜错了用户还得去猜系统猜的是什么。宁可在这里停下来说清楚。
//
// 纯 mode=none 且没有 cidrs 的残留是空操作（新结构里删掉即可），
// 这种情况放行，免得为一行无意义的遗留卡住升级。
func rejectLegacyACL(raw []byte) error {
	var probe struct {
		Routes []struct {
			ID  string `json:"id"`
			ACL *struct {
				Mode  *string          `json:"mode"`
				CIDRs *[]string        `json:"cidrs"`
				Allow *json.RawMessage `json:"allow"`
				Deny  *json.RawMessage `json:"deny"`
			} `json:"acl"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil // 解析失败会有更准确的报错，不在这里抢答
	}
	for i, r := range probe.Routes {
		if r.ACL == nil {
			continue
		}
		id := r.ID
		if id == "" {
			id = "未命名"
		}

		// v0.6.x：mode 二选一 + cidrs
		mode := ""
		if r.ACL.Mode != nil {
			mode = strings.ToLower(strings.TrimSpace(*r.ACL.Mode))
		}
		hasCIDRs := r.ACL.CIDRs != nil && len(*r.ACL.CIDRs) > 0
		if hasCIDRs || (mode != "" && mode != "none") {
			return fmt.Errorf("routes[%d] (%s): acl.mode / acl.cidrs 是 v0.6.x 的旧写法，"+
				"早已不再支持。三代的写法是：\n"+
				"      v0.6.x  acl.mode=allow|deny + acl.cidrs   二选一\n"+
				"      v0.7.x  acl.allow / acl.deny               内联规则，两份可并存\n"+
				"      v0.8.0  acl.lists                          只引用命名名单（当前）\n"+
				"    迁移到当前写法：先在顶层 ip_lists 里建一份名单，再让路由引用它 ——\n"+
				"      \"ip_lists\": [{\"name\": \"办公网\", \"kind\": \"allow\", \"rules\": [\"10.0.0.0/8\"]}],\n"+
				"      \"routes\": [{\"id\": \"%s\", \"acl\": {\"lists\": [\"办公网\"]}}]\n"+
				"    在控制台「IP 名单」页建好名单，再让路由引用它也一样。",
				i, id, id)
		}

		// v0.7.x：内联的 allow / deny
		// 用 *json.RawMessage 是为了区分「文件里写了 allow」和「压根没这个键」——
		// 写成 [] 也算写了（那正是「谁都进不来」的事故写法，更不能放过）。
		if r.ACL.Allow != nil || r.ACL.Deny != nil {
			which := "acl.allow"
			if r.ACL.Allow == nil {
				which = "acl.deny"
			} else if r.ACL.Deny != nil {
				which = "acl.allow / acl.deny"
			}
			return fmt.Errorf("routes[%d] (%s): %s 是 v0.7.x 的内联写法，"+
				"v0.8.0 起路由只能**引用**顶层 ip_lists 里的命名名单。迁移映射：\n"+
				"      acl.allow: [...]  →  ip_lists 里建一份 kind=\"allow\" 的名单，再在 acl.lists 里写它的名字\n"+
				"      acl.deny:  [...]  →  同理，kind=\"deny\"\n"+
				"    例：\n"+
				"      \"ip_lists\": [\n"+
				"        {\"name\": \"办公网\", \"kind\": \"allow\", \"rules\": [\"10.0.0.0/8\"]},\n"+
				"        {\"name\": \"爬虫\",   \"kind\": \"deny\",  \"rules\": [\"203.0.113.66\"]}\n"+
				"      ],\n"+
				"      \"routes\": [{\"id\": \"%s\", \"acl\": {\"lists\": [\"办公网\", \"爬虫\"]}}]\n"+
				"    这样做的好处：同一段网段只维护一处，改完对所有引用它的路由一起生效。\n"+
				"    顶层 global_ip_deny（全局黑名单）写法不变，仍是一份内联规则。\n"+
				"    在控制台「IP 名单」页建好名单，再让路由引用它也一样。",
				i, id, which, id)
		}
	}
	return nil
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

// ---------- 配置写入 ----------

// revisionOf 用配置字节的 sha256 作为配置版本号，供 ETag / If-Match 做乐观并发。
// 用它而不是 mtime：mtime 精度可能只有秒，同一秒内两次修改会撞车。
func revisionOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// saveConfig 把整份配置写进数据库，返回写入后的规范化字节与版本号。
//
// v0.9.0 起这件事是**一个事务**：以前「备份到 .bak → 写 .tmp → fsync →
// rename 覆盖」是靠这段代码手工拼出来的原子性，现在由数据库保证，
// 顺带把「历史版本」从一份 .bak 变成了可回溯的若干份。
//
// 签名与返回值保持原样：调用方（mutate）拿 raw 做回滚、拿 rev 回给客户端。
func saveConfig(path string, cfg *Config) (raw []byte, rev string, err error) {
	st, err := storeFor(path)
	if err != nil {
		return nil, "", err
	}
	return st.write(cfg)
}
