package main

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// 配置校验与名单辅助：validateAdminUsers / validateIPLists / validate，
// 以及 checkIPListName / knownListHint / indexIPList / listUsage。
// 从 config.go 拆出，纯机械移动，逻辑未动。
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

// validateIPLists 校验名单库，返回「名字 → 角色」的映射供路由引用检查。
//
// 单独抽出来是因为它有两个调用点：配置校验，以及「改名 / 删除」这类
// 需要先知道有哪些名字的写路径（见 admin_api.go 的 listUsage）。
func (c *Config) validateIPLists() (map[string]string, error) {
	kinds := make(map[string]string, len(c.IPLists))
	for i, d := range c.IPLists {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			return nil, fmt.Errorf("ip_lists[%d]: name 不能为空 —— 路由靠名字引用名单", i)
		}
		// 首尾空白不做静默 trim：名字是引用键，`"办公网 "` 和 `"办公网"` 是两个
		// 不同的键，静默归一化只会让「明明写了一样的名字却引用不到」更难查。
		if name != d.Name {
			return nil, fmt.Errorf("ip_lists[%d] (%q): name 首尾不能有空白", i, d.Name)
		}
		if err := checkIPListName(name); err != nil {
			return nil, fmt.Errorf("ip_lists[%d] (%s): %w", i, name, err)
		}
		if _, dup := kinds[name]; dup {
			return nil, fmt.Errorf("ip_lists[%d]: 名单名 %q 重复 —— 名字是引用键，不能重名", i, name)
		}

		kind := strings.ToLower(strings.TrimSpace(d.Kind))
		switch kind {
		case IPListKindAllow, IPListKindDeny:
		default:
			return nil, fmt.Errorf("ip_lists[%d] (%s): kind 必须是 %s|%s，当前 %q",
				i, name, IPListKindAllow, IPListKindDeny, d.Kind)
		}

		l, err := NewIPList(d.Rules)
		if err != nil {
			return nil, fmt.Errorf("ip_lists[%d] (%s): %w", i, name, err)
		}
		// 空的黑名单只是什么都不禁，没有危害，放行。
		// 空的白名单不行：它一旦被引用就表示「只允许名单内的地址」，
		// 结果是引用它的路由拒绝所有请求 —— 这是配置事故，不是意图。
		if kind == IPListKindAllow && l.Len() == 0 {
			return nil, fmt.Errorf("ip_lists[%d] (%s): 这是白名单，但一条规则都没有。"+
				"白名单一旦被路由引用就只有「只允许名单内的地址」一个含义，"+
				"空名单会让引用它的路由拒绝所有请求；先填几条地址再保存", i, name)
		}
		kinds[name] = kind
	}
	return kinds, nil
}

// checkIPListName 校验名单名可用的字符。
//
// 名单名会出现在 config.json、控制台、命中测试结果和拦截日志里。两条限制：
//   - 控制字符 / 换行：名字和规则会打进日志的同一行，一个换行就能在日志里
//     伪造出一条并不存在的记录（日志是排障时唯一可信的东西，不能让它可被配置污染）。
//   - 斜杠：名单名将来可能进 URL 路径段，带斜杠会让「按名字定位一份名单」产生歧义。
func checkIPListName(name string) error {
	if n := len([]rune(name)); n > 64 {
		return fmt.Errorf("名单名太长（%d 个字符，上限 64）", n)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("名单名里不能有控制字符或换行")
		}
		if r == '/' || r == '\\' {
			return fmt.Errorf("名单名里不能有 / 或 \\")
		}
	}
	return nil
}

// knownListHint 生成「当前可用的名单有哪些」，贴在「引用了不存在的名单」后面。
//
// 报「不存在」却不说什么存在，用户只能去翻配置文件；名单少的时候一句话就能说清。
func knownListHint(kinds map[string]string) string {
	if len(kinds) == 0 {
		return "当前一份地址列表都没有定义，请先在顶层 ip_lists 里加一份，" +
			"或到控制台「IP 名单」页签创建。"
	}
	names := make([]string, 0, len(kinds))
	for n := range kinds {
		names = append(names, n)
	}
	sort.Strings(names)
	return "当前可用的名单：" + strings.Join(names, "、") + "。"
}

// indexIPList 按名字找一份名单定义。找不到返回 -1。
//
// 名字比较沿用校验时的规则：trim 之后比，大小写敏感 —— 名单名是给人看的中文居多，
// 做大小写折叠反而会让 "Office" 和 "office" 悄悄合并，那是另一场事故。
func indexIPList(defs []IPListDef, name string) int {
	want := strings.TrimSpace(name)
	for i, d := range defs {
		if d.Name == want {
			return i
		}
	}
	return -1
}

// listUsage 统计「每份名单被哪些路由引用」，给控制台展示与删除前置检查用。
//
// 键是名单名，值是引用它的路由 ID（按配置顺序，去重）。
func listUsage(routes []RouteConfig) map[string][]string {
	out := map[string][]string{}
	for _, r := range routes {
		if r.ACL == nil {
			continue
		}
		seen := map[string]bool{}
		for _, ref := range r.ACL.Lists {
			name := strings.TrimSpace(ref)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out[name] = append(out[name], r.ID)
		}
	}
	return out
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

	// 全局黑名单里的 CIDR 也要在写盘前解析通过。
	//
	// 写接口的顺序是「先落盘、再 reload」，校验漏掉这一层的话，
	// 坏配置会先写进文件、然后 reload 才失败 —— 进程停在一个半坏的状态上，
	// 而且文件里已经留下了错误内容。
	if _, err := NewIPList(c.GlobalIPDeny); err != nil {
		return fmt.Errorf("global_ip_deny: %w", err)
	}

	// 名单库先校验。路由的引用要拿它的结论来查，顺序反了就会把
	// 「名单本身写错了」报成「引用了不存在的名单」，指错方向。
	listKinds, err := c.validateIPLists()
	if err != nil {
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
			// 引用必须存在。校验放在这里而不是「用到时才报错」：
			// 写接口的顺序是先落盘再 reload，漏了这一步就会先把悬空引用写进
			// 文件、再在 reload 阶段失败，进程停在一个半坏的状态上。
			//
			// 这里刻意不「自动忽略不认识的引用」：一条 allow 名单引用写错名字
			// 就等于「不限制来源」，那是一次无声的放行 —— 和白名单效力有关的事情
			// 一律 fail-closed。
			for _, ref := range acl.Lists {
				name := strings.TrimSpace(ref)
				if name == "" {
					return fmt.Errorf("routes[%d] (%s): acl.lists 里有空名字", i, r.ID)
				}
				if _, ok := listKinds[name]; !ok {
					return fmt.Errorf("routes[%d] (%s): acl.lists 引用了不存在的名单 %q。%s",
						i, r.ID, name, knownListHint(listKinds))
				}
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
