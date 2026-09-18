package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

/* ==================== 名单条目 ==================== */

// IPRule 是名单里的一条：一段 CIDR（或单个 IP）+ 可选备注。
//
// 配置里支持两种写法，为的是手工编辑配置文件时不啰嗦：
//
//	"global_ip_deny": ["203.0.113.0/24", {"cidr": "198.51.100.7", "note": "爬虫"}]
//
// 备注只影响展示与排查：它会出现在命中测试的「命中依据」和拦截日志里，
// 用来回答「这个 IP 当初到底是为什么被封的」。
type IPRule struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

// UnmarshalJSON 接受字符串简写与 {cidr, note} 两种形式。
func (r *IPRule) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		r.CIDR, r.Note = s, ""
		return nil
	}
	// 用别名类型避免无限递归回自己。
	type plain IPRule
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("ip 条目既不是字符串，也不是 {cidr, note} 对象：%s",
			strings.TrimSpace(string(b)))
	}
	*r = IPRule(p)
	return nil
}

// MarshalJSON 在没有备注时写回字符串简写。
//
// 不这么做的话，一次控制台保存就会把 ["10.0.0.0/8"] 膨胀成
// [{"cidr":"10.0.0.0/8"}]，配置文件越存越长、越读越难。
func (r IPRule) MarshalJSON() ([]byte, error) {
	if r.Note == "" {
		return json.Marshal(r.CIDR)
	}
	type plain IPRule
	return json.Marshal(plain(r))
}

/* ==================== 名单 ==================== */

// ipEntry 是解析后的一条规则。
type ipEntry struct {
	net  *net.IPNet
	raw  string // 配置里写的原始写法，回显用
	note string
}

// IPList 是一份解析好的 IP 名单。
//
// nil 指针与「空名单」是两件不同的事，调用方必须区分：
//   - nil / 没配置白名单 → 不限制
//   - 配了白名单但是空的 → 谁都进不来（属于配置错误，validate 阶段就报错）
type IPList struct {
	entries []ipEntry
}

// NewIPList 解析一组规则。传 nil 返回 nil（=「这份名单没配置」），
// 传空切片返回一个空名单（=「显式配了，但一条都没有」）。
func NewIPList(rules []IPRule) (*IPList, error) {
	if rules == nil {
		return nil, nil
	}
	l := &IPList{}
	for i, r := range rules {
		c := strings.TrimSpace(r.CIDR)
		if c == "" {
			return nil, fmt.Errorf("第 %d 条 ip 规则的 cidr 不能为空", i+1)
		}
		n, err := parseCIDROrIP(c)
		if err != nil {
			return nil, fmt.Errorf("第 %d 条 ip 规则 %q：%w", i+1, c, err)
		}
		l.entries = append(l.entries, ipEntry{
			net:  n,
			raw:  c,
			note: strings.TrimSpace(r.Note),
		})
	}
	return l, nil
}

// parseCIDROrIP 接受 CIDR，也接受单个 IP（自动补成 /32 或 /128）。
//
// 单 IP 按 v4 归一化后再建网段：直接拿 ParseIP 的 16 字节表示配 4 字节掩码
// 虽然也能工作，但依赖 net 包的内部兜底，写清楚更省心。
func parseCIDROrIP(s string) (*net.IPNet, error) {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("既不是 IP 也不是 CIDR")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// IPMatch 说明命中了名单里的哪一条。
type IPMatch struct {
	Rule string // 配置里写的原始写法，比如 10.0.0.0/8
	Note string
}

// Match 返回第一条命中的规则。IP 列表很短（通常是几条到几十条），
// 线性扫描比维护 radix tree 划算得多。
func (l *IPList) Match(ip net.IP) (IPMatch, bool) {
	if l == nil || ip == nil {
		return IPMatch{}, false
	}
	for _, e := range l.entries {
		if e.net.Contains(ip) {
			return IPMatch{Rule: e.raw, Note: e.note}, true
		}
	}
	return IPMatch{}, false
}

// Len 返回条目数。nil 名单算 0 条。
func (l *IPList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

/* ==================== 路由级名单 ==================== */

// ACL 是一条路由上的 IP 名单：白名单与黑名单**并存**。
//
// 这是 v0.7.0 与之前最大的不同。v0.6.x 的 acl 只有 mode 二选一，
// 想「只允许办公网、但把办公网里的一台机器剔掉」就表达不出来；
// 现在 allow 负责收紧范围，deny 负责在范围内开例外。
type ACL struct {
	allow *IPList
	deny  *IPList
}

// NewACL 解析路由级名单。两边都没配时返回 nil，表示这条路由不做 IP 限制。
func NewACL(c *RouteACLConfig) (*ACL, error) {
	if c == nil {
		return nil, nil
	}
	a, err := NewIPList(c.Allow)
	if err != nil {
		return nil, fmt.Errorf("acl.allow: %w", err)
	}
	d, err := NewIPList(c.Deny)
	if err != nil {
		return nil, fmt.Errorf("acl.deny: %w", err)
	}
	if a == nil && d == nil {
		return nil, nil
	}
	return &ACL{allow: a, deny: d}, nil
}

// allowList / denyList 是 nil 安全的访问器。
//
// 直接写 route.deny 在 route 为 nil 时会 panic —— 而 nil 恰好是最常见的
// 情况（这条路由根本没配名单）。字段本身是 *IPList、方法也都处理了 nil 接收者，
// 但「从一个 nil 的 *ACL 上读字段」这一步就已经炸了。
func (a *ACL) allowList() *IPList {
	if a == nil {
		return nil
	}
	return a.allow
}

func (a *ACL) denyList() *IPList {
	if a == nil {
		return nil
	}
	return a.deny
}

// hasAllow 报告是否配置了白名单（用于判定「要不要做未命中即拒绝」）。
func (a *ACL) hasAllow() bool { return a.allowList() != nil }

/* ==================== 判定 ==================== */

// 拦截原因标签。取值直接进访问日志的 blocked 字段和指标的 rejected label，
// 所以刻意做成短横线风格、且每一层一个，排查时能一眼看出是谁拦的。
const (
	reasonACLGlobalDeny = "acl_global_deny"
	reasonACLAllowMiss  = "acl_route_allow_miss"
	reasonACLRouteDeny  = "acl_route_deny"
)

// 层名。给人和给界面看，日志与命中测试共用，避免各处各写一套中文。
const (
	layerGlobalDeny = "全局黑名单"
	layerAllow      = "白名单"
	layerDeny       = "黑名单"
)

// ACLStep 是判定过程中一层的结果，只有命中测试会带上。
type ACLStep struct {
	Layer      string `json:"layer"`
	Configured bool   `json:"configured"`
	Matched    bool   `json:"matched"`
	Rule       string `json:"rule,omitempty"`
	Note       string `json:"note,omitempty"`
	Detail     string `json:"detail"`
}

// ACLDecision 是一次判定的完整结论。
//
// 把「命中的是哪条规则、它带着什么备注、给日志用哪个短标签、给人看哪句话」
// 全都填好，是为了让调用方（请求管线、命中测试接口、未来的界面）
// 不用各自再拼一遍字符串 —— 那种重复最终一定会走样。
type ACLDecision struct {
	IP      string `json:"ip"`
	Allowed bool   `json:"allowed"`

	// 命中拦下的那一层；放行时为空。
	Layer string `json:"layer,omitempty"`
	// 命中的具体规则与它的备注。
	Rule string `json:"rule,omitempty"`
	Note string `json:"note,omitempty"`
	// Reason 是给 blocked / 指标用的短标签，放行时为空。
	Reason string `json:"reason,omitempty"`
	// Message 是给人看的一句话。
	Message string `json:"message"`
	// Steps 只有命中测试会填。
	Steps []ACLStep `json:"steps,omitempty"`

	// RouteID 只在命中测试里出现，说明这次判定套用的是哪条路由的名单。
	RouteID string `json:"route_id,omitempty"`
}

// decideIP 是三层名单的唯一判定入口。顺序即约定，不可随意调整：
//
//	① 全局黑名单命中           → 拒绝，任何白名单都不能豁免
//	② 白名单已配置且未命中     → 拒绝
//	③ 路由黑名单命中           → 拒绝
//	④ 放行
//
// 为什么全局黑名单要放在最前面且不可豁免：它的典型用途是「发现攻击源，
// 立刻全网封禁」。如果某个路由的白名单能把它捞回来，运维就得逐个路由
// 去核对「我到底封干净了没有」—— 那正是紧急处置时最不该花的时间。
//
// 为什么白名单在前、黑名单在后而不是二选一：两者的语义不冲突。
// 白名单回答「范围有多大」，黑名单回答「范围内哪些要剔掉」。
// 先判范围、再判例外，就不存在「谁优先」的歧义。
//
// trace 为 true 时填充 Steps，供命中测试展示；热路径传 false 以免
// 每个请求都白建一个切片。
func decideIP(global *IPList, route *ACL, ipStr string, trace bool) ACLDecision {
	d := ACLDecision{IP: ipStr}
	var steps []ACLStep

	// 解析不出 IP（比如 Unix socket、或 header 被写坏）时不能装作放行：
	// 白名单一旦启用就必须按「不在名单内」处理，这是 fail-closed。
	ip := net.ParseIP(ipStr)

	addStep := func(s ACLStep) {
		if trace {
			steps = append(steps, s)
		}
	}

	// ① 全局黑名单
	if m, ok := global.Match(ip); ok {
		d.Allowed, d.Layer, d.Rule, d.Note = false, layerGlobalDeny, m.Rule, m.Note
		d.Reason = reasonACLGlobalDeny
		d.Message = fmt.Sprintf("命中全局黑名单 %s%s，该规则对全部路由生效，白名单也无法豁免。",
			m.Rule, noteSuffix(m.Note))
		addStep(ACLStep{Layer: layerGlobalDeny, Configured: true, Matched: true,
			Rule: m.Rule, Note: m.Note, Detail: "命中，判定结束"})
		d.Steps = steps
		return d
	}
	addStep(ACLStep{Layer: layerGlobalDeny, Configured: global != nil, Matched: false,
		Detail: listDetail(global, "未命中")})

	// ② 白名单：只在配置了的时候才判。
	// 没配白名单 = 不限制，绝不能理解成「空白名单放行谁都不行」。
	if allow := route.allowList(); allow != nil {
		if m, ok := allow.Match(ip); ok {
			addStep(ACLStep{Layer: layerAllow, Configured: true, Matched: true,
				Rule: m.Rule, Note: m.Note, Detail: "在白名单内，继续判黑名单"})
		} else {
			d.Allowed, d.Layer, d.Reason = false, layerAllow, reasonACLAllowMiss
			d.Message = fmt.Sprintf("白名单已启用（%d 条规则），这个地址不在名单内。", allow.Len())
			addStep(ACLStep{Layer: layerAllow, Configured: true, Matched: false,
				Detail: listDetail(allow, "未命中")})
			d.Steps = steps
			return d
		}
	} else {
		addStep(ACLStep{Layer: layerAllow, Configured: false, Matched: false,
			Detail: "未配置白名单，不限制来源"})
	}

	// ③ 路由黑名单
	deny := route.denyList()
	if m, ok := deny.Match(ip); ok {
		d.Allowed, d.Layer, d.Rule, d.Note = false, layerDeny, m.Rule, m.Note
		d.Reason = reasonACLRouteDeny
		d.Message = fmt.Sprintf("命中本路由黑名单 %s%s。", m.Rule, noteSuffix(m.Note))
		addStep(ACLStep{Layer: layerDeny, Configured: true, Matched: true,
			Rule: m.Rule, Note: m.Note, Detail: "命中，判定结束"})
		d.Steps = steps
		return d
	}
	addStep(ACLStep{Layer: layerDeny, Configured: deny != nil, Matched: false,
		Detail: listDetail(deny, "未命中")})

	d.Allowed = true
	d.Message = "三层名单都没有拦下这个地址。"
	d.Steps = steps
	return d
}

// noteSuffix 把备注拼成「（说明）」的形式；没有备注就返回空串。
func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return "（" + note + "）"
}

// listDetail 生成「N 条规则，未命中」或「未配置」这样的说明。
func listDetail(l *IPList, miss string) string {
	if l == nil {
		return "未配置"
	}
	return fmt.Sprintf("%d 条规则，%s", l.Len(), miss)
}
