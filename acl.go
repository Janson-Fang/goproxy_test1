package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
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

/* ==================== 命名名单库 ==================== */

// NamedList 是一份解析好的命名名单。
type NamedList struct {
	// Name 是名单名，也是路由引用它时用的键。
	Name string
	// Kind 是 IPListKindAllow / IPListKindDeny。
	Kind string
	// List 是解析好的规则集。Rules 为空时这里是 nil（Len() 算 0 条）。
	List *IPList
}

// IPListSet 是解析好的名单库，供路由按名字引用。
//
// 为什么要有这一层、而不是让每条路由各自去 cfg.IPLists 里现查现解析：
//   - 解析 CIDR 不便宜（每条规则一次 net.ParseCIDR），而一份名单通常被好几条
//     路由引用，每条路由各解析一遍是纯重复劳动；
//   - 更要紧的是「同一份名单在不同路由里得到不同的解析结果」这种事根本不该
//     有可能发生。构建一次再分发，这个可能性从结构上就不存在了。
type IPListSet struct {
	byName map[string]NamedList
}

// NewIPListSet 解析配置里的名单库。defs 为空时返回一个空集合（不是 nil）——
// 调用方不必为了「没有名单」多写一个分支。
func NewIPListSet(defs []IPListDef) (*IPListSet, error) {
	s := &IPListSet{byName: make(map[string]NamedList, len(defs))}
	for i, d := range defs {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			return nil, fmt.Errorf("ip_lists[%d]: name 不能为空 —— 路由靠名字引用名单", i)
		}
		kind := strings.ToLower(strings.TrimSpace(d.Kind))
		if kind != IPListKindAllow && kind != IPListKindDeny {
			return nil, fmt.Errorf("ip_lists[%d] (%s): kind 必须是 %s|%s，当前 %q",
				i, name, IPListKindAllow, IPListKindDeny, d.Kind)
		}
		l, err := NewIPList(d.Rules)
		if err != nil {
			return nil, fmt.Errorf("ip_lists[%d] (%s): %w", i, name, err)
		}
		s.byName[name] = NamedList{Name: name, Kind: kind, List: l}
	}
	return s, nil
}

// Len 返回名单份数。
func (s *IPListSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byName)
}

// Names 返回全部名单名（未排序，调用方要稳定顺序请自行排序）。
func (s *IPListSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byName))
	for n := range s.byName {
		out = append(out, n)
	}
	return out
}

// Resolve 把一条路由的引用展开成判定用的 ACL。
//
// refs 为空（或全是空白）时返回 (nil, nil)，表示这条路由不做 IP 限制。
// 注意这与「引用了名单但它没拦住」是两件完全不同的事：nil 是「不设防」，
// 而只要引用了任意一份白名单，就必须命中其中之一才放行。
//
// 重复引用同一个名字会被静默去重：一份名单引用两次和一次的结果完全一样，
// 为此报错只会让用户去删一个无意义的重复项。
func (s *IPListSet) Resolve(refs []string) (*ACL, error) {
	// 允许 nil 接收者：写路径上有「配置里压根没有 ip_lists」这条分支，
	// 那里 set 就是 nil。让它在这里退化成一个空集合，比要求每个调用点
	// 都先判一次空要少一个漏判的机会（而漏判的表现是 panic）。
	var byName map[string]NamedList
	if s != nil {
		byName = s.byName
	}

	acl := &ACL{}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true

		nl, ok := byName[name]
		if !ok {
			// 走到这里说明配置文件绕过了 validate（比如手工改坏）。
			// 报「不存在」而不是当成空名单：一条 allow 引用写错名字如果被当成
			// 「空名单」，结果会是拒绝所有人（fail-closed，安全但满屏 403 且看不出原因）；
			// 如果被当成「没配」，那就是静默放行所有人。两种都不能猜，只能报错。
			return nil, fmt.Errorf("引用了不存在的名单 %q（%s）", name, s.describe())
		}
		if nl.Kind == IPListKindAllow {
			if nl.List.Len() == 0 {
				return nil, fmt.Errorf("白名单 %q 是空的：它一旦被引用就只有「只允许名单内的地址」"+
					"一个含义，空名单会让这条路由拒绝所有请求", name)
			}
			acl.allow = append(acl.allow, nl)
		} else {
			acl.deny = append(acl.deny, nl)
		}
	}
	if len(acl.allow) == 0 && len(acl.deny) == 0 {
		return nil, nil
	}
	return acl, nil
}

// describe 生成「已定义的名单有：A、B」这样的说明，附在「引用了不存在的名单」后面。
func (s *IPListSet) describe() string {
	if s.Len() == 0 {
		return "当前一份地址列表都没定义"
	}
	names := s.Names()
	sort.Strings(names)
	return "已定义的名单：" + strings.Join(names, "、")
}

/* ==================== 路由级名单 ==================== */

// resolveRouteACL 把一条路由的 acl 引用展开成判定用的 ACL。
//
// 单独抽一层是因为「没引用任何名单」这个最常见的情况要返回 nil，
// 而 nil 与「引用了、但一份都没拦住」在判定里是两件必须区分的事：
// 前者不设防，后者在引用白名单时会直接拒绝所有人。
func resolveRouteACL(set *IPListSet, rc RouteConfig) (*ACL, error) {
	if rc.ACL == nil || len(rc.ACL.Lists) == 0 {
		return nil, nil
	}
	return set.Resolve(rc.ACL.Lists)
}

// ACL 是一条路由**展开后**的名单：按角色分成两组，每组可以有多份命名名单。
//
// 组的语义（顺序即约定，见 decideIP）：
//
//	allow 组  白名单，负责划范围：至少命中组内某一份才继续往下走。
//	          它是在收紧来源，不是在额外放行 —— 所以不存在「和黑名单谁优先」的问题。
//	deny  组  黑名单，负责开例外：命中组内任意一份就拒绝。
//
// 一组可以有多份名单，取并集。这正是命名列表的价值所在：
// 「只允许办公网 + 只允许内网跳板」是两条独立的名单，各自维护，
// 一条路由同时引用它们，不必把两个网段抄进同一个地方。
type ACL struct {
	allow []NamedList
	deny  []NamedList
}

// allowLists / denyLists 是 nil 安全的访问器。
//
// 直接写 route.allow 在 route 为 nil 时会 panic —— 而 nil 恰好是最常见的
// 情况（这条路由根本没引用任何名单）。切片本身就处理了 nil 接收者，
// 但「从一个 nil 的 *ACL 上读字段」这一步就已经炸了。
func (a *ACL) allowLists() []NamedList {
	if a == nil {
		return nil
	}
	return a.allow
}

func (a *ACL) denyLists() []NamedList {
	if a == nil {
		return nil
	}
	return a.deny
}

// hasAllow 报告是否引用了白名单（用于判定「要不要做未命中即拒绝」）。
func (a *ACL) hasAllow() bool { return len(a.allowLists()) > 0 }

// matchAny 在若干份名单里找第一条命中的，并带上是哪一份命中的。
//
// 返回值里的 NamedList 不能省：命中之后要在日志和命中测试里说清
// 「是哪份名单拦的」。只说规则（10.0.0.0/8）在有多份名单时回答不了
// 「我该去哪份名单里删掉它」。
func matchAny(lists []NamedList, ip net.IP) (NamedList, IPMatch, bool) {
	for _, nl := range lists {
		if m, ok := nl.List.Match(ip); ok {
			return nl, m, true
		}
	}
	return NamedList{}, IPMatch{}, false
}

// describeLists 把「办公网」「公司内网」拼成一段可读文本。
func describeLists(lists []NamedList) string {
	parts := make([]string, 0, len(lists))
	for _, nl := range lists {
		parts = append(parts, "「"+nl.Name+"」")
	}
	return strings.Join(parts, "、")
}

// totalRules 是这几份名单一共多少条规则。
func totalRules(lists []NamedList) int {
	n := 0
	for _, nl := range lists {
		n += nl.List.Len()
	}
	return n
}

// groupDetail 生成名单组那一层的说明，比如「「办公网」共 12 条规则，未命中」。
func groupDetail(lists []NamedList, miss string) string {
	if len(lists) == 0 {
		return "未引用"
	}
	return fmt.Sprintf("%s共 %d 条规则，%s", describeLists(lists), totalRules(lists), miss)
}

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
	Layer string `json:"layer"`
	// List 是这一层里具体命中的那份命名名单；全局黑名单命中时为空。
	// 「白名单没命中」这种整层性的结论也留空 —— 那一层可能有多份名单，
	// 说成其中某一份会冤枉它。
	List       string `json:"list,omitempty"`
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
	// List 是命中的那份**命名名单**（v0.8.0 起名单有名字了）。
	// 全局黑名单命中和「整层没配/没命中」时为空。
	List string `json:"list,omitempty"`
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
//	① 全局黑名单命中                        → 拒绝，任何白名单都不能豁免
//	② 引用了白名单，但一份都没命中          → 拒绝
//	③ 引用的黑名单里任意一份命中            → 拒绝
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
// ②③ 两层的名单是**取并集**的：多处引用同一层的多份名单，命中任意一份即算命中。
// 所以「只允许办公网 + 只允许内网跳板」就是引用两份 allow 名单，
// 各自维护、互不干扰，而不是把两个网段抄进同一个地方。
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

	// ② 白名单：只在真的引用了的时候才判。
	// 一份都没引用 = 不限制，绝不能理解成「空白名单放行谁都不行」。
	if allow := route.allowLists(); len(allow) > 0 {
		if nl, m, ok := matchAny(allow, ip); ok {
			addStep(ACLStep{Layer: layerAllow, List: nl.Name, Configured: true, Matched: true,
				Rule: m.Rule, Note: m.Note,
				Detail: fmt.Sprintf("落在名单「%s」内，继续判黑名单", nl.Name)})
		} else {
			d.Allowed, d.Layer, d.Reason = false, layerAllow, reasonACLAllowMiss
			d.Message = fmt.Sprintf("白名单已启用（%s，共 %d 条规则），这个地址不在名单内。",
				describeLists(allow), totalRules(allow))
			addStep(ACLStep{Layer: layerAllow, Configured: true, Matched: false,
				Detail: groupDetail(allow, "未命中")})
			d.Steps = steps
			return d
		}
	} else {
		addStep(ACLStep{Layer: layerAllow, Configured: false, Matched: false,
			Detail: "未引用白名单，不限制来源"})
	}

	// ③ 路由黑名单
	deny := route.denyLists()
	if nl, m, ok := matchAny(deny, ip); ok {
		d.Allowed, d.Layer, d.Rule, d.Note, d.List = false, layerDeny, m.Rule, m.Note, nl.Name
		d.Reason = reasonACLRouteDeny
		d.Message = fmt.Sprintf("命中黑名单「%s」中的 %s%s。", nl.Name, m.Rule, noteSuffix(m.Note))
		addStep(ACLStep{Layer: layerDeny, List: nl.Name, Configured: true, Matched: true,
			Rule: m.Rule, Note: m.Note, Detail: "命中，判定结束"})
		d.Steps = steps
		return d
	}
	addStep(ACLStep{Layer: layerDeny, Configured: len(deny) > 0, Matched: false,
		Detail: groupDetail(deny, "未命中")})

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
