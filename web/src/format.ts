/** 格式化小工具。集中放一起，免得每个页面各写一套，数字风格不统一。 */

import type { HoneypotPort, IPRule, RawIPRule } from './types'

const nf = new Intl.NumberFormat('zh-CN')

/** 整数千分位。 */
export function num(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '-'
  return nf.format(Math.round(v))
}

/** 百分比，入参是 0~1 的比例。 */
export function pct(v: number | null | undefined, digits = 2): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '-'
  return `${(v * 100).toFixed(digits)}%`
}

/** 毫秒。大于 1s 自动换成秒，避免出现 12345ms 这种要数零的写法。 */
export function ms(v: number | null | undefined, digits = 1): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '-'
  if (v >= 1000) return `${(v / 1000).toFixed(digits)}s`
  if (v >= 10) return `${Math.round(v)}ms`
  return `${v.toFixed(digits)}ms`
}

/** 字节数。 */
export function bytes(v: number): string {
  if (v < 1024) return `${v} B`
  const units = ['KB', 'MB', 'GB']
  let n = v / 1024
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(1)} ${units[i]}`
}

/** 秒 → 1d 2h 3m 4s。用于运行时长。 */
export function duration(secs: number | null | undefined): string {
  if (secs === null || secs === undefined || secs < 0) return '-'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = Math.floor(secs % 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

/** RFC3339 → HH:MM:SS.mmm，日志表格里只需要时刻。 */
export function clock(ts: string | undefined): string {
  if (!ts) return '-'
  const i = ts.indexOf('T')
  if (i < 0) return ts
  return ts.slice(i + 1).replace(/(\.\d{3})\d*/, '$1').replace(/(Z|[+-]\d{2}:\d{2})$/, '')
}

/** RFC3339 → 本地可读时间。 */
export function datetime(ts: string | undefined): string {
  if (!ts) return '-'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** Unix 秒 → HH:MM:SS，给曲线图的横轴用。 */
export function timeLabel(unixSecs: number): string {
  const d = new Date(unixSecs * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** 请求路径 + 查询串，查询串过长时截断。 */
export function fullPath(path: string, query?: string): string {
  if (!query) return path
  const q = query.length > 48 ? `${query.slice(0, 48)}…` : query
  return `${path}?${q}`
}

/** 状态码归类，给日志行上色用。 */
export function statusClass(status: number): 'ok' | 'redirect' | 'client' | 'server' | 'none' {
  if (status >= 500) return 'server'
  if (status >= 400) return 'client'
  if (status >= 300) return 'redirect'
  if (status >= 200) return 'ok'
  return 'none'
}

/**
 * 粗校验：看起来是不是「IP」或「IP/前缀长度」。
 *
 * 刻意只做形状检查 —— 真正的判定（能不能解析、前缀长度对不对称）交给后端，
 * 因为那里才是唯一权威。这里的作用是在表单上早一步拦住手滑（少写一段、
 * 多打一个字符），而不是替代后端校验。
 */
export function looksLikeCIDR(s: string): boolean {
  const m = /^([0-9a-fA-F:.]+)(?:\/(\d{1,3}))?$/.exec(s.trim())
  if (!m) return false
  const host = m[1]
  if (m[2] !== undefined) {
    const bits = Number(m[2])
    if (bits < 0 || bits > 128) return false
  }
  if (host.includes(':')) {
    // IPv6：只确认字符集与至少两个冒号段，逐段值域交给后端
    return host.split(':').length >= 3
  }
  const parts = host.split('.')
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
}

/**
 * 名单角色的中文名。
 *
 * 集中一处是因为它会同时出现在列表页、路由页、路由表单和提示语里 ——
 * 各写一套的下场是同一个概念在不同页面上叫不同的名字。
 */
export function ipListKindLabel(kind: string | undefined | null): string {
  if (kind === 'allow') return '白名单'
  if (kind === 'deny') return '黑名单'
  // 走到这里说明配置里的 kind 是别的值（后端校验会拦，前端只做兜底展示）——
  // 与其显示成「黑名单」误导人，不如直说没认出来。
  return '未指定角色'
}

/**
 * 拦截原因 → 中文说明。
 *
 * 后端把「IP 名单」这一层拆成了三个独立的标签（v0.7.0）。拆开是有必要的：
 * 以前只有一个笼统的 acl，看到它只能知道「被名单拦了」，但不知道是哪一层 ——
 * 而「全局封禁」和「白名单没配全」的处理方式完全不同，前者要去全局名单里
 * 解除，后者是补一条白名单。见 acl.go 的 decideIP。
 */
export function blockedLabel(reason: string): string {
  if (!reason) return ''
  const map: Record<string, string> = {
    acl_global_deny: '命中全局黑名单（对所有入口生效，白名单不可豁免）',
    acl_route_allow_miss: '不在该路由的白名单内',
    acl_route_deny: '命中该路由的黑名单',
    // v0.6.x 的老标签。老版本的日志还在环形缓冲里，不认它就显示成裸字符串。
    acl: '被 IP 名单拦下（旧版标签）',
    rate_limited: '触发限流',
    circuit_open: '熔断打开，快速失败',
    auth_missing_credentials: '缺少 Basic 凭据',
    auth_unknown_user: '用户名不存在',
    auth_bad_password: '密码错误',
    auth_missing_token: '缺少 JWT',
    auth_token_expired: 'JWT 已过期',
    auth_bad_signature: 'JWT 签名错误',
    auth_alg_not_allowed: 'JWT 算法不被允许',
    auth_invalid_token: 'JWT 非法',
  }
  return map[reason] ?? reason
}

/**
 * 把多行文本按逗号/换行/空格切成去重后的列表。CIDR 列表、端口列表都用它。
 *
 * 注意：IP 名单**不用**它。名单条目带备注，而备注里可以合法地出现逗号，
 * 用这个切会把备注切碎。名单走 parseIPRules / ipRulesToText。
 */
export function splitList(raw: string): string[] {
  return raw
    .split(/[\s,，;；]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/* ---------- IP 名单的文本形态 ---------- */

/**
 * 名单在界面上的文本约定（和 /etc/hosts 一个思路，运维不用学新东西）：
 *
 *     # 以 # 开头的整行是注释
 *     203.0.113.0/24 已知扫描源
 *     198.51.100.7
 *     10.0.0.0/8,10.1.0.0/16        ← 同一行逗号分隔，等价于两行
 *
 * 规则：第一个空白分隔的 token 是 CIDR，剩下的整段是备注。
 * 如果这个 token 里带逗号，就按逗号拆成多条（此时不给备注）——
 * 这样从旧版本粘一串逗号分隔的 CIDR 过来不会报错。
 */
export function parseIPRules(raw: string): IPRule[] {
  const out: IPRule[] = []
  const seen = new Set<string>()
  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue

    const sp = t.search(/\s/)
    const head = sp < 0 ? t : t.slice(0, sp)
    const tail = sp < 0 ? '' : t.slice(sp).trim()

    // 逗号分隔的简写（不带备注）
    if (head.includes(',') || head.includes('，')) {
      for (const piece of head.split(/[,，]/)) {
        const c = piece.trim()
        if (c && !seen.has(c)) {
          seen.add(c)
          out.push({ cidr: c })
        }
      }
      continue
    }
    if (head && !seen.has(head)) {
      seen.add(head)
      out.push(tail ? { cidr: head, note: tail } : { cidr: head })
    }
  }
  return out
}

/** parseIPRules 的反向：条目 → 文本。没备注的只写 CIDR。 */
export function ipRulesToText(rules: IPRule[] | null | undefined): string {
  return (rules ?? [])
    .filter((r) => r && r.cidr)
    .map((r) => (r.note ? `${r.cidr} ${r.note}` : r.cidr))
    .join('\n')
}

/**
 * 后端回传的混合形态（字符串或对象）→ 统一的 IPRule。
 *
 * 后端刻意让「没备注的条目」序列化成字符串简写，否则一次保存就会把配置文件
 * 撑满 {"cidr": ...}。所以前端读到的必然是两种混着的，这里统一收口，
 * 免得每个调用点各写一遍兼容逻辑。
 */
export function normalizeIPRules(raw: RawIPRule[] | null | undefined): IPRule[] {
  const out: IPRule[] = []
  for (const item of raw ?? []) {
    if (typeof item === 'string') {
      const c = item.trim()
      if (c) out.push({ cidr: c })
      continue
    }
    const c = (item?.cidr ?? '').trim()
    if (!c) continue
    const note = (item?.note ?? '').trim()
    out.push(note ? { cidr: c, note } : { cidr: c })
  }
  return out
}

/**
 * 提交给后端的形态：没备注的还原成字符串。
 *
 * 和后端的 MarshalJSON 保持同一个取舍 —— 配置文件是人要读的，
 * 别让一次界面保存把它变得啰嗦。
 */
export function ipRulesToPayload(rules: IPRule[]): (string | IPRule)[] {
  return rules.map((r) => (r.note ? { cidr: r.cidr, note: r.note } : r.cidr))
}

/** 解析端口列表（逗号/空格分隔）。返回 null 表示有非法项。 */
export function parsePorts(raw: string): number[] | null {
  const items = splitList(raw)
  if (items.length === 0) return []
  const out: number[] = []
  for (const s of items) {
    if (!/^\d+$/.test(s)) return null
    const n = Number(s)
    if (n < 1 || n > 65535) return null
    if (!out.includes(n)) out.push(n)
  }
  return out
}

/** JSON 对象 → "k: v, k2: v2" 单行展示。 */
export function pairList(m: Record<string, string> | undefined): string {
  if (!m) return ''
  return Object.entries(m)
    .map(([k, v]) => `${k}: ${v}`)
    .join(', ')
}

/** "k: v" 每行一个 → 对象。 */
export function parsePairs(raw: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t) continue
    const i = t.indexOf(':')
    if (i < 0) continue
    const k = t.slice(0, i).trim()
    const v = t.slice(i + 1).trim()
    if (k && v) out[k] = v
  }
  return out
}


/* ---------- 蜜罐端口的文本形态 ---------- */

/**
 * 端口在界面上的文本约定，和 IP 名单同一套写法（运维不用学第二种）：
 *
 *     # 以 # 开头的整行是注释
 *     23            备注可以跟在后面
 *     3389/tcp
 *     5900/udp      UDP 也一样，只是绝不回包
 *     2323,13389    ← 一行逗号分隔，等价于两行（此时不给备注）
 *
 * 返回 { ports, bad }：bad 是解析不出来的原行，**原样留着给界面报错**。
 * 不在这里静默丢掉 —— 用户少打一个数字就少一个诱饵端口，而这种"少一个"
 * 在界面上看不出来（列表里那一行只是不见了）。
 */
export function parseHoneypotPorts(raw: string): { ports: HoneypotPort[]; bad: string[] } {
  const ports: HoneypotPort[] = []
  const bad: string[] = []
  const seen = new Set<string>()

  const push = (portStr: string, proto: string, note: string) => {
    if (!/^\d+$/.test(portStr)) {
      bad.push(portStr + (note ? ' ' + note : ''))
      return
    }
    const n = Number(portStr)
    if (n < 1 || n > 65535) {
      bad.push(portStr + '（端口号要 1-65535）')
      return
    }
    const p = proto.toLowerCase() === 'udp' ? 'udp' : 'tcp'
    const key = `${p}/${n}`
    if (seen.has(key)) return
    seen.add(key)
    ports.push(note ? { port: n, proto: p, note } : { port: n, proto: p })
  }

  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue

    const sp = t.search(/\s/)
    const head = sp < 0 ? t : t.slice(0, sp)
    const tail = sp < 0 ? '' : t.slice(sp).trim()

    if (head.includes(',') || head.includes('，')) {
      for (const piece of head.split(/[,，]/)) {
        const c = piece.trim()
        if (!c) continue
        const [p, proto] = c.split('/')
        push(p.trim(), (proto ?? 'tcp').trim(), '')
      }
      continue
    }
    const [p, proto] = head.split('/')
    push(p.trim(), (proto ?? 'tcp').trim(), tail)
  }
  return { ports, bad }
}

/** parseHoneypotPorts 的反向。tcp 不写出来 —— 它是默认值，写满 /tcp 只是噪音。 */
export function honeypotPortsToText(ports: HoneypotPort[] | null | undefined): string {
  return (ports ?? [])
    .filter((p) => p && p.port)
    .map((p) => {
      const spec = (p.proto ?? 'tcp').toLowerCase() === 'udp' ? `${p.port}/udp` : `${p.port}`
      return p.note ? `${spec} ${p.note}` : spec
    })
    .join('\n')
}
