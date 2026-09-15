/** 格式化小工具。集中放一起，免得每个页面各写一套，数字风格不统一。 */

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

/** 拦截原因 → 中文说明。后端返回的是 acl / rate_limited / circuit_open / auth_xxx。 */
export function blockedLabel(reason: string): string {
  if (!reason) return ''
  const map: Record<string, string> = {
    acl: 'IP 不在白名单 / 命中黑名单',
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

/** 把多行文本按逗号/换行/空格切成去重后的列表。CIDR 列表、端口列表都用它。 */
export function splitList(raw: string): string[] {
  return raw
    .split(/[\s,，;；]+/)
    .map((s) => s.trim())
    .filter(Boolean)
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
