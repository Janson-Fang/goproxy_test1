/**
 * 与后端 JSON 契约一一对应的类型定义。
 *
 * 对照来源：
 *   - 路由与全局配置：admin_api.go / config.go
 *   - 状态与日志：    stats.go / metrics.go / accesslog.go / circuitbreaker.go
 *
 * 后端用 Go 的 omitempty，所以「没有这个字段」和「字段是 null」语义不同：
 *   - RouteConfig.Enabled 是 *bool，缺省（undefined）等于 true；
 *   - rate_limit / circuit_breaker / auth / acl 缺省或 null 都表示不启用。
 * 提交时我们总是显式给全，避免 PUT 覆盖出意外。
 */

// ---------- 路由 ----------

export interface BasicAuthEntry {
  username: string
  /** 明文密码。后端会自动转 bcrypt，但配置文件里会留下明文，优先用 password_hash。 */
  password?: string
  /** bcrypt hash，形如 $2a$10$... */
  password_hash?: string
}

export interface JWTConfig {
  /** HS256/384/512 的密钥 */
  secret?: string
  /** RS256 的 PEM 公钥 */
  public_key_pem?: string
  /** 算法白名单，留空按凭据推断。alg=none 永远被拒。 */
  algs?: string[]
  issuer?: string
  audience?: string
  leeway_secs?: number
  /** claim → 转发给后端的请求头，如 {"sub": "X-User-Id"} */
  forward_claims?: Record<string, string>
}

export type AuthMode = '' | 'none' | 'basic' | 'jwt'

export interface RouteAuthConfig {
  mode: AuthMode
  realm?: string
  basic?: BasicAuthEntry[]
  jwt?: JWTConfig | null
}

export type ACLMode = '' | 'none' | 'allow' | 'deny'

export interface ACLConfig {
  mode: ACLMode
  /** IP 或 CIDR */
  cidrs?: string[]
}

export type RateLimitScope = '' | 'ip' | 'global'

export interface RateLimitConfig {
  rps: number
  burst: number
  scope?: RateLimitScope
}

export interface CBConfig {
  /** 错误率阈值，0~1 */
  error_rate: number
  /** 窗口内最少调用数，避免刚启动就被零星错误打跳闸 */
  min_calls: number
  /** 跳闸后保持 open 的秒数 */
  open_secs: number
  /** half-open 阶段放行的探测请求数 */
  half_open_calls: number
  /** 滑动窗口长度（秒），上限 300 */
  window_secs: number
}

/** circuitbreaker.go 的 CBSnapshot */
export interface CBSnapshot {
  state: 'closed' | 'open' | 'half_open' | string
  calls: number
  fails: number
  error_rate: number
  opened_total: number
  rejected_total: number
}

/** 单条路由的实时观测值，只读，来自当前生效的路由表 */
export interface RouteLive {
  requests_total: number
  by_status?: Record<string, number>
  rate_limited_total: number
  rejected_total: number
  in_flight: number
  avg_ms: number
  circuit_breaker?: CBSnapshot
}

export interface Route {
  id: string
  name: string
  /** 缺省表示启用 */
  enabled?: boolean
  /** 0 表示挂在所有监听端口上 */
  listen_port: number
  /** 空串表示任意域名，支持 *.example.com 通配 */
  host: string
  path_prefix: string
  target: string
  strip_prefix: boolean
  preserve_host: boolean
  /** 0 表示用全局默认 60s */
  timeout_ms: number
  rate_limit?: RateLimitConfig | null
  circuit_breaker?: CBConfig | null
  auth?: RouteAuthConfig | null
  acl?: ACLConfig | null
  /** 服务端附带的实时观测值，提交时会被忽略 */
  live?: RouteLive | null
}

// ---------- 全局配置 ----------

/** admin_api.go 的 configView。刻意不含 admin_token 明文。 */
export interface ConfigView {
  default_ports: number[]
  admin_addr: string
  admin_enabled: boolean
  admin_token_set: boolean
  access_log: boolean
  trusted_proxies: string[] | null
  route_count: number
}

export interface ConfigPatch {
  default_ports?: number[]
  access_log?: boolean
  trusted_proxies?: string[]
  admin_token?: string
}

// ---------- 状态 ----------

export interface Summary {
  requests_total: number
  by_status: Record<string, number>
  /** 没匹配到任何路由的请求数 —— 配置写错时最该看到的信号 */
  unmatched_total: number
  in_flight: number
  rate_limited_total: number
  rejected_total: number
  avg_ms: number
  p95_ms: number
  error_rate: number
}

/** 每秒的增量点，不是累计值 */
export interface SeriesPoint {
  /** Unix 秒 */
  t: number
  requests: number
  errors: number
  blocked: number
}

export interface CbCounts {
  closed: number
  open: number
  half_open: number
  tripped_total: number
  rejected_total: number
}

export interface LogBufferStats {
  buffered: number
  capacity: number
  subscribers: number
  dropped: number
  latest_seq: number
}

export interface Stats {
  version: string
  commit: string
  now: string
  started_at: string
  uptime_seconds: number
  config_path: string
  config_revision?: string
  routes_configured: number
  routes_active: number
  ports: number[] | null
  reload_total: number
  summary: Summary
  circuit: CbCounts
  series: SeriesPoint[] | null
  logs: LogBufferStats
}

// ---------- 日志 ----------

export interface LogEntry {
  seq: number
  time: string
  route?: string
  route_name?: string
  port: number
  host?: string
  method: string
  path: string
  query?: string
  status: number
  dur_ms: number
  client_ip?: string
  ua?: string
  /** 非空表示请求没被转发出去，值是拦截原因：acl / rate_limited / circuit_open / auth_xxx */
  blocked?: string
}

export interface LogsResponse {
  entries: LogEntry[] | null
  buffered: number
  capacity: number
  latest_seq: number
  subscribers: number
  dropped: number
}

// ---------- 写操作的返回体 ----------

export interface MutationResult {
  revision: string
  routes: number
  ports: number[] | null
  route?: Route
  deleted?: string
}
