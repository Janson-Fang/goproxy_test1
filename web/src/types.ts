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
  /** TLS 模式：off 明文 / auto 自动签发 / manual 挂本地证书。留空按全局开关推导。 */
  tls_mode?: TLSMode
  /** manual 模式的证书与私钥路径。相对路径相对 tls.cert_dir 解析。 */
  cert_file?: string
  key_file?: string
  /** 是否把明文请求跳到 HTTPS。缺省为 true。 */
  redirect_http?: boolean
  rate_limit?: RateLimitConfig | null
  circuit_breaker?: CBConfig | null
  auth?: RouteAuthConfig | null
  acl?: ACLConfig | null
  /** 服务端附带的实时观测值，提交时会被忽略 */
  live?: RouteLive | null
}

// ---------- TLS ----------

export type TLSMode = '' | 'off' | 'auto' | 'manual'

export interface ACMEConfig {
  /** 注册邮箱，CA 用它发到期提醒 */
  email?: string
  /** ACME 目录地址。留空走 Let's Encrypt 生产环境。 */
  directory_url?: string
  /** 改用 Let's Encrypt 测试环境。调试时务必打开，避免烧掉生产配额。 */
  staging?: boolean
  /** 证书缓存目录，必须持久化。默认 data/certs。 */
  cache_dir?: string
  /** 允许申请证书的域名白名单。留空表示按路由的 host 限制。 */
  hosts?: string[]
}

export interface TLSConfig {
  /** 总开关。默认 false，即全部明文。 */
  enabled: boolean
  acme?: ACMEConfig | null
  /** 手动证书的默认目录 */
  cert_dir?: string
  /** 明文端口，承担 ACME 挑战与 HTTP→HTTPS 重定向。默认 80。 */
  http_port?: number
  /** TLS 端口。默认 443。 */
  https_port?: number
}

/** 单张证书的状态 */
export interface CertStatus {
  hosts: string[]
  /** manual | auto */
  source: string
  issuer?: string
  subject?: string
  not_before?: string
  not_after?: string
  /** 剩余天数，负数表示已过期 */
  days_left: number
  /** 剩余天数低于告警阈值（20 天） */
  expiring: boolean
  expired: boolean
  /** 加载或签发失败的原因 */
  error?: string
  /** 引用这张证书的路由 ID */
  routes?: string[]
}

export interface CertsResponse {
  tls_enabled: boolean
  acme_dir: string
  certs: CertStatus[]
}

/** 监听端口及其 TLS 属性 */
export interface PortInfo {
  port: number
  tls: boolean
}

// ---------- 登录 / 会话 ----------

/**
 * GET /_goproxy/session 的响应。
 *
 * 注意这个接口本身在 adminGuard 之内：**能拿到 200 就一定已经通过鉴权**，
 * 所以 `authenticated` 恒为 true。真正要区分的是「怎么通过的」：
 *
 *   session  —— 登录态，可以显示登出按钮
 *   loopback —— 本机直连免认证（没有会话可登出）
 *   bearer   —— 靠 Authorization 头（脚本场景，控制台里一般不会出现）
 */
export interface SessionInfo {
  authenticated: boolean
  /**
   * 这次请求是靠什么通过认证的。
   *   session —— 浏览器登录后拿到的会话 Cookie（唯一「有身份」的那种）
   *   bearer  —— 带 Authorization: Bearer <admin_token> 的脚本/探针
   * 未认证时后端不回这个字段。
   *
   * v0.6.0 去掉了 'loopback'：回环不再免认证，本机访问同样要凭据。
   */
  via: 'session' | 'bearer' | ''
  /** 仅当 via === 'session' 为 true。前端据此决定要不要渲染「登出」 */
  has_session: boolean
  /** 登录账号名。via === 'session' 时后端一定给得出；bearer 时为空串 */
  username: string
  /** 配置里是否设了 admin_token（展示用，不参与鉴权决定） */
  token_set: boolean
}

/** /_goproxy/session 在 401 时的响应体。前端靠它区分「该登录」和「该去配账号」 */
export interface SessionUnauthorized {
  error: string
  message: string
  /**
   * 服务端到底有没有配过凭据。
   *
   * false 时登录页必须直接说「去 config.json 配一个账号」，
   * 而不是显示「用户名或密码错误」—— 后者会让人对着一个
   * 从来没设过的账号反复试密码。
   */
  credentials_configured: boolean
}

// ---------- 全局配置 ----------

/** admin_api.go 的 configView。刻意不含 admin_token 明文与任何密码哈希。 */
export interface ConfigView {
  default_ports: number[]
  admin_addr: string
  admin_enabled: boolean
  admin_token_set: boolean
  access_log: boolean
  trusted_proxies: string[] | null
  route_count: number
  /** 当前配置了哪些管理员账号。**只有用户名**，密码哈希永远不下发。 */
  admin_users: string[]
  /** 是否至少有一种可用凭据（admin_users 或 admin_token） */
  credentials_configured: boolean
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
