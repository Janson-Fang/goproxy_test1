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

/**
 * 名单里的一条：CIDR（或单个 IP）+ 可选备注。
 *
 * 备注只用于展示与排查 —— 它会出现在命中测试的「命中依据」里，
 * 用来回答「这个地址当初到底是为什么被封的」。
 */
export interface IPRule {
  cidr: string
  note?: string
}

/**
 * 后端回传的名单条目是**两种形态混在一起**的：
 *   ["10.0.0.0/8", {"cidr": "1.2.3.4", "note": "爬虫"}]
 *
 * 没有备注的条目会走字符串简写 —— 后端 MarshalJSON 刻意这么做的，
 * 否则一次控制台保存就会把配置文件撑得满屏都是 {"cidr": ...}。
 * 界面读进来统一归一化成 IPRule，写回去时没备注的再还原成字符串。
 */
export type RawIPRule = string | { cidr?: string; note?: string }

/**
 * 一条路由上的 IP 名单 —— 从 v0.8.0 起只是**引用**，规则本身在顶层的 ip_lists 里。
 *
 * 为什么不再内联：同一段「办公网」以前要在每条路由里各写一遍，改一次要改 N 处，
 * 漏一处就是某条路由的防护没跟上，而且肉眼看不出来。现在建一次、按名字引用。
 *
 * 引用到的多份名单按各自的 kind 落到两层，同层取并集：
 *   ① 全局黑名单命中                 → 拒绝（顶层 global_ip_deny，不可豁免）
 *   ② 引用了白名单，但一份都没命中   → 拒绝
 *   ③ 引用的黑名单里任意一份命中     → 拒绝
 *   ④ 放行
 *
 * 后端实现见 acl.go 的 decideIP，前端只是照抄这个顺序做提示。
 */
export interface RouteACLConfig {
  /**
   * 引用到的名单名（就是 IPListDef.name）。一份都不引用 = 这条路由不做 IP 限制。
   *
   * 显式的 null 表示「取消所有引用」。
   *
   * 这不是可有可无的讲究：PATCH 路由是「反序列化到现有路由上」的合并语义，
   * 字段不出现就保持原值。控制台取消全部引用时必须显式写 null ——
   * 否则界面上看着清干净了，磁盘上那些引用还在拦人。
   */
  lists?: string[] | null
}

/** 名单的角色。角色定义在名单上，不在引用点 —— 同一份名单在所有路由里角色一致。 */
export type IPListKind = 'allow' | 'deny'

/**
 * 一份可复用的命名地址列表。
 *
 * name 既是对外的展示名，也是路由引用它的键，所以不能重名、不能带 / 和换行。
 * rules 是原始形态（条目可能是字符串简写），读进来统一走 normalizeIPRules。
 */
export interface IPListDef {
  name: string
  kind: IPListKind | ''
  rules?: RawIPRule[] | null
}

/** 命中测试里单层的判定结果。 */
export interface ACLStep {
  layer: string
  /** 这一层里具体命中的那份命名名单；全局黑名单命中、「整层没命中」时为空。 */
  list?: string
  configured: boolean
  matched: boolean
  rule?: string
  note?: string
  detail: string
}

/** 一次 IP 名单判定的完整结论（对应后端 acl.go 的 ACLDecision）。 */
export interface ACLDecision {
  ip: string
  allowed: boolean
  /** 拦下它的那一层；放行时为空。 */
  layer?: string
  /** 命中的那份命名名单。全局黑名单命中和「整层没命中」时为空。 */
  list?: string
  /** 命中的具体规则与备注。 */
  rule?: string
  note?: string
  /** 给 blocked / 指标用的短标签，放行时为空。 */
  reason?: string
  /** 给人看的一句话。 */
  message: string
  steps?: ACLStep[]
  route_id?: string
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
  acl?: RouteACLConfig | null
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
  /**
   * 全局黑名单：命中的来源在**所有**入口上一律拒绝，包括管理端口，
   * 也不受任何路由白名单的豁免。
   *
   * 注意它**作用于管理端口** —— 在这里加一条覆盖自己来源的规则，
   * 保存生效后这个控制台就打不开了。后端因此在写路径上有一道自锁检查
   * （guardSelfLockout），会直接拒绝这类保存。
   */
  global_ip_deny: RawIPRule[] | null
  /**
   * 可复用的命名地址列表库。路由的白名单 / 黑名单都从这里引用。
   *
   * 「IP 名单」页签编辑它，路由表单读它来列出「可以勾选哪些名单」——
   * 所以这个字段必须下发，不能只在名单页用。
   */
  ip_lists: IPListDef[] | null
}

export interface ConfigPatch {
  default_ports?: number[]
  access_log?: boolean
  trusted_proxies?: string[]
  admin_token?: string
  /**
   * 全局黑名单。传空数组表示清空；不传表示保持现状。
   *
   * 类型是 RawIPRule 而不是 IPRule：没备注的条目要走字符串简写，
   * 否则一次控制台保存就会把 config.json 里每条规则都撑成 {"cidr": …}。
   * 后端 IPRule.UnmarshalJSON 两种形态都收。
   */
  global_ip_deny?: RawIPRule[]
  /**
   * 名单库的**全量替换**。控制台总是把当前所有名单一起提交。
   *
   * 之所以是全量而不是按名字增量：增量要回答「改名的名单算新的还是旧的」，
   * 那个问题从数据本身判断不出来，只能靠猜。
   */
  ip_lists?: IPListDef[]
  /**
   * 声明「哪份名单改了名」：{"旧名": "新名"}。
   *
   * 只在改名时需要。有了它，改名才能和引用改写合成一次原子写 ——
   * 没有它的话「先删旧名再加新名」会让所有引用在中间态里悬空，
   * 而悬空引用是硬错误，保存根本提交不下去。
   */
  ip_list_renames?: Record<string, string>
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
  /**
   * 当前生效的自动封禁条数。可选：老版本二进制不会返回它，
   * 那种情况下页签角标不显示，其余功能不受影响。
   */
  bans_active?: number
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
  /**
   * 客户端 IP 的地域（国家 / 省 / 市）。
   *
   * 服务端是在**出站时**把地域挂到这条记录上的，所以它和同一个对象里的
   * client_ip 天然是一对 —— 不存在「地域和 IP 配错行」的可能（那不是靠
   * 两边按顺序对齐维持的，而是靠它们在同一个对象里）。
   * 没有来源地址（client_ip 为空）时这里就没有。
   */
  ip_geo?: IpGeo
}

/**
 * 一个 IP 的地域结论。
 *
 * status 分得细是有意的：它们对使用者是**不同的事** ——
 * 「内网地址」是确定的结论，「库没启用」是部署问题，「未收录」是数据边界，
 * 「查询失败」是故障。混成一句「未知」会让人以为功能坏了。
 */
export interface IpGeo {
  status: 'ok' | 'internal' | 'unsupported' | 'unknown' | 'bad_ip' | 'unavailable' | 'failed' | string
  country?: string
  province?: string
  city?: string
  district?: string
  /** 地域库里的原始文本（地点串 · ISP），做 tooltip；省市切分是启发式的，原文是唯一依据 */
  detail?: string
}

/** 地域库自述：来源、版本时间、命中统计。日志页用它说明「地域是哪来的、什么时候更新的」。 */
export interface GeoMeta {
  available: boolean
  path?: string
  entries?: number
  updated_at?: string
  reason?: string
  queries: number
  hits: number
  misses: number
  errors: number
}

export interface LogsResponse {
  entries: LogEntry[] | null
  buffered: number
  capacity: number
  latest_seq: number
  subscribers: number
  dropped: number
  geo?: GeoMeta
}

// ---------- 写操作的返回体 ----------

export interface MutationResult {
  revision: string
  routes: number
  ports: number[] | null
  route?: Route
  deleted?: string
}

// ---------- 升级（upgrade.go / upgradefetch.go） ----------

/**
 * 运行时与升级能力。
 *
 * restart_strategy 是服务端告诉前端「换完二进制之后靠什么把新版本跑起来」：
 *   reexec（Unix）：syscall.Exec 原地替换进程镜像，PID 不变，不依赖服务管理器
 *   spawn   Windows：起一个新进程再退出旧进程（运行中的 exe 有独占锁，没法 exec）
 *   unsupported 不能自升级，原因在 UpgradeState.reason 里
 */
export interface UpgradeRuntime {
  version: string
  commit: string
  goos: string
  goarch: string
  exe: string
  exe_dir: string
  service: string
  restart_strategy: 'reexec' | 'spawn' | 'unsupported' | string
  /** 版本是不是 vX.Y.Z 形式：dev / 裸提交号无法与发布版本比大小 */
  version_comparable: boolean
}

export interface UpgradeStaged {
  present: boolean
  path?: string
  size?: number
  sha256?: string
  version?: string
  commit?: string
  mtime?: string
  /** 服务端是否在本进程里验证过它（跑过 -version） */
  verified: boolean
  /** upload | rollback */
  source?: string
  /**
   * 配置预检：上传时拿这个二进制试读了一次当前配置库。
   *
   * checked 为 true = 跑过且通过；skipped = 那个二进制不认识 -config-check
   * （降级到 v0.15.0 之前）；problem 非空 = 它读不了当前配置，装上去服务会起不来。
   * 三者都是空/假表示「不知道」（比如刚重启过，内存里那次结果没了）。
   */
  config_checked?: boolean
  config_check_skipped?: boolean
  config_problem?: string
}

export interface UpgradeBackup {
  present: boolean
  path?: string
  size?: number
  /** 备份自述的版本；文件不是能跑的 goproxy 时为空 */
  version?: string
  commit?: string
  mtime?: string
}

export interface UpgradeState {
  runtime: UpgradeRuntime
  supported: boolean
  reason?: string
  writable: boolean
  /**
   * 发布页地址。升级本身不向 GitHub 发请求了（跑反代的服务器常常连不上），
   * 但**浏览器**通常能打开它 —— 去那儿下 tar.gz，再用下面的「上传文件升级」传上来。
   */
  release_page: string
  /**
   * 最后一步（写二进制 + 重启服务）必须由 root 做。
   *
   * install.sh 装出来的实例就是这种：服务以 goproxy 跑、ReadWritePaths 只放行了
   * 状态目录与配置目录，而 /usr/local/bin 归 root。这时控制台仍然能校验、
   * 验证并把结果暂存下来，只是要有人在服务器上跑一条 sudo 命令收尾。
   */
  needs_root: boolean
  /** 暂存目录（needs_root 时是配置库旁边的 upgrade/） */
  stage_dir?: string
  /** 给人复制的 root 命令 */
  apply_command?: string
  rollback_command?: string
  staged: UpgradeStaged
  backup: UpgradeBackup
  busy: boolean
}

export interface UpgradeInstallResult {
  ok: boolean
  from: string
  to: string
  /** 最终装上去那个二进制的 sha256 */
  sha256: string
  backup: string
  restart: string
  service: string
  source: string
  verified: boolean
  /** true 表示这次只是「校验 + 暂存」，还没换上去，要 root 执行 apply_command */
  needs_root: boolean
  apply_command?: string
  staged_path?: string
  staged_sha256?: string
  /** 非空表示这次是「带着问题」继续的（目前只有配置预检没过却带了 force） */
  warning?: string
}

/* ---------- 蜜罐与自动封禁 ---------- */

/** 一个要伪装的端口。proto 省略时按 tcp。 */
export interface HoneypotPort {
  port: number
  proto?: string
  note?: string
}

/**
 * 蜜罐配置。
 *
 * 它**不属于 Config**（不进 revision、不进 config_history、不出现在
 * -config-export 里）：自动封禁是运行时状态，混进整份配置会让「每封一个 IP
 * 都让正在编辑的人撞 409」。所以保存它不需要 If-Match，也就不会有 409。
 */
export interface HoneypotConfig {
  enabled: boolean
  /** observe（只记录）| enforce（命中即封禁） */
  mode: string
  /** 阶梯的基准时长（秒）：第 1 次用它，之后 ×6 → ×24 → 封顶 7 天 */
  ban_secs: number
  /** 额外豁免的 CIDR —— 内网/可信代理/白名单/控制台来源已在代码里硬豁免 */
  exempt?: string[] | null
  ports?: HoneypotPort[] | null
}

/** 单个蜜罐端口的运行状态。 */
export interface TrapStat {
  port: number
  proto: string
  note?: string
  /** 端口是否真的在监听。false 时看 error */
  listening: boolean
  hits: number
  /** 去重后的来源 IP 数（用来看「一个地址反复试」还是「一大片地址各试一次」） */
  distinct_ips: number
  first_at?: string
  last_at?: string
  /** 监听失败的原因（端口被占、权限不足…）—— 配置保存成功但端口没起来时在这里 */
  error?: string
}

/** 一次命中。Head 是对方前 64 字节，多数扫描器连上就关所以是空的。 */
export interface TrapProbe {
  time: string
  ip: string
  port: number
  proto: string
  head?: string
}

export interface BanStats {
  /** 当前生效的封禁条数 */
  active: number
  /** 还留在记忆窗口内的条数（含已过期、用于阶梯升级） */
  known: number
  /** 累计被拦下的请求数 */
  blocked: number
  /** 累计因命中豁免而没被自动封禁的次数 */
  exempted: number
  /** 非空表示自动封禁正处于突发熔断中（全网扫描时暂停写入） */
  paused_till?: string
  base_duration: string
}

export interface BanEntry {
  ip: string
  /** honeypot 时是命中的端口，如 tcp/3389；人工封禁时是人填的原因 */
  reason: string
  /** honeypot | manual */
  source: string
  /** 阶梯层级（第几次被封） */
  level: number
  /** 命中次数（生效期内重复命中只累计，不升级也不续期） */
  hits: number
  created_at: string
  expires_at: string
  last_at: string
  /** 最多 5 条命中样本，内容来自攻击者，展示时按纯文本处理 */
  samples?: string[] | null
}

export interface BansState {
  config: HoneypotConfig
  stats: BanStats
  entries?: BanEntry[] | null
  traps?: TrapStat[] | null
  recent?: TrapProbe[] | null
  /** 阶梯的人话说明，如「第 1 次 1 小时」——由后端按 ban_secs 算，前端不重复实现 */
  ladder?: string[] | null
}

export interface HoneypotSaveResult {
  ok: boolean
  config: HoneypotConfig
  /** 有端口没能生效时的原因（配置已保存，只是那几个端口没起来） */
  problems?: string
  traps?: TrapStat[] | null
}
