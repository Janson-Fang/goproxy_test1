/**
 * 管理接口客户端。
 *
 * 几个刻意的设计：
 *  1. 控制台静态页面本身不需要凭据（否则浏览器打不开页面就没法登录），
 *     但所有 /_goproxy/* 接口都受 adminGuard 保护。
 *  2. **默认走会话 Cookie**（登录后由服务端下发 HttpOnly Cookie，JS 读不到），
 *     所以所有请求要带 credentials: 'same-origin'。
 *     Bearer 令牌作为回退路径保留，给不方便登录的场景（监控探针、运维脚本）用。
 *  3. 写接口支持 If-Match（后端用配置文件的 sha256 当 revision 做乐观并发）。
 *     两个页签同时编辑时，后提交的那个会拿到 409，而不是静默覆盖对方的改动。
 *  4. 实时日志走 fetch + ReadableStream 而不是 EventSource ——
 *     EventSource 不能自定义请求头，带不了 Bearer 令牌。
 *     （Cookie 模式下其实可以，但为了保留令牌回退路径，继续用 fetch。）
 *  5. v0.6.0 起用户登录是**用户名 + 密码**，不再是粘贴 admin_token。
 *     密码只在登录请求体里出现一次，服务端校验后下发 Cookie，密码不留任何痕迹。
 */

import type {
  ACLDecision,
  CertsResponse,
  ConfigPatch,
  ConfigView,
  LogEntry,
  LogsResponse,
  MutationResult,
  PortInfo,
  Route,
  SessionInfo,
  Stats,
} from './types'

const TOKEN_KEY = 'goproxy.admin_token'

/**
 * 令牌回退。**不再往 localStorage 写**，只在会话不可用时由用户临时输入，
 * 存在内存里（刷新即丢）。
 *
 * 之前是持久化到 localStorage 的 —— 那等于把一个长期有效的秘密放在
 * 任何一段 JS 都能读到的地方，而这个项目有已知的存储型 XSS 面
 * （访问日志字段原样渲染）。现在正常情况下令牌根本不进浏览器：
 * 用户登录一次，服务端下发 HttpOnly 会话 Cookie，脚本读不到。
 */
let memoryToken = ''

export function getToken(): string {
  return memoryToken
}

export function setToken(token: string): void {
  memoryToken = token
  // 顺手清掉历史版本可能留下的持久化令牌
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* 忽略 */
  }
}

/** 登录时用不到，但保留给「清除本机保存的令牌」这类入口 */
export function clearToken(): void {
  setToken('')
}

export interface ApiErrorInit {
  status: number
  code: string
  message: string
  /** 仅 /_goproxy/session 的 401 会带：服务端有没有配过凭据 */
  credentialsConfigured?: boolean
}

export class ApiError extends Error {
  status: number
  code: string

  /**
   * 服务端是否配过凭据。undefined 表示这次响应没说（绝大多数接口都不说，
   * 只有 /_goproxy/session 的 401 会带）。
   *
   * 前端拿它来区分「该显示登录表单」和「该引导去改配置」——
   * 后者对一个从没设过密码的人来说才是真正有用的信息。
   */
  credentialsConfigured?: boolean

  constructor({ status, code, message, credentialsConfigured }: ApiErrorInit) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.credentialsConfigured = credentialsConfigured
  }

  /** 需要用户输入/更正凭据 */
  get isUnauthorized(): boolean {
    return this.status === 401
  }

  /**
   * 服务端一个凭据都没配（admin_users 和 admin_token 都空）。
   *
   * 这是**独立于 401 的一个错误码**，不是「密码错了」的另一种说法。
   * 前端必须据此显示「去 config.json 配一个管理员账号」，
   * 否则用户会对着一个从来没设过的密码反复试。
   *
   * v0.6.0 从 admin_token_not_set 改名为 admin_credentials_not_set ——
   * 令牌不再是唯一凭据，旧名字会误导人以为「必须去配个令牌」。
   */
  get isCredentialsNotSet(): boolean {
    return this.status === 403 && this.code === 'admin_credentials_not_set'
  }

  /** 兼容旧名。只在 403 时可能为真。 */
  get isTokenNotSet(): boolean {
    return this.isCredentialsNotSet
  }

  /** 配置已被别处修改，需要重新读取 */
  get isConflict(): boolean {
    return this.status === 409
  }
}

interface RawResult<T> {
  data: T
  etag: string | null
}

type Query = Record<string, string | number | undefined>

function buildPath(path: string, query?: Query): string {
  if (!query) return path
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== '') sp.set(k, String(v))
  }
  const qs = sp.toString()
  return qs ? `${path}?${qs}` : path
}

async function raw<T>(
  method: string,
  path: string,
  opts: { body?: unknown; ifMatch?: string | null; query?: Query; signal?: AbortSignal } = {},
): Promise<RawResult<T>> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  // revision 里带引号，If-Match 要求原样回传
  if (opts.ifMatch) headers['If-Match'] = `"${opts.ifMatch.replace(/^"|"$/g, '')}"`

  let res: Response
  try {
    res = await fetch(buildPath(path, opts.query), {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: opts.signal,
      // 会话 Cookie 必须显式带上。跨源请求默认不发 Cookie，
      // 漏了这个的话「登录成功但每个接口都 401」。
      credentials: 'same-origin',
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError({
      status: 0,
      code: 'network_error',
      message: `无法连接管理接口：${err instanceof Error ? err.message : String(err)}`,
    })
  }

  const text = await res.text()
  let payload: unknown = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      // 非 JSON（比如 nginx 的 502 HTML 页面）——原样带出来，比一个 "Unexpected token" 有用得多
      if (!res.ok) {
        throw new ApiError({
          status: res.status,
          code: 'bad_response',
          message: `HTTP ${res.status}：${text.slice(0, 200)}`,
        })
      }
      throw new ApiError({
        status: res.status,
        code: 'bad_response',
        message: `响应不是合法 JSON：${text.slice(0, 200)}`,
      })
    }
  }

  if (!res.ok) {
    const obj = (payload ?? {}) as {
      error?: string
      message?: string
      credentials_configured?: unknown
    }
    // credentials_configured 只有 /_goproxy/session 的 401 会给。
    // 非布尔值一律当「没说」，不要把 "false" 这种字符串当成假值带下去。
    const creds =
      typeof obj.credentials_configured === 'boolean' ? obj.credentials_configured : undefined
    throw new ApiError({
      status: res.status,
      code: obj.error || `http_${res.status}`,
      message: obj.message || `HTTP ${res.status}`,
      credentialsConfigured: creds,
    })
  }

  const etag = res.headers.get('ETag')
  return { data: payload as T, etag: etag ? etag.replace(/^"|"$/g, '') : null }
}

// ---------- 登录 / 会话 ----------

/**
 * 查询当前登录状态。
 *
 * 这个接口在 adminGuard 之外（见后端 isAuthPath），未登录时返回 401，
 * 前端据此切到登录页。**不要**把它包在 try/catch 里当成错误处理 ——
 * 401 在这里是正常流程的一部分。
 */
export async function getSession(): Promise<SessionInfo> {
  const { data } = await raw<SessionInfo>('GET', '/_goproxy/session')
  return data
}

/**
 * 用**用户名 + 密码**登录。
 *
 * 成功后服务端下发 HttpOnly Cookie，密码**不留在浏览器里** ——
 * 它只在这个请求体里出现过一次，之后就只剩服务端算出的 bcrypt 比对结果。
 * 这是这套机制的核心收益：XSS 也偷不到一个长期有效的秘密。
 *
 * 失败时抛 ApiError：
 *   - 401 → 用户名或密码错误（后端刻意不区分，避免枚举出有哪些账号）
 *   - 403 admin_credentials_not_set → 服务端压根没配账号，要去改 config.json
 *   - 429 → 失败次数过多，被临时封禁
 */
export async function login(username: string, password: string): Promise<void> {
  await raw<{ ok: boolean }>('POST', '/_goproxy/login', { body: { username, password } })
}

export async function logout(): Promise<void> {
  await raw<{ ok: boolean }>('DELETE', '/_goproxy/session')
  clearToken()
}

// ---------- 路由 ----------

export async function listRoutes(): Promise<{ routes: Route[]; revision: string | null }> {
  const { data, etag } = await raw<Route[]>('GET', '/_goproxy/routes')
  return { routes: data ?? [], revision: etag }
}

export async function createRoute(
  route: Route,
  ifMatch: string | null,
): Promise<MutationResult> {
  const { data } = await raw<MutationResult>('POST', '/_goproxy/routes', {
    body: route,
    ifMatch,
  })
  return data
}

export async function replaceRoute(
  route: Route,
  ifMatch: string | null,
): Promise<MutationResult> {
  const { data } = await raw<MutationResult>('PUT', `/_goproxy/routes/${encodeURIComponent(route.id)}`, {
    body: route,
    ifMatch,
  })
  return data
}

/** 局部更新。只改 enabled 这类操作走它，避免把整条路由的其它字段一起覆盖。 */
export async function patchRoute(
  id: string,
  patch: Partial<Route>,
  ifMatch: string | null,
): Promise<MutationResult> {
  const { data } = await raw<MutationResult>('PATCH', `/_goproxy/routes/${encodeURIComponent(id)}`, {
    body: patch,
    ifMatch,
  })
  return data
}

export async function deleteRoute(id: string, ifMatch: string | null): Promise<MutationResult> {
  const { data } = await raw<MutationResult>('DELETE', `/_goproxy/routes/${encodeURIComponent(id)}`, {
    ifMatch,
  })
  return data
}

// ---------- 全局配置 ----------

export async function getConfig(): Promise<{ config: ConfigView; revision: string | null }> {
  const { data, etag } = await raw<ConfigView>('GET', '/_goproxy/config')
  return { config: data, revision: etag }
}

export async function patchConfig(patch: ConfigPatch, ifMatch: string | null): Promise<string> {
  const { data } = await raw<{ revision: string }>('PATCH', '/_goproxy/config', {
    body: patch,
    ifMatch,
  })
  return data.revision
}

// ---------- IP 名单命中测试 ----------

export interface ACLTestResult {
  decision: ACLDecision
  /** true 表示这次测的是「我自己」（调用方没指定 IP） */
  self: boolean
  route_name: string
}

/**
 * 拿一个地址跑一遍三层名单，看它会不会被拦、被哪一层拦。
 *
 * **不传 ip 就是「测我自己」**：服务端用本次请求的来源地址来判。
 * 这一问在改名单时最常用 —— 「我加完这条还能不能进得来」，
 * 后端在保存路径上也做了同一件事（自锁检查），这里只是让人能提前看到。
 *
 * 只读接口，不改任何状态，也不依赖写权限。
 */
export async function testACL(ip: string, routeId?: string): Promise<ACLTestResult> {
  const { data } = await raw<ACLTestResult>('POST', '/_goproxy/acl/test', {
    body: { ip, route_id: routeId || '' },
  })
  return data
}

// ---------- 状态与日志 ----------

export async function getStats(): Promise<Stats> {
  const { data } = await raw<Stats>('GET', '/_goproxy/stats')
  return data
}

export async function getLogs(limit = 200): Promise<LogsResponse> {
  const { data } = await raw<LogsResponse>('GET', '/_goproxy/logs', { query: { limit } })
  return data
}

export async function reloadConfig(): Promise<void> {
  await raw<{ ok: boolean }>('POST', '/_goproxy/reload')
}

export async function getPorts(): Promise<PortInfo[]> {
  const { data } = await raw<PortInfo[]>('GET', '/_goproxy/ports')
  return data
}

export async function getCerts(): Promise<CertsResponse> {
  const { data } = await raw<CertsResponse>('GET', '/_goproxy/certs')
  return data
}

// ---------- 实时事件（SSE） ----------

export type StreamState = 'connecting' | 'open' | 'closed'

export interface EventStreamHandlers {
  /** 握手事件，带当前最新 seq；用来和 /_goproxy/logs 拉到的历史去重 */
  onHello?: (info: { latest_seq: number; buffered: number }) => void
  onEntry: (entry: LogEntry) => void
  onState?: (state: StreamState, detail?: string) => void
}

/**
 * 订阅 /_goproxy/events。返回取消函数。
 *
 * 断线后按 0.5s → 10s 指数退避重连（浏览器关标签页会 abort，
 * 所以必须检查停止标志，否则重连循环会变成泄漏的定时器）。
 */
export function openEventStream(handlers: EventStreamHandlers): () => void {
  const ctrl = new AbortController()
  let stopped = false

  const run = async () => {
    let delay = 500
    while (!stopped) {
      handlers.onState?.('connecting')
      try {
        const headers: Record<string, string> = { Accept: 'text/event-stream' }
        const token = getToken()
        if (token) headers.Authorization = `Bearer ${token}`

        const res = await fetch('/_goproxy/events', { headers, signal: ctrl.signal })
        if (!res.ok) {
          const text = await res.text().catch(() => '')
          throw new ApiError({
            status: res.status,
            code: 'stream_failed',
            message: `事件流建立失败：HTTP ${res.status} ${text.slice(0, 120)}`,
          })
        }
        if (!res.body) {
          throw new ApiError({ status: 0, code: 'stream_failed', message: '响应没有可读的流' })
        }

        handlers.onState?.('open')
        delay = 500

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        let event = ''
        let data = ''

        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })

          let nl: number
          while ((nl = buf.indexOf('\n')) >= 0) {
            let line = buf.slice(0, nl)
            buf = buf.slice(nl + 1)
            if (line.endsWith('\r')) line = line.slice(0, -1)

            if (line === '') {
              // 空行 = 一条事件结束
              if (data) {
                try {
                  if (event === 'hello') handlers.onHello?.(JSON.parse(data))
                  else handlers.onEntry(JSON.parse(data) as LogEntry)
                } catch {
                  /* 半条 JSON 不该拖垮整个流 */
                }
              }
              event = ''
              data = ''
              continue
            }
            if (line.startsWith(':')) continue // 心跳注释
            const colon = line.indexOf(':')
            const field = colon < 0 ? line : line.slice(0, colon)
            let v = colon < 0 ? '' : line.slice(colon + 1)
            if (v.startsWith(' ')) v = v.slice(1)
            if (field === 'event') event = v
            else if (field === 'data') data = data ? `${data}\n${v}` : v
          }
        }
        if (!stopped) handlers.onState?.('closed', '连接已被服务端关闭')
      } catch (err) {
        if (stopped || (err instanceof DOMException && err.name === 'AbortError')) return
        handlers.onState?.('closed', err instanceof Error ? err.message : String(err))
      }

      if (stopped) return
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(delay * 2, 10_000)
    }
  }

  void run()

  return () => {
    stopped = true
    ctrl.abort()
  }
}
