/**
 * 管理接口客户端。
 *
 * 几个刻意的设计：
 *  1. 控制台静态页面本身不需要令牌（否则浏览器打不开页面就没法输入令牌了），
 *     但所有 /_goproxy/* 接口都受 adminGuard 保护 —— 令牌存在 localStorage，
 *     每次请求以 Authorization: Bearer 发出。
 *  2. 写接口支持 If-Match（后端用配置文件的 sha256 当 revision 做乐观并发）。
 *     两个页签同时编辑时，后提交的那个会拿到 409，而不是静默覆盖对方的改动。
 *  3. 实时日志走 fetch + ReadableStream 而不是 EventSource ——
 *     EventSource 不能自定义请求头，带不了 Bearer 令牌。
 */

import type {
  ConfigPatch,
  ConfigView,
  LogEntry,
  LogsResponse,
  MutationResult,
  Route,
  Stats,
} from './types'

const TOKEN_KEY = 'goproxy.admin_token'

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export function setToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token)
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* 隐私模式下 localStorage 可能不可写，忽略即可 */
  }
}

export interface ApiErrorInit {
  status: number
  code: string
  message: string
}

export class ApiError extends Error {
  status: number
  code: string

  constructor({ status, code, message }: ApiErrorInit) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  /** 需要用户输入/更正管理令牌 */
  get isUnauthorized(): boolean {
    return this.status === 401
  }

  /** 管理端口对外监听但没设 admin_token，后端会拒绝所有外部请求 */
  get isTokenNotSet(): boolean {
    return this.status === 403 && this.code === 'admin_token_not_set'
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
    const obj = (payload ?? {}) as { error?: string; message?: string }
    throw new ApiError({
      status: res.status,
      code: obj.error || `http_${res.status}`,
      message: obj.message || `HTTP ${res.status}`,
    })
  }

  const etag = res.headers.get('ETag')
  return { data: payload as T, etag: etag ? etag.replace(/^"|"$/g, '') : null }
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
