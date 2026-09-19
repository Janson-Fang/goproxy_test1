import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../api'
import type { StreamState } from '../api'
import type { LogEntry, LogsResponse } from '../types'
import { Badge, Card, Empty, Note, Switch, toast } from '../ui'
import { blockedLabel, clock, fullPath, ms, num, statusClass } from '../format'

/** 前端最多保留多少条。超过就丢最旧的 —— 浏览器标签页的内存不是无限的。 */
const MAX_ENTRIES = 2000

type StatusFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'blocked'

export function LogsPage({
  active = true,
  focusRoute = '',
  focusSeq = 0,
}: {
  active?: boolean
  /** 从「路由」页点「日志」跳进来时，要预选的路由 id。非空时把筛选器锁定到这一条。 */
  focusRoute?: string
  /** 每次从路由页触发「看日志」都会 +1。没有它，连着两次点同一条路由的
   * 「日志」（中间手动改过筛选）会因 prop 没变而漏掉第二次预筛。 */
  focusSeq?: number
}) {
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [meta, setMeta] = useState<LogsResponse | null>(null)
  const [state, setState] = useState<StreamState>('connecting')
  const [stateMsg, setStateMsg] = useState<string | undefined>()
  const [paused, setPaused] = useState(false)
  const [follow, setFollow] = useState(true)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [routeFilter, setRouteFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('')

  // 从「路由」页点「日志」跳进来时，把筛选器锁定到那条路由。
  // 以 focusSeq（触发次数）为依赖：同一条路由点两次，id 不变但 seq 变，预筛仍要重放。
  // 直接打开日志页（seq=0）时不碰筛选器 —— 用户自己选的不该被清掉。
  useEffect(() => {
    if (focusSeq > 0) setRouteFilter(focusRoute)
  }, [focusSeq, focusRoute])
  const [keyword, setKeyword] = useState('')
  const [historyLimit, setHistoryLimit] = useState(200)

  const scrollRef = useRef<HTMLDivElement>(null)
  // 用 ref 承载「暂停」和「已收到的最大 seq」：SSE 回调是在 effect 建立时闭包捕获的，
  // 直接读 state 会永远读到初始值（经典 stale closure）。
  const pausedRef = useRef(paused)
  const seenSeqRef = useRef(0)
  const openCountRef = useRef(0)
  pausedRef.current = paused

  const loadHistory = useCallback(async (limit: number) => {
    try {
      const res = await api.getLogs(limit)
      const list = res.entries ?? []
      for (const e of list) if (e.seq > seenSeqRef.current) seenSeqRef.current = e.seq
      setEntries(list)
      setMeta(res)
    } catch (e) {
      toast('err', `读取历史日志失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }, [])

  useEffect(() => {
    void loadHistory(historyLimit)
  }, [loadHistory, historyLimit])

  // SSE：先连上再拉历史会漏一小段，所以上面先拉历史，这里只接增量。
  useEffect(() => {
    const close = api.openEventStream({
      onEntry: (e) => {
        // 暂停时也要推进 seenSeq，否则恢复后会把暂停期间的一起补出来
        if (e.seq > seenSeqRef.current) seenSeqRef.current = e.seq
        if (pausedRef.current) return
        setEntries((prev) => {
          const next = prev.length >= MAX_ENTRIES ? prev.slice(prev.length - MAX_ENTRIES + 1) : [...prev]
          next.push(e)
          return next
        })
      },
      onState: (s, detail) => {
        setState(s)
        setStateMsg(detail)
        if (s === 'open') {
          openCountRef.current += 1
          // 断线重连时补一次历史，把断开期间的日志填回来
          if (openCountRef.current > 1) void loadHistory(historyLimit)
        }
      },
    })
    return close
  }, [loadHistory, historyLimit])

  // 跟随滚动。用户自己往上翻的时候就自动关掉，不然会被不停拽回底部。
  // 页面被 display:none 隐藏时 scrollHeight 是 0，所以切回日志页要重新贴一次底。
  useEffect(() => {
    if (!follow || !active) return
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [entries, follow, active])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    if (!atBottom && follow) setFollow(false)
  }

  const routeOptions = useMemo(() => {
    const set = new Map<string, string>()
    // 筛选器锁定的路由还没有任何记录时，把它补进选项里：
    // 不补的话受控 value 在 DOM 里无处落，下拉框会显示「全部路由」，
    // 看起来像没过滤，实际却在过滤 —— 显示和状态不一致比没有这个选项更糟。
    if (routeFilter && routeFilter !== '__none__' && !set.has(routeFilter)) {
      set.set(routeFilter, routeFilter)
    }
    for (const e of entries) {
      if (!e.route) continue
      set.set(e.route, e.route_name || e.route)
    }
    return [...set.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [entries, routeFilter])

  const methodOptions = useMemo(() => {
    const s = new Set<string>()
    for (const e of entries) s.add(e.method)
    return [...s].sort()
  }, [entries])

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return entries.filter((e) => {
      if (statusFilter === 'blocked' && !e.blocked) return false
      if (statusFilter === '2xx' && !(e.status >= 200 && e.status < 300)) return false
      if (statusFilter === '3xx' && !(e.status >= 300 && e.status < 400)) return false
      if (statusFilter === '4xx' && !(e.status >= 400 && e.status < 500)) return false
      if (statusFilter === '5xx' && !(e.status >= 500 && e.status < 600)) return false
      if (routeFilter === '__none__' ? e.route : routeFilter && e.route !== routeFilter) return false
      if (methodFilter && e.method !== methodFilter) return false
      if (kw) {
        const hay = `${e.path}?${e.query ?? ''} ${e.host ?? ''} ${e.client_ip ?? ''} ${e.ua ?? ''} ${e.route ?? ''} ${e.route_name ?? ''}`.toLowerCase()
        if (!hay.includes(kw)) return false
      }
      return true
    })
  }, [entries, statusFilter, routeFilter, methodFilter, keyword])

  const blockedCount = entries.filter((e) => e.blocked).length

  return (
    <div className="stack">
      <Note kind="info">
        日志来自进程内的定长环形缓冲（{meta ? `${meta.buffered}/${meta.capacity}` : '—'} 条，只看得到最近的一段）。
        完整历史请用 <code>access_log: true</code> 输出到 stdout，交给 journald / logrotate 去管。
      </Note>

      <Card
        title="访问日志"
        sub={`显示 ${filtered.length} / ${entries.length} 条`}
        flush
        actions={
          <div className="row tight">
            <span className="row tight" style={{ gap: 6 }}>
              <span className={`dot-live ${state}`} />
              <span className="small muted">
                {state === 'open' ? '实时' : state === 'connecting' ? '连接中…' : '已断开'}
              </span>
            </span>
            {state !== 'open' && stateMsg && <span className="small faint">· {stateMsg}</span>}
          </div>
        }
      >
        <div className="toolbar">
          <select
            className="select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          >
            <option value="all">全部状态</option>
            <option value="2xx">2xx 成功</option>
            <option value="3xx">3xx 重定向</option>
            <option value="4xx">4xx 客户端错误</option>
            <option value="5xx">5xx 服务端错误</option>
            <option value="blocked">仅被拦截</option>
          </select>

          <select className="select" value={routeFilter} onChange={(e) => setRouteFilter(e.target.value)}>
            <option value="">全部路由</option>
            <option value="__none__">未匹配任何路由</option>
            {routeOptions.map(([id, name]) => (
              <option key={id} value={id}>
                {name === id ? id : `${id} · ${name}`}
              </option>
            ))}
          </select>

          <select className="select" value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)}>
            <option value="">全部方法</option>
            {methodOptions.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          <input
            className="input search"
            placeholder="搜路径 / Host / 客户端 IP / UA / 路由"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
          />

          <div className="spacer" />

          <Switch checked={paused} onChange={setPaused} label={paused ? '已暂停滚动' : '跟随中'} />
          <Switch checked={follow} onChange={setFollow} label="自动滚到底" />

          <select
            className="select"
            value={String(historyLimit)}
            onChange={(e) => setHistoryLimit(Number(e.target.value))}
            title="重新拉取的历史条数"
          >
            <option value="100">100 条</option>
            <option value="200">200 条</option>
            <option value="500">500 条</option>
            <option value="1000">1000 条</option>
          </select>

          <button className="btn ghost sm" onClick={() => void loadHistory(historyLimit)}>
            重新拉取
          </button>
          <button
            className="btn ghost sm"
            onClick={() => {
              setEntries([])
              toast('info', '视图已清空（服务端的环形缓冲不受影响）')
            }}
          >
            清屏
          </button>
        </div>

        {meta && meta.dropped > 0 && (
          <div style={{ padding: '10px 14px 0' }}>
            <Note kind="warn">
              有 {num(meta.dropped)} 条事件因为消费太慢被丢弃（慢客户端保护）。
              界面上看到的可能不是全部流量。
            </Note>
          </div>
        )}

        {filtered.length === 0 ? (
          <Empty
            icon="▤"
            text={
              entries.length === 0
                ? routeFilter && routeFilter !== '__none__'
                  ? `路由 ${routeFilter} 还没有访问记录。往它的监听端口发一个请求就能看到。`
                  : '还没有访问记录。往任意监听端口发一个请求就能看到。'
                : '当前筛选条件下没有记录'
            }
          />
        ) : (
          <div className="log-scroll" ref={scrollRef} onScroll={onScroll}>
            <table className="tbl">
              <thead>
                <tr>
                  <th className="nowrap">时间</th>
                  <th className="nowrap">端口</th>
                  <th className="nowrap">方法</th>
                  <th>路径</th>
                  <th className="nowrap">状态</th>
                  <th className="right nowrap">耗时</th>
                  <th className="nowrap">路由</th>
                  <th className="nowrap">客户端</th>
                  <th>UA</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => (
                  <tr key={e.seq} className={e.blocked ? 'blocked' : undefined}>
                    <td className="nowrap mono-sm">{clock(e.time)}</td>
                    <td className="nowrap mono-sm faint">{e.port || '—'}</td>
                    <td className="nowrap mono-sm">{e.method}</td>
                    <td>
                      <div className="log-path">{fullPath(e.path, e.query)}</div>
                      {e.host && <div className="faint small">{e.host}</div>}
                    </td>
                    <td className="nowrap">
                      <span className={`status-code ${statusClass(e.status)}`}>{e.status}</span>
                      {e.blocked && (
                        <div style={{ marginTop: 2 }}>
                          <Badge kind="warn">{blockedLabel(e.blocked)}</Badge>
                        </div>
                      )}
                    </td>
                    <td className="right nowrap mono-sm">{ms(e.dur_ms)}</td>
                    <td className="nowrap mono-sm">
                      {e.route ? (
                        e.route
                      ) : (
                        <span className="faint" title="没有匹配到任何路由，检查 listen_port / host / path_prefix">
                          未匹配
                        </span>
                      )}
                    </td>
                    <td className="nowrap mono-sm">{e.client_ip || '—'}</td>
                    <td>
                      <div className="ua-cell" title={e.ua}>
                        {e.ua || '—'}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="toolbar" style={{ borderTop: '1px solid var(--border-soft)', borderBottom: 0 }}>
          <span className="small faint">
            共 {entries.length} 条（最多保留 {MAX_ENTRIES}）· 其中被拦截 {blockedCount} 条
            {meta && ` · 服务端订阅者 ${meta.subscribers}`}
          </span>
          <div className="spacer" />
          {paused && <Badge kind="warn">视图已暂停，新日志仍在内核/服务端缓冲里</Badge>}
        </div>
      </Card>
    </div>
  )
}
