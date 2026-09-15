import { useMemo } from 'react'
import type { Stats } from '../types'
import { Badge, Card, Empty, LineChart, Note, Spinner, type ChartSeries } from '../ui'
import { datetime, duration, ms, num, pct, timeLabel } from '../format'

export function Dashboard({
  stats,
  error,
  loading,
}: {
  stats: Stats | null
  error: string | null
  loading: boolean
}) {
  if (!stats) {
    return (
      <Card title="总览">
        {error ? <Note kind="err">{error}</Note> : <Spinner label="正在读取运行状态…" />}
      </Card>
    )
  }

  const s = stats.summary
  const points = stats.series ?? []
  const labels = useMemo(() => points.map((p) => timeLabel(p.t)), [points])

  const reqSeries: ChartSeries[] = [
    {
      name: '请求/秒',
      color: 'var(--accent)',
      values: points.map((p) => p.requests),
      fill: true,
    },
  ]
  const errSeries: ChartSeries[] = [
    { name: '5xx/秒', color: 'var(--err)', values: points.map((p) => p.errors) },
    { name: '拦截/秒', color: 'var(--warn)', values: points.map((p) => p.blocked) },
  ]

  const statusRows = Object.entries(s.by_status ?? {})
    .map(([code, count]) => ({ code: Number(code), count }))
    .sort((a, b) => a.code - b.code)
  const statusMax = statusRows.reduce((m, r) => Math.max(m, r.count), 0)

  const errKind = s.error_rate >= 0.05 ? 'err' : s.error_rate >= 0.01 ? 'warn' : 'ok'
  const unmatchedPct = s.requests_total > 0 ? s.unmatched_total / s.requests_total : 0

  return (
    <div className="stack">
      {loading && !stats && <Spinner />}

      <div className="metrics">
        <Metric label="总请求数" value={num(s.requests_total)} foot={`未匹配 ${num(s.unmatched_total)}`} />
        <Metric
          label="5xx 错误率"
          value={pct(s.error_rate)}
          foot={`错误 ${num(countOf(s.by_status, (c) => c >= 500))} 次`}
          tone={errKind}
        />
        <Metric label="P95 耗时" value={ms(s.p95_ms)} foot={`平均 ${ms(s.avg_ms)}`} />
        <Metric label="在途请求" value={num(s.in_flight)} tone={s.in_flight > 0 ? 'accent' : undefined} />
        <Metric label="限流拒绝" value={num(s.rate_limited_total)} tone={s.rate_limited_total > 0 ? 'warn' : undefined} />
        <Metric
          label="其它拒绝"
          value={num(s.rejected_total)}
          foot="ACL / 熔断 / 认证"
          tone={s.rejected_total > 0 ? 'warn' : undefined}
        />
        <Metric
          label="活跃路由"
          value={`${stats.routes_active}`}
          foot={`配置文件里 ${stats.routes_configured} 条`}
          tone={stats.routes_active !== stats.routes_configured ? 'warn' : undefined}
        />
        <Metric label="运行时长" value={duration(stats.uptime_seconds)} foot={`重载 ${stats.reload_total} 次`} />
      </div>

      {unmatchedPct >= 0.05 && s.unmatched_total > 0 && (
        <Note kind="warn">
          <b>{pct(unmatchedPct, 1)}</b> 的请求（{num(s.unmatched_total)} 次）没有匹配到任何路由。
          通常是 <code>listen_port</code> / <code>host</code> / <code>path_prefix</code> 配错了，
          去「路由」页对照一下，或在「日志」页筛 <code>未匹配</code> 看实际打进来的 host 和路径。
        </Note>
      )}

      <div className="grid2" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))' }}>
        <Card title="请求速率" sub="最近 5 分钟 · 每秒增量">
          <ChartOrEmpty series={reqSeries} labels={labels} yFormat={(v) => v.toFixed(0)} />
        </Card>
        <Card title="错误与拦截" sub="5xx 与 限流/熔断/ACL/认证 拒绝">
          <ChartOrEmpty series={errSeries} labels={labels} yFormat={(v) => v.toFixed(0)} />
        </Card>
      </div>

      <div className="grid2" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        <Card title="熔断器" sub={`共 ${stats.circuit.closed + stats.circuit.open + stats.circuit.half_open} 条路由启用`}>
          <div className="row" style={{ gap: 10, marginBottom: 12 }}>
            <Badge kind={stats.circuit.open > 0 ? 'err' : 'ok'} dot>
              闭合 {stats.circuit.closed}
            </Badge>
            <Badge kind={stats.circuit.open > 0 ? 'err' : 'muted'} dot>
              打开 {stats.circuit.open}
            </Badge>
            <Badge kind={stats.circuit.half_open > 0 ? 'warn' : 'muted'} dot>
              半开 {stats.circuit.half_open}
            </Badge>
          </div>
          <dl className="kv">
            <dt>累计跳闸</dt>
            <dd>{num(stats.circuit.tripped_total)}</dd>
            <dt>快速失败</dt>
            <dd>{num(stats.circuit.rejected_total)} 次</dd>
          </dl>
          {stats.circuit.open + stats.circuit.half_open > 0 && (
            <div style={{ marginTop: 12 }}>
              <Note kind="err">
                有路由正处于熔断状态，请求会被立即拒绝（返回 503）。去「路由」页看是哪一条的实时状态。
              </Note>
            </div>
          )}
        </Card>

        <Card title="状态码分布" sub={`共 ${num(s.requests_total)} 次`}>
          {statusRows.length === 0 ? (
            <Empty text="还没有收到任何请求" />
          ) : (
            <div className="stack" style={{ gap: 9 }}>
              {statusRows.map((r) => {
                const cls = r.code >= 500 ? 'err' : r.code >= 400 ? 'warn' : undefined
                return (
                  <div key={r.code} className="row tight" style={{ gap: 10 }}>
                    <span className={`status-code ${statusTone(r.code)}`} style={{ width: 38 }}>
                      {r.code}
                    </span>
                    <div className={`bar ${cls ?? 'ok'}`} style={{ flex: 1 }}>
                      <i style={{ width: `${statusMax > 0 ? (r.count / statusMax) * 100 : 0}%` }} />
                    </div>
                    <span className="mono-sm muted" style={{ width: 74, textAlign: 'right' }}>
                      {num(r.count)}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      </div>

      <Card title="运行信息">
        <dl className="kv">
          <dt>版本</dt>
          <dd>
            <code>{stats.version}</code>
            <span className="faint small"> · commit {stats.commit}</span>
          </dd>
          <dt>监听端口</dt>
          <dd>
            {stats.ports && stats.ports.length > 0 ? (
              <span className="tag-list">
                {stats.ports.map((p) => (
                  <Badge key={p} kind="info">
                    {p}
                  </Badge>
                ))}
              </span>
            ) : (
              <span className="faint">无</span>
            )}
          </dd>
          <dt>启动时间</dt>
          <dd>{datetime(stats.started_at)}</dd>
          <dt>服务端时间</dt>
          <dd>{datetime(stats.now)}</dd>
          <dt>配置文件</dt>
          <dd>
            <code>{stats.config_path}</code>
          </dd>
          <dt>配置版本</dt>
          <dd>
            <code className="mono-sm">{(stats.config_revision ?? '').slice(0, 12) || '-'}</code>
            <span className="faint small"> · sha256</span>
          </dd>
          <dt>日志缓冲</dt>
          <dd>
            {num(stats.logs.buffered)} / {num(stats.logs.capacity)} 条 · 订阅者 {stats.logs.subscribers}
            {stats.logs.dropped > 0 && (
              <span className="faint small"> · 累计丢弃 {num(stats.logs.dropped)} 条（有慢客户端）</span>
            )}
          </dd>
        </dl>
      </Card>
    </div>
  )
}

function Metric({
  label,
  value,
  foot,
  tone,
}: {
  label: string
  value: string
  foot?: string
  tone?: 'ok' | 'warn' | 'err' | 'accent'
}) {
  return (
    <div className={`metric${tone ? ` is-${tone}` : ''}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  )
}

function ChartOrEmpty({
  series,
  labels,
  yFormat,
}: {
  series: ChartSeries[]
  labels: string[]
  yFormat: (v: number) => string
}) {
  const hasData = series.some((s) => s.values.some((v) => v > 0))
  if (labels.length === 0) {
    return <Empty text="采样点还没攒够（服务端每秒采一个点）" />
  }
  return (
    <>
      <LineChart labels={labels} series={series} yFormat={yFormat} />
      <div className="chart-legend" style={{ marginTop: 8 }}>
        {series.map((s) => (
          <span key={s.name}>
            <i style={{ background: s.color }} />
            {s.name}
            {!hasData && <span className="faint"> · 暂无流量</span>}
          </span>
        ))}
      </div>
    </>
  )
}

function countOf(byStatus: Record<string, number>, pred: (code: number) => boolean): number {
  let total = 0
  for (const [code, n] of Object.entries(byStatus)) {
    if (pred(Number(code))) total += n
  }
  return total
}

function statusTone(code: number): string {
  if (code >= 500) return 'server'
  if (code >= 400) return 'client'
  if (code >= 300) return 'redirect'
  if (code >= 200) return 'ok'
  return 'none'
}
