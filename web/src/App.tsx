import { useCallback, useEffect, useState } from 'react'
import * as api from './api'
import { ApiError } from './api'
import type { Stats } from './types'
import { Badge, Card, Note, ToastHost, toast } from './ui'
import { useHashTab, usePolling, useTheme } from './hooks'
import { duration, num } from './format'
import { Dashboard } from './pages/Dashboard'
import { RoutesPage } from './pages/RoutesPage'
import { LogsPage } from './pages/LogsPage'
import { SettingsPage } from './pages/SettingsPage'

type Gate = 'checking' | 'ok' | 'need-token' | 'blocked'

export default function App() {
  const [tab, navigate] = useHashTab()
  const [theme, toggleTheme] = useTheme()
  const [gate, setGate] = useState<Gate>('checking')
  const [stats, setStats] = useState<Stats | null>(null)
  const [statsErr, setStatsErr] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStats()
      setStats(s)
      setStatsErr(null)
      setGate('ok')
    } catch (e) {
      if (e instanceof ApiError && e.isUnauthorized) {
        setGate('need-token')
        return
      }
      if (e instanceof ApiError && e.isTokenNotSet) {
        setGate('blocked')
        return
      }
      setStatsErr(e instanceof Error ? e.message : String(e))
    }
  }, [])

  usePolling(refresh, 3000, gate === 'checking' || gate === 'ok')

  if (gate === 'checking' || gate === 'need-token' || gate === 'blocked') {
    return (
      <>
        <TokenGate mode={gate} onRetry={() => { setGate('checking'); void refresh() }} />
        <ToastHost />
      </>
    )
  }

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">
          <Logo />
          goproxy
        </span>

        {stats && (
          <div className="pill-row">
            <Badge kind="muted">{stats.version}</Badge>
            {(stats.ports ?? []).slice(0, 6).map((p) => (
              <Badge key={p} kind="info">
                :{p}
              </Badge>
            ))}
            {(stats.ports?.length ?? 0) > 6 && <Badge kind="muted">+{(stats.ports?.length ?? 0) - 6}</Badge>}
            <Badge kind={stats.circuit.open > 0 ? 'err' : 'ok'} dot>
              {stats.circuit.open > 0 ? `熔断 ${stats.circuit.open}` : '正常'}
            </Badge>
            <span className="faint small">运行 {duration(stats.uptime_seconds)}</span>
          </div>
        )}

        <div className="spacer" />

        {stats && (
          <span className="faint small nowrap">
            {num(stats.summary.requests_total)} 请求 · 路由 {stats.routes_active}
          </span>
        )}

        <button className="btn ghost icon" onClick={toggleTheme} title="切换深色 / 浅色">
          {theme === 'dark' ? '☾' : '☀'}
        </button>
        <button className="btn ghost" onClick={() => void refresh()}>
          刷新
        </button>
      </header>

      <nav className="tabs">
        <button className="tab" aria-selected={tab === 'dashboard'} onClick={() => navigate('dashboard')}>
          总览
        </button>
        <button className="tab" aria-selected={tab === 'routes'} onClick={() => navigate('routes')}>
          路由
          {stats && <span className="count">{stats.routes_configured}</span>}
        </button>
        <button className="tab" aria-selected={tab === 'logs'} onClick={() => navigate('logs')}>
          日志
        </button>
        <button className="tab" aria-selected={tab === 'settings'} onClick={() => navigate('settings')}>
          配置
        </button>
      </nav>

      <main className="content">
        {statsErr && (
          <div style={{ marginBottom: 16 }}>
            <Note kind="warn">
              状态接口读取失败：{statsErr}
              <span className="faint"> · 页面其余功能不受影响</span>
            </Note>
          </div>
        )}

        {/* 四个页面保持挂载：切页签不丢状态，日志流也不会断（断一次就会漏掉那段时间的记录） */}
        <div style={{ display: tab === 'dashboard' ? 'block' : 'none' }}>
          <Dashboard stats={stats} error={statsErr} loading={false} />
        </div>
        <div style={{ display: tab === 'routes' ? 'block' : 'none' }}>
          <RoutesPage onChanged={() => void refresh()} />
        </div>
        <div style={{ display: tab === 'logs' ? 'block' : 'none' }}>
          <LogsPage active={tab === 'logs'} />
        </div>
        <div style={{ display: tab === 'settings' ? 'block' : 'none' }}>
          <SettingsPage onChanged={() => void refresh()} />
        </div>
      </main>

      <ToastHost />
    </div>
  )
}

function Logo() {
  return (
    <svg width="20" height="20" viewBox="0 0 64 64" aria-hidden>
      <rect width="64" height="64" rx="14" fill="var(--accent)" />
      <g fill="none" stroke="#fff" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M16 22h14" />
        <path d="M16 42h14" />
        <path d="M34 22h6a8 8 0 0 1 8 8v4a8 8 0 0 1-8 8h-6" />
      </g>
    </svg>
  )
}

/**
 * 令牌门。
 *
 * 控制台的静态页面本身刻意不鉴权（否则浏览器连页面都打不开，就没法输入令牌了），
 * 但所有 /_goproxy/* 接口都受 adminGuard 保护。所以在管理端口对外监听时，
 * 页面能打开、数据拿不到 —— 这一屏就是用来提示并采集令牌的。
 */
function TokenGate({ mode, onRetry }: { mode: Gate; onRetry: () => void }) {
  const [token, setToken] = useState(api.getToken())

  useEffect(() => {
    if (mode === 'checking') {
      const t = window.setTimeout(onRetry, 1200)
      return () => window.clearTimeout(t)
    }
    return undefined
  }, [mode, onRetry])

  if (mode === 'blocked') {
    return (
      <div className="gate">
        <Card title="管理接口已拒绝所有外部请求">
          <div className="stack">
            <Note kind="err">
              管理端口监听在非回环地址上，但 <code>config.json</code> 里没有配置 <code>admin_token</code>。
              后端的保护策略是：这种情况下拒绝一切外部管理请求（回环地址不受影响）。
            </Note>
            <div className="small">
              两个选择：
              <ol style={{ margin: '8px 0 0', paddingLeft: 20, lineHeight: 1.9 }}>
                <li>
                  在服务器的 <code>config.json</code> 里给 <code>admin_token</code> 设一个强口令，
                  保存后会自动热重载，然后回到这里填入同一个令牌；
                </li>
                <li>
                  把 <code>admin_addr</code> 改回 <code>127.0.0.1:8080</code>，只允许本机访问（需要重启进程）。
                </li>
              </ol>
            </div>
            <Note kind="warn">
              不要为了让这个页面能用就把管理端口裸奔在小端口上 —— 那等于把「改路由 / 看全部流量 / 换后端地址」
              的能力开放给整个网络。
            </Note>
            <div>
              <button className="btn primary" onClick={onRetry}>
                我改好了，重试
              </button>
            </div>
          </div>
        </Card>
      </div>
    )
  }

  return (
    <div className="gate">
      <Card title="goproxy 控制台" sub={mode === 'checking' ? '正在连接…' : '需要管理令牌'}>
        <div className="stack">
          {mode === 'checking' ? (
            <div className="row">
              <span className="spinner" />
              <span className="muted">正在检查管理接口…</span>
            </div>
          ) : (
            <>
              <Note kind="warn">
                管理接口返回了 <code>401 Unauthorized</code>。请输入服务端
                <code> config.json </code>里配置的 <code>admin_token</code>。
              </Note>
              <div className="field">
                <label className="label">管理令牌</label>
                <input
                  className="input mono"
                  type="password"
                  autoComplete="off"
                  placeholder="粘贴 admin_token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      api.setToken(token)
                      onRetry()
                    }
                  }}
                />
                <div className="hint">令牌只保存在这台浏览器的 localStorage 里，不会发往第三方。</div>
              </div>
              <div className="row">
                <button
                  className="btn primary"
                  disabled={!token}
                  onClick={() => {
                    api.setToken(token)
                    toast('info', '令牌已保存，正在验证…')
                    onRetry()
                  }}
                >
                  连接
                </button>
                <button
                  className="btn ghost"
                  onClick={() => {
                    api.setToken('')
                    setToken('')
                    toast('info', '已清除本机保存的令牌')
                  }}
                >
                  清除已保存的令牌
                </button>
              </div>
            </>
          )}
        </div>
      </Card>
    </div>
  )
}
