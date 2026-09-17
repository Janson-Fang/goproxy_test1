import { useCallback, useEffect, useState } from 'react'
import * as api from './api'
import { ApiError } from './api'
import type { SessionInfo, Stats } from './types'
import { Badge, Card, Note, ToastHost, toast } from './ui'
import { useHashTab, usePolling, useTheme } from './hooks'
import { duration, num } from './format'
import { Dashboard } from './pages/Dashboard'
import { RoutesPage } from './pages/RoutesPage'
import { CertsPage } from './pages/CertsPage'
import { LogsPage } from './pages/LogsPage'
import { SettingsPage } from './pages/SettingsPage'

type Gate = 'checking' | 'ok' | 'need-login' | 'blocked'

export default function App() {
  const [tab, navigate] = useHashTab()
  const [theme, toggleTheme] = useTheme()
  const [gate, setGate] = useState<Gate>('checking')
  const [stats, setStats] = useState<Stats | null>(null)
  const [statsErr, setStatsErr] = useState<string | null>(null)
  const [via, setVia] = useState<SessionInfo['via']>('none')

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStats()
      setStats(s)
      setStatsErr(null)
      setGate('ok')
      // 会话来源单独查一次：它决定要不要显示「登出」。
      // 失败不影响主流程（拿不到状态时按「不可登出」处理，最坏就是不显示按钮）。
      try {
        const info = await api.getSession()
        setVia(info.via)
      } catch {
        setVia('none')
      }
    } catch (e) {
      if (e instanceof ApiError && e.isUnauthorized) {
        setGate('need-login')
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

  const onLogout = useCallback(async () => {
    try {
      await api.logout()
      toast('info', '已登出')
    } catch {
      toast('warn', '登出请求失败，但本机会话数据已清除')
    }
    setGate('checking')
    void refresh()
  }, [refresh])

  if (gate === 'checking' || gate === 'need-login' || gate === 'blocked') {
    return (
      <>
        <LoginGate mode={gate} onRetry={() => { setGate('checking'); void refresh() }} />
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
        {/* 只有真的靠会话登录时才给登出。本机免认证 / Bearer 令牌进来的没有会话可撤 */}
        {via === 'session' && (
          <button className="btn ghost" onClick={() => void onLogout()} title="注销当前会话">
            登出
          </button>
        )}
      </header>

      <nav className="tabs">
        <button className="tab" aria-selected={tab === 'dashboard'} onClick={() => navigate('dashboard')}>
          总览
        </button>
        <button className="tab" aria-selected={tab === 'routes'} onClick={() => navigate('routes')}>
          路由
          {stats && <span className="count">{stats.routes_configured}</span>}
        </button>
        <button className="tab" aria-selected={tab === 'certs'} onClick={() => navigate('certs')}>
          证书
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
        <div style={{ display: tab === 'certs' ? 'block' : 'none' }}>
          <CertsPage />
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
 * 登录门。
 *
 * 控制台的静态页面本身刻意不鉴权（否则浏览器连页面都打不开，就没法输入令牌了），
 * 但所有 /_goproxy/* 接口都受 adminGuard 保护。所以在管理端口对外监听时，
 * 页面能打开、数据拿不到 —— 这一屏就是用来完成登录的。
 *
 * 两条路径：
 *  1. 首选：用 admin_token 换一个 HttpOnly 会话 Cookie（令牌不留在浏览器里）
 *  2. 回退：把令牌放在内存里，以 Authorization: Bearer 发（刷新即丢）
 *     留给「不方便登录」的场景，代价是刷新后要重新填。
 */
function LoginGate({ mode, onRetry }: { mode: Gate; onRetry: () => void }) {
  const [token, setToken] = useState(api.getToken())
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

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

  const doLogin = async (withToken: boolean) => {
    if (!token) return
    setBusy(true)
    setErr(null)
    try {
      if (withToken) {
        await api.login(token)
        // 会话建立成功后立刻把令牌从内存里扔掉 —— 后续请求只靠 Cookie。
        // 这是「令牌不进浏览器」这个收益的最后一步，别省。
        api.clearToken()
        setToken('')
        toast('info', '登录成功')
      } else {
        api.setToken(token)
        toast('info', '令牌已设置（仅本次会话有效）')
      }
      onRetry()
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : String(e)
      setErr(msg)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="gate">
      <Card title="goproxy 控制台" sub={mode === 'checking' ? '正在连接…' : '需要登录'}>
        <div className="stack">
          {mode === 'checking' ? (
            <div className="row">
              <span className="spinner" />
              <span className="muted">正在检查管理接口…</span>
            </div>
          ) : (
            <>
              <Note kind={err ? 'err' : 'warn'}>
                {err ? (
                  <>登录失败：{err}</>
                ) : (
                  <>
                    需要认证。请输入服务端 <code>config.json</code> 里配置的 <code>admin_token</code>。
                  </>
                )}
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
                    if (e.key === 'Enter' && !busy) void doLogin(true)
                  }}
                />
                <div className="hint">
                  登录成功后服务端会下发一个 <code>HttpOnly</code> 会话 Cookie，
                  <strong>令牌本身不会留在浏览器里</strong>，脚本也读不到会话凭据。
                </div>
              </div>
              <div className="row">
                <button className="btn primary" disabled={!token || busy} onClick={() => void doLogin(true)}>
                  {busy ? '登录中…' : '登录'}
                </button>
                <button
                  className="btn ghost"
                  disabled={!token || busy}
                  onClick={() => void doLogin(false)}
                  title="不建立会话，直接把令牌放在内存里用。刷新页面后需要重新输入。"
                >
                  仅用令牌访问
                </button>
              </div>
              <Note kind="info">
                「仅用令牌访问」是给不方便登录的场景留的回退路径：令牌只存在内存中，
                每次刷新都要重填。正常使用建议直接登录。
              </Note>
            </>
          )}
        </div>
      </Card>
    </div>
  )
}
