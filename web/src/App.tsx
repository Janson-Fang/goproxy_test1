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

/**
 * 控制台的整体状态。
 *
 * v0.6.0 去掉了 'blocked'：以前「没配 token」是一个独立的滞留状态，
 * 因为回环免认证让我们没法用一句话概括「你能不能进」——本机能进、
 * 远程不能进。现在一律要登录，所以只剩三态：
 *   checking    —— 还在探测
 *   need-login  —— 需要（或需要重新）登录
 *   ok          —— 已通过认证
 * 而「服务端到底有没有配账号」是 need-login 之上的一个**子状态**，
 * 由 credentialsConfigured 单独携带，用来决定登录页给表单还是给配置指引。
 */
type Gate = 'checking' | 'ok' | 'need-login'

export default function App() {
  const [tab, navigate] = useHashTab()
  const [theme, toggleTheme] = useTheme()
  const [gate, setGate] = useState<Gate>('checking')
  const [stats, setStats] = useState<Stats | null>(null)
  const [statsErr, setStatsErr] = useState<string | null>(null)
  const [via, setVia] = useState<SessionInfo['via']>('')
  const [username, setUsername] = useState('')
  // null = 还不知道（还没探测过）。用来区分「服务端确实没配账号」
  // 和「刚打开页面、还没拿到答案」——前者要引导去改配置，后者该显示登录表单。
  const [credsConfigured, setCredsConfigured] = useState<boolean | null>(null)

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStats()
      setStats(s)
      setStatsErr(null)
      setGate('ok')
      // 会话来源单独查一次：它决定要不要显示「登出」、以及顶部显示谁登录了。
      // 失败不影响主流程（拿不到状态时按「不可登出」处理，最坏就是不显示按钮）。
      try {
        const info = await api.getSession()
        setVia(info.via)
        setUsername(info.username)
        setCredsConfigured(true)
      } catch {
        setVia('')
        setUsername('')
      }
    } catch (e) {
      if (e instanceof ApiError && e.isUnauthorized) {
        setGate('need-login')
        // 401 是唯一能顺带拿到「服务端配没配凭据」的时机 ——
        // /_goproxy/session 在 401 的响应体里带了 credentials_configured。
        // 有了它，登录页才能在「压根没配账号」时直接给出正确指引。
        if (e.code === 'unauthorized' && typeof e.credentialsConfigured === 'boolean') {
          setCredsConfigured(e.credentialsConfigured)
        }
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

  if (gate === 'checking' || gate === 'need-login') {
    return (
      <>
        <LoginGate
          mode={gate}
          credentialsConfigured={credsConfigured}
          onRetry={() => { setGate('checking'); void refresh() }}
        />
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
        {/* 只有真的靠会话登录进来时才给登出。用 Bearer 令牌的脚本/探针没有会话可撤。 */}
        {via === 'session' && (
          <>
            {username && <span className="faint small nowrap">{username}</span>}
            <button className="btn ghost" onClick={() => void onLogout()} title="注销当前会话">
              登出
            </button>
          </>
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
 * 控制台的静态页面本身刻意不鉴权（否则浏览器连页面都打不开，就没法登录了），
 * 但所有 /_goproxy/* 接口都受 adminGuard 保护。因此未登录时页面能打开、
 * 数据拿不到 —— 这一屏就是用来完成登录的。
 *
 * v0.6.0 的两个变化：
 *  1. 登录凭据从「粘贴 admin_token」改成**用户名 + 密码**。密码只在提交那一次
 *     出现在请求体里，服务端换回一个 HttpOnly 会话 Cookie，密码不留痕迹。
 *  2. 去掉了「仅用令牌访问」这条回退路径，也去掉了按 IP 判断「你该不该登录」。
 *     以前回环免认证，导致同一个页面在「本机打开」和「远程打开」下行为不同 ——
 *     用户反馈「没见到登录界面」的根因就在这。现在一律要登录。
 */
function LoginGate({ mode, credentialsConfigured, onRetry }: {
  mode: Gate
  /**
   * 服务端到底有没有配过管理员账号。
   *
   * false 时不该让用户去猜密码 —— 直接给出「去 config.json 配一个」的指引。
   * 传 null 表示还没探测出来（比如刚打开页面时），这时显示通用的登录表单。
   */
  credentialsConfigured: boolean | null
  onRetry: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  // 服务端明确报告「没配账号」时，锁定成引导态，连表单都不显示 ——
  // 让人对着一个不可能成功的输入框敲密码是最没善意的一种设计。
  const [noCreds, setNoCreds] = useState(false)

  useEffect(() => {
    if (mode === 'checking') {
      const t = window.setTimeout(onRetry, 1200)
      return () => window.clearTimeout(t)
    }
    return undefined
  }, [mode, onRetry])

  // 探测到「服务端没配凭据」时切到引导态。放在 effect 里而不是渲染期，
  // 是为了避免在 render 里 setState。
  useEffect(() => {
    if (mode === 'need-login' && credentialsConfigured === false) setNoCreds(true)
  }, [mode, credentialsConfigured])

  const doLogin = async () => {
    if (!username || !password) return
    setBusy(true)
    setErr(null)
    try {
      await api.login(username, password)
      // 立刻把密码从内存里清掉：它已经完成使命了，后续请求只靠 Cookie。
      setPassword('')
      toast('info', '登录成功')
      onRetry()
    } catch (e) {
      if (e instanceof ApiError && e.isCredentialsNotSet) {
        // 服务端连账号都没配 —— 这不是「密码错了」，是配置问题
        setNoCreds(true)
      } else {
        setErr(e instanceof ApiError ? e.message : String(e))
      }
    } finally {
      setBusy(false)
    }
  }

  // ---- 配置引导态：服务端没有任何可用凭据 ----
  if (noCreds) {
    return (
      <div className="gate">
        <Card title="还没有配置管理员账号">
          <div className="stack">
            <Note kind="err">
              服务端的 <code>config.json</code> 里既没有 <code>admin_users</code>，
              也没有 <code>admin_token</code>，所以没有任何凭据可以通过认证。
            </Note>
            <div className="small">
              在服务器上编辑 <code>config.json</code>，加一个管理员账号：
            </div>
            <pre className="code">{`{
  "admin_addr": "0.0.0.0:9080",
  "admin_users": [
    {
      "username": "admin",
      "password_hash": "$2a$10$...."
    }
  ]
}`}</pre>
            <div className="small">
              上面的 <code>password_hash</code> 用这条命令生成（要填进配置的是它输出的那一行）：
            </div>
            <pre className="code">{`goproxy -hash-password '你的密码'`}</pre>
            <Note kind="warn">
              不要直接把明文写进 <code>password</code> 字段 —— 那个字段只是给测试留的，
              启动时会打警告，而且密码会明文躺在配置文件里。
            </Note>
            <Note kind="info">
              保存后配置会自动热重载，不需要重启进程。然后回到这个页面刷新即可登录。
            </Note>
            <div className="row">
              <button className="btn primary" onClick={onRetry}>
                我配好了，重试
              </button>
              <button className="btn ghost" onClick={() => setNoCreds(false)}>
                仍然尝试登录
              </button>
            </div>
          </div>
        </Card>
      </div>
    )
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
              {err ? (
                <Note kind="err">登录失败：{err}</Note>
              ) : (
                <Note kind="info">
                  请输入管理员账号。用户名与密码在服务端的 <code>config.json</code> 里配置。
                </Note>
              )}

              <div className="field">
                <label className="label" htmlFor="login-username">
                  用户名
                </label>
                <input
                  id="login-username"
                  className="input"
                  type="text"
                  autoComplete="username"
                  autoFocus
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !busy) void doLogin()
                  }}
                />
              </div>

              <div className="field">
                <label className="label" htmlFor="login-password">
                  密码
                </label>
                <input
                  id="login-password"
                  className="input"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !busy) void doLogin()
                  }}
                />
              </div>

              <div className="row">
                <button
                  className="btn primary"
                  disabled={!username || !password || busy}
                  onClick={() => void doLogin()}
                >
                  {busy ? '登录中…' : '登录'}
                </button>
              </div>

              <div className="hint">
                登录成功后服务端下发一个 <code>HttpOnly</code> 会话 Cookie，
                <strong>密码不会留在浏览器里</strong>，脚本也读不到会话凭据。
                连续输错会被按 IP 临时封禁。
              </div>
            </>
          )}
        </div>
      </Card>
    </div>
  )
}
