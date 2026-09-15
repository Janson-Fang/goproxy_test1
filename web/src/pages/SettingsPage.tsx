import { useCallback, useEffect, useState } from 'react'
import * as api from '../api'
import type { ConfigView } from '../types'
import { Badge, Card, Field, Note, Spinner, Switch, toast } from '../ui'
import { parsePorts, splitList } from '../format'

export function SettingsPage({ onChanged }: { onChanged: () => void }) {
  const [cfg, setCfg] = useState<ConfigView | null>(null)
  const [rev, setRev] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const [portsText, setPortsText] = useState('')
  const [accessLog, setAccessLog] = useState(false)
  const [trustedText, setTrustedText] = useState('')
  const [tokenInput, setTokenInput] = useState('')
  const [clearToken, setClearToken] = useState(false)

  const load = useCallback(async () => {
    try {
      const { config, revision } = await api.getConfig()
      setCfg(config)
      setRev(revision)
      setPortsText((config.default_ports ?? []).join(', '))
      setAccessLog(!!config.access_log)
      setTrustedText((config.trusted_proxies ?? []).join('\n'))
      setTokenInput('')
      setClearToken(false)
      setErr(null)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (loading && !cfg) {
    return (
      <Card title="全局配置">
        {err ? <Note kind="err">{err}</Note> : <Spinner label="正在读取配置…" />}
      </Card>
    )
  }
  if (!cfg) {
    return (
      <Card title="全局配置">
        <Note kind="err">{err ?? '读取配置失败'}</Note>
      </Card>
    )
  }

  const parsedPorts = parsePorts(portsText)
  const portsError = parsedPorts === null ? '只能是 1~65535 之间的端口号，用逗号或空格分隔' : undefined
  const dirty =
    portsText !== (cfg.default_ports ?? []).join(', ') ||
    accessLog !== !!cfg.access_log ||
    trustedText !== (cfg.trusted_proxies ?? []).join('\n') ||
    tokenInput !== '' ||
    clearToken

  const adminParsed = /^(.+):(\d+)$/.exec(cfg.admin_addr ?? '')
  const adminHost = adminParsed ? adminParsed[1] : cfg.admin_addr
  const adminPort = adminParsed ? adminParsed[2] : ''
  const isLoopbackOnly = adminHost === '127.0.0.1' || adminHost === 'localhost' || adminHost === '::1'
  const exposedWithoutToken = cfg.admin_enabled && !isLoopbackOnly && !cfg.admin_token_set

  const save = async () => {
    if (portsError) {
      toast('err', portsError)
      return
    }
    setBusy(true)
    try {
      const patch: Parameters<typeof api.patchConfig>[0] = {
        default_ports: parsedPorts ?? [],
        access_log: accessLog,
        trusted_proxies: splitList(trustedText),
      }
      if (clearToken) patch.admin_token = ''
      else if (tokenInput) patch.admin_token = tokenInput

      const newRev = await api.patchConfig(patch, rev)
      toast('ok', `配置已保存并热重载（revision ${newRev.slice(0, 8)}）`)
      if (clearToken) api.setToken('')
      await load()
      onChanged()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      toast('err', msg)
      if (e instanceof api.ApiError && e.isConflict) await load()
    } finally {
      setBusy(false)
    }
  }

  const reload = async () => {
    setBusy(true)
    try {
      await api.reloadConfig()
      await load()
      onChanged()
      toast('ok', '已手动重载配置文件')
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="stack">
      {exposedWithoutToken && (
        <Note kind="err">
          <b>管理端口正在监听非回环地址（{cfg.admin_addr}），但没有设置 admin_token。</b>
          <br />
          后端会拒绝所有来自外部的管理请求，也就是说你现在这个页面上的操作在别的机器上都会失败。
          要么设置一个令牌，要么把 <code>admin_addr</code> 改回 <code>127.0.0.1:8080</code> 只允许本机访问。
        </Note>
      )}

      {err && <Note kind="err">{err}</Note>}

      <Card
        title="运行期配置"
        sub={rev ? `revision ${rev.slice(0, 12)}` : undefined}
        actions={
          <>
            <button className="btn ghost" onClick={() => void load()} disabled={busy}>
              放弃修改
            </button>
            <button className="btn" onClick={() => void reload()} disabled={busy}>
              手动重载
            </button>
            <button className="btn primary" onClick={() => void save()} disabled={busy || !dirty}>
              {busy ? '保存中…' : '保存并生效'}
            </button>
          </>
        }
      >
        <div className="stack">
          <div className="grid2">
            <Field
              label="默认监听端口 default_ports"
              error={portsError}
              hint="无论有没有路由引用都会监听的端口。业务端口由路由的 listen_port 自动派生，不用写在这里。"
            >
              <input
                className={`input mono${portsError ? ' invalid' : ''}`}
                value={portsText}
                placeholder="80"
                onChange={(e) => setPortsText(e.target.value)}
              />
            </Field>

            <Field
              label="访问日志 access_log"
              hint="控制是否把每条访问记录写成结构化日志到 stdout。关掉不影响控制台里的实时日志。"
            >
              <div style={{ paddingTop: 5 }}>
                <Switch
                  checked={accessLog}
                  onChange={setAccessLog}
                  label={accessLog ? '输出到 stdout' : '仅内存环形缓冲'}
                />
              </div>
            </Field>

            <Field
              label="可信代理 trusted_proxies"
              error={undefined}
              hint="一行一个 IP 或 CIDR。只有当请求来自这些地址时，才会采信 X-Forwarded-For 里的客户端 IP —— 否则任何人伪造这个头就能绕过 ACL 和限流。"
              span
            >
              <textarea
                className="textarea mono"
                value={trustedText}
                placeholder={'10.0.0.0/8\n172.16.0.0/12'}
                onChange={(e) => setTrustedText(e.target.value)}
              />
            </Field>

            <Field
              label={
                <>
                  管理令牌 admin_token{' '}
                  {cfg.admin_token_set ? <Badge kind="ok">已设置</Badge> : <Badge kind="muted">未设置</Badge>}
                </>
              }
              hint="留空表示不修改。后端永远不会把令牌明文回传，所以这里只能覆盖，不能查看。"
              span
            >
              <div className="row tight">
                <input
                  className="input mono"
                  style={{ flex: '1 1 260px' }}
                  type="password"
                  autoComplete="new-password"
                  placeholder={clearToken ? '（保存后将清空令牌）' : '留空 = 保持现状'}
                  value={tokenInput}
                  disabled={clearToken}
                  onChange={(e) => setTokenInput(e.target.value)}
                />
                <Switch
                  checked={clearToken}
                  onChange={(v) => {
                    setClearToken(v)
                    if (v) setTokenInput('')
                  }}
                  label="清空令牌"
                />
              </div>
            </Field>
          </div>

          <Note kind="info">
            这些改动走的是 <code>PATCH /_goproxy/config</code>：先原子写回 <code>config.json</code>
            （旧文件备份为 <code>.bak</code>），再热重载。如果新配置在运行期加载不起来，会自动回滚到修改前的版本。
          </Note>
        </div>
      </Card>

      <Card title="启动期配置（只读）">
        <div className="stack">
          <Field
            label="管理端口 admin_addr"
            hint="监听套接字在进程启动时就绑定了，运行期改它不会生效，还可能把当前连接一起弄断，所以后端直接拒绝修改。"
          >
            <div className="row tight">
              <input className="input mono" style={{ flex: '1 1 240px' }} value={cfg.admin_addr} disabled />
              <Badge kind={isLoopbackOnly ? 'ok' : 'warn'}>
                {isLoopbackOnly ? '仅本机可访问' : '对外监听'}
              </Badge>
            </div>
          </Field>

          <div className="small faint">
            要改它：编辑 <code>config.json</code> 里的 <code>admin_addr</code> 后
            <b>重启进程</b>。填 <code>off</code> / <code>none</code> / <code>disabled</code> 可以彻底关掉管理端口
            —— 代价是这个控制台也一起没了。
            {adminPort && (
              <>
                {' '}
                当前管理端口 <code>{adminPort}</code> 不能和任何路由的 <code>listen_port</code> 或
                <code> default_ports</code> 撞车，否则监听会失败。
              </>
            )}
          </div>

          <hr className="hr" />

          <dl className="kv">
            <dt>配置来源</dt>
            <dd>
              单一 JSON 文件（SQLite 尚未启用）。也可以直接改文件 —— 进程每秒轮询 mtime，改了会自动热重载。
            </dd>
            <dt>路由条数</dt>
            <dd>{cfg.route_count}</dd>
            <dt>管理接口</dt>
            <dd>
              <code>GET/POST /_goproxy/routes</code> · <code>GET/PUT/PATCH/DELETE /_goproxy/routes/&#123;id&#125;</code> ·{' '}
              <code>GET/PATCH /_goproxy/config</code> · <code>GET /_goproxy/stats</code> ·{' '}
              <code>GET /_goproxy/logs</code> · <code>GET /_goproxy/events</code> ·{' '}
              <code>POST /_goproxy/reload</code> · <code>GET /metrics</code>
            </dd>
          </dl>
        </div>
      </Card>
    </div>
  )
}
