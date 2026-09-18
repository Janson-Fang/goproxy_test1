import { useCallback, useEffect, useState } from 'react'
import * as api from '../api'
import type { ConfigView, Route } from '../types'
import { Badge, Card, Field, Note, Spinner, Switch, toast } from '../ui'
import {
  ipRulesToPayload,
  ipRulesToText,
  looksLikeCIDR,
  normalizeIPRules,
  parseIPRules,
  parsePorts,
  splitList,
} from '../format'

export function SettingsPage({ onChanged }: { onChanged: () => void }) {
  const [cfg, setCfg] = useState<ConfigView | null>(null)
  const [rev, setRev] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const [portsText, setPortsText] = useState('')
  const [accessLog, setAccessLog] = useState(false)
  const [trustedText, setTrustedText] = useState('')
  const [denyText, setDenyText] = useState('')
  const [tokenInput, setTokenInput] = useState('')
  const [clearToken, setClearToken] = useState(false)

  // 命中测试面板的本地状态。这块整体是只读的（后端不复用写路径），
  // 所以它不参与上面的 dirty / save 流程。
  const [routes, setRoutes] = useState<Route[]>([])
  const [testIP, setTestIP] = useState('')
  const [testSelf, setTestSelf] = useState(false)
  const [testRouteId, setTestRouteId] = useState('')
  const [testBusy, setTestBusy] = useState(false)
  const [testResult, setTestResult] = useState<api.ACLTestResult | null>(null)
  const [testErr, setTestErr] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const { config, revision } = await api.getConfig()
      setCfg(config)
      setRev(revision)
      setPortsText((config.default_ports ?? []).join(', '))
      setAccessLog(!!config.access_log)
      setTrustedText((config.trusted_proxies ?? []).join('\n'))
      setDenyText(ipRulesToText(normalizeIPRules(config.global_ip_deny)))
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

  // 路由列表只用于命中测试的「选一条路由」下拉。
  // 取不到就退化成「只能测全局黑名单那一层」——这不值得让整页失败，
  // 所以单独 try 掉。
  useEffect(() => {
    void (async () => {
      try {
        const { routes: rs } = await api.listRoutes()
        setRoutes(rs)
      } catch {
        /* 忽略：下拉空着也能用 */
      }
    })()
  }, [])

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

  const denyRules = parseIPRules(denyText)
  const denyBad = denyRules.filter((r) => !looksLikeCIDR(r.cidr))
  const denyError = denyBad.length
    ? `这些不是合法的 IP 或 CIDR：${denyBad.map((r) => r.cidr).join('、')}`
    : undefined
  // 和磁盘上的值比对，用来点亮「保存」按钮。
  // 注意这条只反映**这个格子**有没有改，所以下面命中测试面板拿它来提醒
  // 「你改的还没生效，测试看不到」。
  const denyDirty = denyText !== ipRulesToText(normalizeIPRules(cfg.global_ip_deny))

  const dirty =
    portsText !== (cfg.default_ports ?? []).join(', ') ||
    accessLog !== !!cfg.access_log ||
    trustedText !== (cfg.trusted_proxies ?? []).join('\n') ||
    denyDirty ||
    tokenInput !== '' ||
    clearToken

  const adminParsed = /^(.+):(\d+)$/.exec(cfg.admin_addr ?? '')
  const adminHost = adminParsed ? adminParsed[1] : cfg.admin_addr
  const adminPort = adminParsed ? adminParsed[2] : ''
  const isLoopbackOnly = adminHost === '127.0.0.1' || adminHost === 'localhost' || adminHost === '::1'
  // v0.6.0：凭据不再只有 admin_token，admin_users 同样算数。
  // 用后端给的 credentials_configured 而不是自己拼条件 —— 判断「算不算配好了」
  // 这件事只应该有一个权威来源，前端猜一遍迟早和后端跑偏。
  const exposedWithoutCredentials = cfg.admin_enabled && !isLoopbackOnly && !cfg.credentials_configured

  const save = async () => {
    if (portsError) {
      toast('err', portsError)
      return
    }
    if (denyError) {
      toast('err', denyError)
      return
    }
    setBusy(true)
    try {
      const patch: Parameters<typeof api.patchConfig>[0] = {
        default_ports: parsedPorts ?? [],
        access_log: accessLog,
        trusted_proxies: splitList(trustedText),
        global_ip_deny: ipRulesToPayload(denyRules),
      }
      if (clearToken) patch.admin_token = ''
      else if (tokenInput) patch.admin_token = tokenInput

      const newRev = await api.patchConfig(patch, rev)
      // 命中测试读的是磁盘上的配置。名单真的改过之后，上面那份结论就不再对应当前配置了，
      // 留着它会让人误以为「刚测过、没问题」。只在名单确实变了时清，改个端口不影响它。
      if (denyDirty) setTestResult(null)
      toast('ok', `配置已保存并热重载（revision ${newRev.slice(0, 8)}）`)
      if (clearToken) api.setToken('')
      await load()
      onChanged()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      toast('err', msg)
      // 两种情况都会走到这里，且都需要把界面拉回磁盘上的真实状态：
      //   - 409 self_lockout：后端拒绝了「会把你自己挡在门外」的全局黑名单，
      //     磁盘上的配置没变，不重读的话用户会以为改动已经写进去了。
      //   - 409 乐观并发冲突：别处改过配置，revision 已经过期。
      if (e instanceof api.ApiError && e.isConflict) await load()
    } finally {
      setBusy(false)
    }
  }

  const runTest = async () => {
    const ip = testSelf ? '' : testIP.trim()
    if (!testSelf && !ip) {
      toast('err', '请填一个 IP 地址，或者打开「测我自己」')
      return
    }
    setTestBusy(true)
    setTestErr(null)
    try {
      setTestResult(await api.testACL(ip, testRouteId))
    } catch (e) {
      setTestResult(null)
      setTestErr(e instanceof Error ? e.message : String(e))
    } finally {
      setTestBusy(false)
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
      {exposedWithoutCredentials && (
        <Note kind="err">
          <b>管理端口正在监听非回环地址（{cfg.admin_addr}），但没有任何管理员凭据。</b>
          <br />
          后端会拒绝所有管理请求 —— 包括从本机发出的。也就是说你现在这个页面上的操作
          在你刷新后都会失败。
          <br />
          请配置 <code>admin_users</code>（用户名 + bcrypt 密码哈希，推荐），
          或者给脚本/探针用的 <code>admin_token</code>；也可以把 <code>admin_addr</code>
          改回 <code>127.0.0.1:8080</code> 只允许本机访问。
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

            {/*
              IP 名单在这里只出现「全局黑名单」一份 —— 另外两份（白名单 / 黑名单）
              是路由级的，在路由表单里维护。三份名单放在一起讲一次顺序，
              比在三个地方各写半句更容易理解。
            */}
            <Note kind="info" span>
              <b>IP 名单一共三份，判定顺序是固定的：</b>
              <br />
              ① <b>全局黑名单</b>（本页）→ 命中就拒绝。对<b>所有</b>入口生效，包括管理端口，
              任何路由白名单都豁免不了。
              <br />
              ② <b>路由白名单</b>（路由表单里）→ 配了就只剩一个含义：只允许名单内的地址。
              <br />
              ③ <b>路由黑名单</b>（路由表单里）→ 在②划定的范围内再剔掉几个地址。
              <br />
              三层都没拦下才放行。想确认某个地址会被哪一层拦下，用下面的<b>命中测试</b>先跑一遍。
            </Note>

            <Field
              label={
                <>
                  全局黑名单 global_ip_deny{' '}
                  {denyRules.length ? (
                    <Badge kind="warn">{denyRules.length} 条</Badge>
                  ) : (
                    <Badge kind="muted">未启用</Badge>
                  )}
                </>
              }
              error={denyError}
              hint={
                <>
                  一行一条：<code>CIDR [备注]</code>，单个 IP 按 /32 处理，<code>#</code> 开头是注释。
                  命中的来源在<b>所有</b>入口上一律 403，且不受任何路由白名单豁免。
                  <br />
                  它<b>同样作用于管理端口</b> —— 在这里加一条覆盖自己来源的规则，保存生效后
                  这个控制台就打不开了。后端因此会在保存前拦一道（自锁检查），
                  真要封自己的网段只能改配置文件后重启。
                </>
              }
              span
            >
              <textarea
                className={`textarea mono${denyError ? ' invalid' : ''}`}
                value={denyText}
                placeholder={'203.0.113.66 爬虫，一直扫目录\n198.51.100.0/24 整段异常流量'}
                onChange={(e) => setDenyText(e.target.value)}
              />
            </Field>

            {/*
              管理员账号只读展示。
              故意不做成可编辑的：账号要在配置文件里 + 用命令行生成 bcrypt 哈希，
              在网页上改密码意味着要在这里收明文密码再算哈希 ——
              那条路会让密码经过一个本该只读的接口，不值得。
            */}
            <Field
              label={
                <>
                  管理员账号 admin_users{' '}
                  {cfg.admin_users?.length ? (
                    <Badge kind="ok">{cfg.admin_users.length} 个</Badge>
                  ) : (
                    <Badge kind="muted">未配置</Badge>
                  )}
                </>
              }
              hint={
                <>
                  「用户名 + 密码」登录用的账号。只读 —— 增删改请在服务器的{' '}
                  <code>config.json</code> 里操作，密码哈希用{' '}
                  <code>goproxy -hash-password '密码'</code> 生成，保存后会自动热重载。
                  出于安全考虑，密码哈希永远不会被这个页面读到。
                </>
              }
              span
            >
              {cfg.admin_users?.length ? (
                <div className="tag-list">
                  {cfg.admin_users.map((u) => (
                    <Badge key={u} kind="info">
                      {u}
                    </Badge>
                  ))}
                </div>
              ) : (
                <span className="faint small">还没有配置任何账号，登录页会引导你去添加。</span>
              )}
            </Field>

            <Field
              label="管理令牌 admin_token"
              hint={
                <>
                  给脚本 / 监控探针用的 Bearer 令牌，<b>不是给人登录用的</b> ——
                  人用上面的用户名 + 密码。留空表示不修改；后端永远不会把令牌明文回传，
                  所以这里只能覆盖，不能查看。
                </>
              }
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
            全局黑名单也在这一份 PATCH 里，清空它就等于关掉整个全局封禁。
          </Note>
        </div>
      </Card>

      <Card title="IP 名单命中测试" sub="只读，不改任何配置">
        <div className="stack">
          <Note kind="info">
            三层名单的先后顺序是固定的，光盯着配置列表很难在脑子里推出结果 ——
            特别是同一个地址既出现在白名单里、又命中某层黑名单的时候。这里可以直接试一次：
            填一个地址（或者打开「测我自己」用你当前请求的来源 IP），再决定要不要选一条路由。
            <br />
            判定读的是<b>磁盘上的 config.json</b>，也就是「保存之后会怎样」——
            所以顺序是先在上面保存，再来这里验证。
          </Note>

          {denyDirty && (
            <Note kind="warn">
              上面的全局黑名单有<b>还没保存</b>的修改。命中测试用的是磁盘上的配置，
              看不到这些改动 —— 先点「保存并生效」再来测，否则得到的是旧结果。
            </Note>
          )}

          <div className="row tight">
            <input
              className="input mono"
              style={{ flex: '1 1 220px' }}
              placeholder={testSelf ? '（用你当前的来源 IP）' : '如 203.0.113.66'}
              value={testSelf ? '' : testIP}
              disabled={testSelf || testBusy}
              onChange={(e) => setTestIP(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void runTest()
              }}
            />
            <select
              className="select"
              style={{ flex: '0 1 260px' }}
              value={testRouteId}
              disabled={testBusy}
              onChange={(e) => setTestRouteId(e.target.value)}
            >
              <option value="">不指定路由（只判全局黑名单）</option>
              {routes.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name || r.id}
                </option>
              ))}
            </select>
            <Switch
              checked={testSelf}
              onChange={(v) => {
                setTestSelf(v)
                if (v) setTestIP('')
              }}
              label="测我自己"
            />
            <button className="btn" onClick={() => void runTest()} disabled={testBusy}>
              {testBusy ? '判定中…' : '测试'}
            </button>
          </div>

          {testErr && <Note kind="err">{testErr}</Note>}

          {testResult && (
            <>
              <div className="row tight">
                <Badge kind={testResult.decision.allowed ? 'ok' : 'err'} dot>
                  {testResult.decision.allowed ? '放行' : '拒绝'}
                </Badge>
                <span className="mono-sm">{testResult.decision.ip}</span>
                {testResult.self && <Badge kind="info">这是你当前的来源 IP</Badge>}
                <Badge kind="muted">
                  {testResult.route_name ? `路由 ${testResult.route_name}` : '未指定路由'}
                </Badge>
              </div>

              <div>{testResult.decision.message}</div>

              {testResult.decision.rule && (
                <div className="small faint">
                  命中规则 <code className="mono-sm">{testResult.decision.rule}</code>
                  {testResult.decision.layer && <> · 来自「{testResult.decision.layer}」</>}
                  {testResult.decision.note && <> · 备注：{testResult.decision.note}</>}
                </div>
              )}

              {!testResult.route_name && (
                <div className="small faint">
                  没选路由，所以路由级的白名单 / 黑名单没有参与判定（下面两行会显示「未配置」）。
                  要连它们一起看，请在上面选一条路由再测一次。
                </div>
              )}

              {testResult.decision.steps?.length ? (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th className="nowrap">层</th>
                        <th className="nowrap">是否配置</th>
                        <th className="nowrap">结果</th>
                        <th>说明</th>
                      </tr>
                    </thead>
                    <tbody>
                      {testResult.decision.steps.map((s, i) => (
                        <tr key={i}>
                          <td className="nowrap">{s.layer}</td>
                          <td className="nowrap faint">{s.configured ? '已配置' : '未配置'}</td>
                          <td className="nowrap">
                            {s.matched ? <Badge kind="err">命中</Badge> : <Badge kind="muted">未命中</Badge>}
                          </td>
                          <td>
                            {s.detail}
                            {s.rule && (
                              <div className="faint small mono-sm">
                                {s.rule}
                                {s.note ? ` · ${s.note}` : ''}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </>
          )}
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
              <code>GET/PATCH /_goproxy/config</code> · <code>GET/POST /_goproxy/acl/test</code> ·{' '}
              <code>GET /_goproxy/stats</code> ·{' '}
              <code>GET /_goproxy/logs</code> · <code>GET /_goproxy/events</code> ·{' '}
              <code>POST /_goproxy/reload</code> · <code>GET /metrics</code>
            </dd>
          </dl>
        </div>
      </Card>
    </div>
  )
}
