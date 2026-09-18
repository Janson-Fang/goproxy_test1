import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../api'
import { ApiError } from '../api'
import type { ConfigView, Route, RouteACLConfig } from '../types'
import { Badge, Card, Empty, Note, Spinner, Switch, toast } from '../ui'
import {
  ipRulesToPayload,
  ipRulesToText,
  looksLikeCIDR,
  normalizeIPRules,
  parseIPRules,
} from '../format'

/*
 * IP 名单页。
 *
 * 三份名单在这里统一维护 —— 全局黑名单（对所有入口生效）以及每条路由的
 * 白名单 / 黑名单。它们原先分散在两处：全局黑名单在「配置」页里跟端口、
 * 令牌挤在一起，路由级的两份在路由的新建/编辑表单里。名单是同一类东西，
 * 判定又是同一个固定顺序，分散着改就必须在脑子里拼三处配置才能推出结果。
 *
 * 判定顺序（后端 acl.go 的 decideIP，前端只做展示）：
 *   ① 全局黑名单 → ② 路由白名单 → ③ 路由黑名单 → 放行
 */

/** 一条路由名单的编辑草稿。null 表示当前没有行在编辑。 */
interface Draft {
  id: string
  allow: string
  deny: string
}

/**
 * 把两段文本拼成要提交的 acl 值。
 *
 * 两条都是空就返回 null —— 让 config.json 里干脆不出现 acl 字段，
 * 而不是留下 {"acl":{}} 这种「配了但什么都没配」的写法。
 *
 * 有内容时**两个键都显式写出来**，空的那侧写 null。PATCH 路由是
 * 「反序列化到现有路由上」的合并语义（admin_api.go 的 handlePatchRoute），
 * 不显式写 null 的话，用户清空的那一份名单会**残留**在磁盘上：
 * 界面上看着删干净了，实际还在拦人。
 */
function buildACL(allowText: string, denyText: string): RouteACLConfig | null {
  const allow = parseIPRules(allowText)
  const deny = parseIPRules(denyText)
  if (allow.length === 0 && deny.length === 0) return null
  return {
    allow: allow.length > 0 ? ipRulesToPayload(allow) : null,
    deny: deny.length > 0 ? ipRulesToPayload(deny) : null,
  }
}

/** 校验一段名单文本，返回错误信息或 undefined。 */
function checkRules(text: string, what: string): string | undefined {
  const bad = parseIPRules(text).filter((r) => !looksLikeCIDR(r.cidr))
  if (bad.length === 0) return undefined
  return `${what}里这些不是合法的 IP 或 CIDR：${bad.map((r) => r.cidr).join('、')}`
}

export function IPListPage({
  active = true,
  onChanged,
}: {
  /** 当前是不是正显示这一页。切回来时会重读一次配置。 */
  active?: boolean
  onChanged: () => void
}) {
  // ---- 全局黑名单 ----
  const [cfg, setCfg] = useState<ConfigView | null>(null)
  const [cfgRev, setCfgRev] = useState<string | null>(null)
  const [denyText, setDenyText] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  // ---- 路由名单 ----
  const [routes, setRoutes] = useState<Route[]>([])
  const [routeRev, setRouteRev] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft | null>(null)

  // ---- 命中测试（只读，不参与任何保存流程）----
  const [testIP, setTestIP] = useState('')
  const [testSelf, setTestSelf] = useState(false)
  const [testRouteId, setTestRouteId] = useState('')
  const [testBusy, setTestBusy] = useState(false)
  const [testResult, setTestResult] = useState<api.ACLTestResult | null>(null)
  const [testErr, setTestErr] = useState<string | null>(null)

  // 两块内容分属两个接口（全局配置 / 路由列表），各自的 revision 也不同。
  // 分开 try：路由列表读失败不该让整页空白，全局黑名单还是能看的。
  const load = useCallback(async () => {
    try {
      const { config, revision } = await api.getConfig()
      setCfg(config)
      setCfgRev(revision)
      setDenyText(ipRulesToText(normalizeIPRules(config.global_ip_deny)))
      setErr(null)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
    try {
      const { routes: list, revision } = await api.listRoutes()
      setRoutes(list)
      setRouteRev(revision)
      // 重载后草稿可能已经过期（别人改过），直接丢掉，避免拿旧文本覆盖新值。
      setDraft(null)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
    setLoading(false)
  }, [])

  const globalRules = parseIPRules(denyText)
  const globalError = checkRules(denyText, '全局黑名单')
  const globalDirty = cfg !== null && denyText !== ipRulesToText(normalizeIPRules(cfg.global_ip_deny))

  const draftAllowError = draft ? checkRules(draft.allow, '白名单') : undefined
  const draftDenyError = draft ? checkRules(draft.deny, '黑名单') : undefined

  // 有没有「改了但还没保存」的东西 —— 命中测试读的是磁盘上的配置，
  // 有未保存改动时结论就不对应当前编辑内容，必须提醒。
  const draftDirty = (() => {
    if (!draft) return false
    const r = routes.find((x) => x.id === draft.id)
    if (!r) return false
    return (
      draft.allow !== ipRulesToText(normalizeIPRules(r.acl?.allow)) ||
      draft.deny !== ipRulesToText(normalizeIPRules(r.acl?.deny))
    )
  })()
  const anyDirty = globalDirty || draftDirty

  // 把「有没有未保存改动」同步到一个 ref 里，给下面那个 effect 用。
  // 必须走 ref：那个 effect 只在页签切换时跑，不能把 dirty 放进依赖数组 ——
  // 放进去就等于「每敲一个字都重新拉一遍配置」，那会把正在编辑的文本冲掉。
  const dirtyRef = useRef(false)
  useEffect(() => {
    dirtyRef.current = anyDirty
  })

  // 切回本页时重读一次：revision 和名单都可能已经被「路由」页改过 ——
  // 两页写的是同一个配置文件，带着过期 revision 保存会先撞一次 409。
  // 有未保存改动时不重读：用户可能只是去路由页看了一眼，回来不该丢掉正在改的名单。
  useEffect(() => {
    if (active && !dirtyRef.current) void load()
  }, [active, load])

  if (loading && !cfg) {
    return (
      <Card title="IP 名单">
        {err ? <Note kind="err">{err}</Note> : <Spinner label="正在读取名单…" />}
      </Card>
    )
  }

  const handleError = (e: unknown) => {
    if (e instanceof ApiError && e.isConflict) {
      // 409 有两种，处理方式相反，不能混在一起：
      //   - self_lockout：这次改动本身被拒（会把你自己关在门外），磁盘**没变**。
      //     不能重载 —— 重载会把用户刚敲进去的那条规则擦掉，可那正是他要改的东西。
      //     保留原文，他改一下那条就能重存。
      //   - revision_mismatch：磁盘被别处改过，我们手里的 revision 过期了，必须重读。
      if (e.code === 'self_lockout') {
        toast('err', e.message)
        return
      }
      toast('err', e.message)
      void load()
      return
    }
    toast('err', e instanceof Error ? e.message : String(e))
  }

  const saveGlobal = async () => {
    if (globalError) {
      toast('err', globalError)
      return
    }
    setBusy(true)
    try {
      await api.patchConfig({ global_ip_deny: ipRulesToPayload(globalRules) }, cfgRev)
      // 测试结果读的是磁盘配置，名单真的变了之后旧结论就该作废，
      // 留着它会让人误以为「刚测过，没问题」。
      setTestResult(null)
      toast('ok', `全局黑名单已保存并热重载（${globalRules.length} 条）`)
      await load()
      onChanged()
    } catch (e) {
      handleError(e)
    } finally {
      setBusy(false)
    }
  }

  const saveRoute = async () => {
    if (!draft) return
    const e = draftAllowError || draftDenyError
    if (e) {
      toast('err', e)
      return
    }
    setBusy(true)
    try {
      const acl = buildACL(draft.allow, draft.deny)
      await api.patchRoute(draft.id, { acl }, routeRev)
      setTestResult(null)
      toast('ok', acl === null ? `已清空 ${draft.id} 的名单` : `已保存 ${draft.id} 的名单`)
      await load()
      onChanged()
    } catch (err) {
      handleError(err)
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

  return (
    <div className="stack">
      {err && <Note kind="err">{err}</Note>}

      <Note kind="info">
        <b>IP 名单一共三份，判定顺序是固定的：</b>
        <br />
        ① <b>全局黑名单</b>（本页第一块）→ 命中就拒绝。对<b>所有</b>入口生效，
        包括管理端口，任何路由白名单都豁免不了。
        <br />
        ② <b>路由白名单</b>（本页第二块，按路由）→ 配了就只剩一个含义：
        只允许名单内的地址。
        <br />
        ③ <b>路由黑名单</b>（同上）→ 在②划定的范围内再剔掉几个地址。
        <br />
        三层都没拦下才放行。想确认某个地址会被哪一层拦下，用页面底部的
        <b>命中测试</b>先跑一遍 —— 它读的是磁盘上的配置，所以是「保存之后会怎样」。
      </Note>

      {/* ---------------- ① 全局黑名单 ---------------- */}
      <Card
        title="全局黑名单"
        sub={cfgRev ? `revision ${cfgRev.slice(0, 12)}` : undefined}
        actions={
          <>
            <button className="btn ghost" onClick={() => void load()} disabled={busy || !globalDirty}>
              放弃修改
            </button>
            <button
              className="btn primary"
              onClick={() => void saveGlobal()}
              disabled={busy || !globalDirty}
            >
              {busy ? '保存中…' : '保存并生效'}
            </button>
          </>
        }
      >
        <div className="stack">
          <div className="row tight">
            {globalRules.length ? (
              <Badge kind="warn">{globalRules.length} 条</Badge>
            ) : (
              <Badge kind="muted">未启用</Badge>
            )}
            <span className="faint small">
              {cfg?.global_ip_deny?.length
                ? '当前磁盘上生效的就是这些规则'
                : '当前没有全局封禁的地址'}
            </span>
          </div>

          <textarea
            className={`textarea mono${globalError ? ' invalid' : ''}`}
            style={{ minHeight: 120 }}
            value={denyText}
            placeholder={'203.0.113.66 爬虫，一直扫目录\n198.51.100.0/24 整段异常流量'}
            onChange={(e) => setDenyText(e.target.value)}
          />

          {globalError && <Note kind="err">{globalError}</Note>}

          <div className="small faint">
            一行一条：<code>CIDR [备注]</code>，单个 IP 按 /32 处理，<code>#</code> 开头是注释。
            备注只用于展示与排查（会出现在命中依据和拦截日志里）。清空全部内容再保存
            = 关掉整个全局封禁。
          </div>

          <Note kind="warn">
            它<b>同样作用于管理端口</b>。在这里加一条覆盖自己来源的规则，保存生效后
            这个控制台就打不开了 —— 后端因此会在保存前拦一道（自锁检查），
            真要封自己的网段只能改配置文件后重启。
            <br />
            正因为如此，保存全局黑名单只能靠<b>这个页面的写接口</b>；被封之后唯一的退路是
            改配置文件 + 重启，那条路不受护栏限制。
          </Note>

          <div className="small faint">
            这份名单属于运行期配置，走 <code>PATCH /_goproxy/config</code>：
            先原子写回 <code>config.json</code>（旧文件备份为 <code>.bak</code>），再热重载；
            新配置在运行期加载不起来会自动回滚。
          </div>
        </div>
      </Card>

      {/* ---------------- ② 路由名单 ---------------- */}
      <Card
        title="路由白名单 / 黑名单"
        sub={routeRev ? `revision ${routeRev.slice(0, 12)}` : undefined}
      >
        <div className="stack">
          <Note kind="info">
            白名单负责<b>划范围</b>，黑名单负责在范围内<b>开例外</b>。所以
            「只允许办公网、但把其中一台机器剔掉」= 白名单写办公网网段，
            黑名单写那一台。白名单<b>一旦配置</b>就只剩一个含义 ——
            只允许名单内的地址；想让这条路由不限制来源，把白名单清空即可
            （清空 ≠ 配成空的，后者等于谁都进不来，后端会直接拒）。
            <br />
            名单只作用于<b>这一条路由所挂的端口</b>，所以每行都把端口摆在旁边。
            新建的路由默认不做 IP 限制，想加就回到这一页。
          </Note>

          {routes.length === 0 ? (
            <Empty text="还没有任何路由，先去「路由」页签建一条。" />
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>路由</th>
                    <th className="nowrap">端口</th>
                    <th className="nowrap">白名单</th>
                    <th className="nowrap">黑名单</th>
                    <th className="nowrap" />
                  </tr>
                </thead>
                <tbody>
                  {routes.map((r) => {
                    const allowN = normalizeIPRules(r.acl?.allow).length
                    const denyN = normalizeIPRules(r.acl?.deny).length
                    const editing = draft?.id === r.id
                    return (
                      <Fragment key={r.id}>
                        <tr>
                          <td>
                            <div>{r.name || <span className="faint">（未命名）</span>}</div>
                            <div className="faint small mono-sm">{r.id}</div>
                          </td>
                          <td className="nowrap mono-sm">
                            {r.listen_port > 0 ? r.listen_port : <span className="faint">共享</span>}
                          </td>
                          <td className="nowrap">
                            {allowN > 0 ? (
                              <Badge kind="info">{allowN} 条</Badge>
                            ) : (
                              <Badge kind="muted">不限制</Badge>
                            )}
                          </td>
                          <td className="nowrap">
                            {denyN > 0 ? (
                              <Badge kind="warn">{denyN} 条</Badge>
                            ) : (
                              <Badge kind="muted">未启用</Badge>
                            )}
                          </td>
                          <td className="nowrap">
                            {editing ? (
                              <button className="btn ghost" onClick={() => setDraft(null)} disabled={busy}>
                                收起
                              </button>
                            ) : (
                              <button
                                className="btn ghost"
                                disabled={busy}
                                onClick={() =>
                                  setDraft({
                                    id: r.id,
                                    allow: ipRulesToText(normalizeIPRules(r.acl?.allow)),
                                    deny: ipRulesToText(normalizeIPRules(r.acl?.deny)),
                                  })
                                }
                              >
                                编辑名单
                              </button>
                            )}
                          </td>
                        </tr>

                        {editing && draft && (
                          <tr>
                            <td colSpan={5}>
                              <div className="stack">
                                <div className="grid2">
                                  <div>
                                    <div className="label">
                                      白名单 acl.allow{' '}
                                      {parseIPRules(draft.allow).length ? (
                                        <Badge kind="info">
                                          {parseIPRules(draft.allow).length} 条
                                        </Badge>
                                      ) : (
                                        <Badge kind="muted">不限制来源</Badge>
                                      )}
                                    </div>
                                    <textarea
                                      className={`textarea mono${draftAllowError ? ' invalid' : ''}`}
                                      value={draft.allow}
                                      placeholder={'10.0.0.0/8 办公网'}
                                      onChange={(e) => setDraft({ ...draft, allow: e.target.value })}
                                    />
                                  </div>
                                  <div>
                                    <div className="label">
                                      黑名单 acl.deny{' '}
                                      {parseIPRules(draft.deny).length ? (
                                        <Badge kind="warn">
                                          {parseIPRules(draft.deny).length} 条
                                        </Badge>
                                      ) : (
                                        <Badge kind="muted">未启用</Badge>
                                      )}
                                    </div>
                                    <textarea
                                      className={`textarea mono${draftDenyError ? ' invalid' : ''}`}
                                      value={draft.deny}
                                      placeholder={'10.0.0.9 那台机器在扫端口'}
                                      onChange={(e) => setDraft({ ...draft, deny: e.target.value })}
                                    />
                                  </div>
                                </div>

                                {(draftAllowError || draftDenyError) && (
                                  <Note kind="err">{draftAllowError ?? draftDenyError}</Note>
                                )}

                                <div className="row tight">
                                  <button className="btn primary" onClick={() => void saveRoute()} disabled={busy}>
                                    {busy ? '保存中…' : '保存这两份名单'}
                                  </button>
                                  <button className="btn ghost" onClick={() => setDraft(null)} disabled={busy}>
                                    放弃修改
                                  </button>
                                  <span className="faint small">
                                    两条都清空再保存 = 取消这条路由的 IP 限制。
                                  </span>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div className="small faint">
            名单走 <code>PATCH /_goproxy/routes/&#123;id&#125;</code>，只提交 acl 这一个字段 ——
            这条路由的端口、目标、限流等原样不动。<b>路由表单里不再维护名单</b>，
            同一份数据只有一个编辑入口。
          </div>

          <Note kind="warn">
            IP 名单是按<b>客户端 IP</b>判断的，而这个取值受 <code>trusted_proxies</code> 影响 ——
            如果前面还有一层反代（或 CDN）没被加进可信代理，名单看到的会是<b>上一跳的地址</b>：
            按它封禁会误伤整条链路，按它做白名单则会连自己都进不来。
            挂在「所有端口」上的路由（<code>listen_port</code> 为 0）尤其要注意这一点。
            <br />
            改 <code>trusted_proxies</code> 的去处是「配置」页签。
          </Note>
        </div>
      </Card>

      {/* ---------------- ③ 命中测试 ---------------- */}
      <Card title="名单命中测试" sub="只读，不改任何配置">
        <div className="stack">
          <Note kind="info">
            三层名单的先后顺序是固定的，光盯着配置列表很难在脑子里推出结果 ——
            特别是同一个地址既出现在白名单里、又命中某层黑名单的时候。这里可以直接试一次：
            填一个地址（或者打开「测我自己」用你当前请求的来源 IP），再决定要不要选一条路由。
            <br />
            判定读的是<b>磁盘上的 config.json</b>，也就是「保存之后会怎样」——
            所以顺序是先保存，再来这里验证。
          </Note>

          {anyDirty && (
            <Note kind="warn">
              上面有<b>还没保存</b>的修改。命中测试用的是磁盘上的配置，看不到这些改动 ——
              先点保存，否则得到的是旧结果。
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
    </div>
  )
}
