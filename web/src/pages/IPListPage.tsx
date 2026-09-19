import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../api'
import { ApiError } from '../api'
import type { ConfigView, IPListDef, IPListKind, Route } from '../types'
import { Badge, Card, Empty, Note, Spinner, Switch, toast } from '../ui'
import {
  ipListKindLabel,
  ipRulesToPayload,
  ipRulesToText,
  looksLikeCIDR,
  normalizeIPRules,
  parseIPRules,
} from '../format'

/*
 * IP 名单页。
 *
 * 三块内容：
 *   ① 地址列表库 —— 命名、可复用的 IP 集合，路由按名字引用它（v0.8.0 起）
 *   ② 全局黑名单 —— 对所有入口（含管理端口）生效的唯一一份，不参与引用
 *   ③ 命中测试   —— 只读，拿一个地址跑一遍三层判定
 *
 * 为什么要有 ①：「办公网」这一段网段以前要在每条路由里各写一遍，改一次要改 N 处，
 * 漏一处就是某条路由的防护没跟上，而且肉眼看不出来。现在建一次、按名字引用，
 * 改一处全场生效。角色（白名单 / 黑名单）定义在列表上，不在引用点上 ——
 * 这样同一条列表在所有路由里角色一致，读配置时不用回到引用处去猜。
 *
 * 判定顺序（后端 acl.go 的 decideIP，前端只做展示）：
 *   ① 全局黑名单 → ② 引用的白名单（并集）→ ③ 引用的黑名单（并集）→ 放行
 */

/** 名单在编辑器里的一行。名字就是引用键，所以 original 是「服务端上叫什么」。 */
interface ListRow {
  /** React key，仅本地用；名字会变、不能当 key。 */
  key: number
  /** 服务端上的旧名字。空串 = 新建的行。 */
  original: string
  name: string
  kind: IPListKind
  /** 规则文本（一行一条：CIDR [备注]）。 */
  rules: string
}

function toRows(lists: IPListDef[] | null | undefined, seq: () => number): ListRow[] {
  return (lists ?? []).map((d) => ({
    key: seq(),
    original: d.name,
    name: d.name,
    kind: d.kind === 'allow' ? 'allow' : 'deny',
    rules: ipRulesToText(normalizeIPRules(d.rules)),
  }))
}

/** 行的指纹，用来判断「改了没有」。 */
function rowSig(r: ListRow): string {
  return `${r.name}\u0000${r.kind}\u0000${r.rules}`
}

/** 把编辑器里的行拼成提交体：全量的名单表 + 改名声明。 */
function toPayload(rows: ListRow[]): {
  ip_lists: IPListDef[]
  ip_list_renames: Record<string, string>
} {
  const ip_lists: IPListDef[] = rows.map((r) => ({
    name: r.name.trim(),
    kind: r.kind,
    rules: ipRulesToPayload(parseIPRules(r.rules)),
  }))
  // 改名 = 这一行的名字和它在服务端上的旧名字不一样。
  // 单独声明出来，服务端才能在**同一次写**里把路由的引用一起改掉 ——
  // 否则引用会在中间态里悬空，而悬空引用过不了校验，保存根本提交不下去。
  const ip_list_renames: Record<string, string> = {}
  for (const r of rows) {
    const to = r.name.trim()
    if (r.original && r.original !== to) ip_list_renames[r.original] = to
  }
  return { ip_lists, ip_list_renames }
}

/** 校验行里的一条规则文本，返回错误信息或 undefined。 */
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
  // ---- 名单库 ----
  const [cfg, setCfg] = useState<ConfigView | null>(null)
  const [cfgRev, setCfgRev] = useState<string | null>(null)
  const [rows, setRows] = useState<ListRow[]>([])
  // 展开编辑的行；null 表示都收起来了。行内容本身一直在 rows 里，收起只是收起输入框。
  const [openKey, setOpenKey] = useState<number | null>(null)

  // ---- 路由（用来算「这份名单被谁用着」，以及命中测试的路由下拉）----
  const [routes, setRoutes] = useState<Route[]>([])
  const [routeRev, setRouteRev] = useState<string | null>(null)

  // ---- 全局黑名单 ----
  const [denyText, setDenyText] = useState('')

  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  // ---- 命中测试（只读，不参与任何保存流程）----
  const [testIP, setTestIP] = useState('')
  const [testSelf, setTestSelf] = useState(false)
  const [testRouteId, setTestRouteId] = useState('')
  const [testBusy, setTestBusy] = useState(false)
  const [testResult, setTestResult] = useState<api.ACLTestResult | null>(null)
  const [testErr, setTestErr] = useState<string | null>(null)

  // 行的 key 必须跨多次 load 保持唯一（重读后行会重建，key 不能撞）。
  const keySeq = useRef(0)
  const nextKey = () => ++keySeq.current

  // 两块内容分属两个接口（全局配置 / 路由列表），各自的 revision 也不同。
  // 分开 try：路由列表读失败不该让整页空白，名单库还是能编辑的。
  const load = useCallback(async () => {
    try {
      const { config, revision } = await api.getConfig()
      setCfg(config)
      setCfgRev(revision)
      setDenyText(ipRulesToText(normalizeIPRules(config.global_ip_deny)))
      setRows(toRows(config.ip_lists, nextKey))
      setOpenKey(null)
      setErr(null)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
    try {
      const { routes: list, revision } = await api.listRoutes()
      setRoutes(list)
      setRouteRev(revision)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
    setLoading(false)
  }, [])

  /** 每份名单被哪些路由引用着。删除前必须知道这个 —— 删一份还在用的名单是硬错误。 */
  const usage = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const r of routes) {
      for (const name of r.acl?.lists ?? []) {
        const ids = m.get(name) ?? []
        if (!ids.includes(r.id)) ids.push(r.id)
        m.set(name, ids)
      }
    }
    return m
  }, [routes])

  /** 我要删掉的那些名字（服务端上有、现在没了的）。改名不算删，靠 ip_list_renames 表达。 */
  const removedNames = useMemo(() => {
    const kept = new Set(rows.map((r) => r.name.trim()))
    const renamed = new Set(Object.keys(toPayload(rows).ip_list_renames))
    return (cfg?.ip_lists ?? [])
      .map((d) => d.name)
      .filter((n) => !kept.has(n) && !renamed.has(n))
  }, [rows, cfg])

  // ---- 本地校验 ----------------------------------------------------------
  // 后端才是权威，但等一次 400 回来时编辑器已经重载了，改起来很难受。
  // 这里先把「一定能一眼看出不对」的情况拦掉。
  const listErrors = useMemo(() => {
    const errs: string[] = []
    const seen = new Set<string>()
    for (const r of rows) {
      const name = r.name.trim()
      const who = name || '（未命名）'
      if (!name) {
        errs.push('名单名不能为空 —— 路由靠名字引用名单')
        continue
      }
      if (name.length > 64) errs.push(`名单名「${who}」太长（上限 64 个字符）`)
      if (/[/\\]/.test(name)) errs.push(`名单名「${who}」不能带 / 或 \\`)
      if (/[\r\n]/.test(r.name)) errs.push('名单名不能有换行')
      if (seen.has(name)) errs.push(`名单名「${who}」重复 —— 名字是引用键，不能重名`)
      seen.add(name)

      const bad = checkRules(r.rules, `名单「${who}」`)
      if (bad) errs.push(bad)
      if (r.kind === 'allow' && parseIPRules(r.rules).length === 0) {
        errs.push(
          `「${who}」是白名单，但一条规则都没有。白名单一旦被路由引用就只有` +
            `「只允许名单内的地址」一个含义，空名单会让引用它的路由拒绝所有请求`,
        )
      }
    }
    // 被引用的名单不能删。这里提前说清楚「被谁用着」，
    // 比让用户点保存再收一个 409 强 —— 那时候他还得自己回去找是哪条路由。
    for (const name of removedNames) {
      const ids = usage.get(name) ?? []
      if (ids.length > 0) {
        errs.push(`名单「${name}」还被这些路由引用着，不能删除：${ids.join('、')}。先去那些路由里取消勾选，或者用改名。`)
      }
    }
    return errs
  }, [rows, removedNames, usage])

  const serverSig = useMemo(
    () => toRows(cfg?.ip_lists, () => 0).map(rowSig).join('\n'),
    [cfg],
  )
  const listsDirty = useMemo(() => rows.map(rowSig).join('\n') !== serverSig, [rows, serverSig])

  const globalRules = parseIPRules(denyText)
  const globalError = checkRules(denyText, '全局黑名单')
  const globalDirty =
    cfg !== null && denyText !== ipRulesToText(normalizeIPRules(cfg.global_ip_deny))
  const anyDirty = listsDirty || globalDirty

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
      // 409 有三种，处理方式不同，不能混在一起：
      //   - self_lockout：这次改动本身被拒（会把你自己关在门外），磁盘**没变**。
      //     不能重载 —— 重载会把用户刚敲进去的那条规则擦掉，可那正是他要改的东西。
      //   - list_in_use：要删的名单还在被路由引用，磁盘**没变**。同理保留输入，
      //     让用户看到提示后自己去处理引用。
      //   - revision_mismatch：磁盘被别处改过，我们手里的 revision 过期了，必须重读。
      if (e.code === 'self_lockout' || e.code === 'list_in_use') {
        toast('err', e.message)
        return
      }
      toast('err', e.message)
      void load()
      return
    }
    toast('err', e instanceof Error ? e.message : String(e))
  }

  const saveLists = async () => {
    if (listErrors.length > 0) {
      toast('err', listErrors[0])
      return
    }
    setBusy(true)
    try {
      const payload = toPayload(rows)
      await api.patchConfig(payload, cfgRev)
      // 测试结果读的是磁盘配置，名单真的变了之后旧结论就该作废，
      // 留着它会让人误以为「刚测过，没问题」。
      setTestResult(null)
      const renamed = Object.keys(payload.ip_list_renames).length
      toast(
        'ok',
        `名单库已保存并热重载（${payload.ip_lists.length} 份${renamed ? `，${renamed} 份改名并同步了引用` : ''}）`,
      )
      await load()
      onChanged()
    } catch (e) {
      handleError(e)
    } finally {
      setBusy(false)
    }
  }

  const saveGlobal = async () => {
    if (globalError) {
      toast('err', globalError)
      return
    }
    setBusy(true)
    try {
      await api.patchConfig({ global_ip_deny: ipRulesToPayload(globalRules) }, cfgRev)
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

  const patchRow = (key: number, patch: Partial<ListRow>) =>
    setRows((prev) => prev.map((r) => (r.key === key ? { ...r, ...patch } : r)))

  const addRow = () => {
    const key = nextKey()
    setRows((prev) => [...prev, { key, original: '', name: '', kind: 'deny', rules: '' }])
    setOpenKey(key)
  }

  const removeRow = (key: number) =>
    setRows((prev) => prev.filter((r) => r.key !== key))

  const allowRows = rows.filter((r) => r.kind === 'allow')
  const denyRows = rows.filter((r) => r.kind === 'deny')

  return (
    <div className="stack">
      {err && <Note kind="err">{err}</Note>}

      <Note kind="info">
        <b>三层名单，判定顺序固定：</b>
        <br />
        ① <b>全局黑名单</b>（本页第二块）→ 命中就拒绝。对<b>所有</b>入口生效，
        包括管理端口，任何白名单都豁免不了。
        <br />
        ② <b>白名单</b> → 只允许名单内的地址。路由<b>引用</b>哪几份白名单由路由自己决定，
        引用了就必须命中其中之一。
        <br />
        ③ <b>黑名单</b> → 在②划定的范围内再剔掉几个地址。同样由路由引用。
        <br />
        三层都没拦下才放行。地址列表建一次可以被多条路由引用 ——
        改一处，所有引用它的路由一起生效。想确认某个地址会被哪一层拦下，
        用页面底部的<b>命中测试</b>（它读的是磁盘上的配置，所以是「保存之后会怎样」）。
      </Note>

      {/* ---------------- ① 地址列表库 ---------------- */}
      <Card
        title="地址列表"
        sub={`${rows.length} 份${cfgRev ? ` · revision ${cfgRev.slice(0, 12)}` : ''}`}
        actions={
          <>
            <button className="btn ghost" onClick={addRow} disabled={busy}>
              + 新建名单
            </button>
            <button
              className="btn ghost"
              onClick={() => void load()}
              disabled={busy || !listsDirty}
              title="丢掉这一页未保存的改动，重新读磁盘上的配置"
            >
              放弃修改
            </button>
            <button
              className="btn primary"
              onClick={() => void saveLists()}
              disabled={busy || !listsDirty}
            >
              {busy ? '保存中…' : '保存并生效'}
            </button>
          </>
        }
      >
        <div className="stack">
          <Note kind="info">
            名单的<b>角色写在名单自己身上</b>（白名单 / 黑名单），不在路由的引用点上 ——
            所以同一份名单在所有路由里角色一致，看一处就够。
            <br />
            同名清单想同时当白名单用又当黑名单用，那是两件不同的事，建两份就好。
            <br />
            规则一行一条：<code>CIDR [备注]</code>，单个 IP 按 /32 处理，
            <code>#</code> 开头是注释。备注会出现在命中依据和拦截日志里，
            用来回答「这个地址当初到底是为什么被封的」。
          </Note>

          {listErrors.length > 0 && (
            <Note kind="err">
              <b>还有 {listErrors.length} 处需要修正：</b>
              <ul style={{ margin: '6px 0 0', paddingLeft: 20 }}>
                {listErrors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </Note>
          )}

          {rows.length === 0 ? (
            <Empty
              icon="🗂"
              text="还没有任何地址列表。点右上角「+ 新建名单」建一份，路由就能引用它了。"
            />
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>名单</th>
                    <th className="nowrap">角色</th>
                    <th className="nowrap">规则</th>
                    <th>被哪些路由引用</th>
                    <th className="right nowrap">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {[...allowRows, ...denyRows].map((r) => {
                    const editing = openKey === r.key
                    const n = parseIPRules(r.rules).length
                    const ids = usage.get(r.original || r.name.trim()) ?? []
                    const renamed = r.original !== '' && r.original !== r.name.trim()
                    const isNew = r.original === ''
                    return (
                      <Fragment key={r.key}>
                        <tr>
                          <td>
                            <div className="row tight" style={{ gap: 6 }}>
                              <code style={{ fontWeight: 600 }}>
                                {r.name.trim() || <span className="faint">（未命名）</span>}
                              </code>
                              {isNew && <Badge kind="ok">新增</Badge>}
                              {renamed && <Badge kind="warn">改名自 {r.original}</Badge>}
                            </div>
                          </td>
                          <td className="nowrap">
                            <Badge kind={r.kind === 'allow' ? 'info' : 'warn'}>
                              {ipListKindLabel(r.kind)}
                            </Badge>
                          </td>
                          <td className="nowrap">
                            {n > 0 ? (
                              <Badge kind="muted">{n} 条</Badge>
                            ) : r.kind === 'allow' ? (
                              <Badge kind="err">空（会被拒）</Badge>
                            ) : (
                              <span className="faint small">空</span>
                            )}
                          </td>
                          <td>
                            {ids.length > 0 ? (
                              <span className="small mono-sm">{ids.join('、')}</span>
                            ) : (
                              <span className="faint small">没有路由用它</span>
                            )}
                          </td>
                          <td className="right nowrap">
                            <button
                              className="btn ghost sm"
                              disabled={busy}
                              onClick={() => setOpenKey(editing ? null : r.key)}
                            >
                              {editing ? '收起' : '编辑'}
                            </button>
                            <button
                              className="btn ghost sm"
                              disabled={busy}
                              onClick={() => removeRow(r.key)}
                              title={
                                ids.length > 0
                                  ? `还被 ${ids.join('、')} 引用，保存时会被拒绝`
                                  : '删除这份名单'
                              }
                            >
                              删除
                            </button>
                          </td>
                        </tr>

                        {editing && (
                          <tr>
                            <td colSpan={5}>
                              <div className="stack">
                                <div className="grid2">
                                  <div>
                                    <div className="label">
                                      名单名{' '}
                                      <span className="faint small">
                                        路由就是用它来引用的，所以改名会把引用一起改掉
                                      </span>
                                    </div>
                                    <input
                                      className="input mono"
                                      value={r.name}
                                      placeholder="例如：办公网"
                                      onChange={(e) => patchRow(r.key, { name: e.target.value })}
                                    />
                                  </div>
                                  <div>
                                    <div className="label">角色</div>
                                    <select
                                      className="select"
                                      value={r.kind}
                                      onChange={(e) =>
                                        patchRow(r.key, { kind: e.target.value as IPListKind })
                                      }
                                    >
                                      <option value="allow">
                                        白名单 —— 只允许名单内的地址
                                      </option>
                                      <option value="deny">黑名单 —— 把名单内的地址剔掉</option>
                                    </select>
                                  </div>
                                </div>

                                <div>
                                  <div className="label">
                                    规则{' '}
                                    {n > 0 ? (
                                      <Badge kind="muted">{n} 条</Badge>
                                    ) : (
                                      <Badge kind="muted">0 条</Badge>
                                    )}
                                  </div>
                                  <textarea
                                    className="textarea mono"
                                    style={{ minHeight: 110 }}
                                    value={r.rules}
                                    placeholder={
                                      r.kind === 'allow'
                                        ? '10.0.0.0/8 办公网\n192.168.0.0/16'
                                        : '10.0.0.9 那台机器在扫端口\n203.0.113.0/24 整段异常流量'
                                    }
                                    onChange={(e) => patchRow(r.key, { rules: e.target.value })}
                                  />
                                </div>

                                <div className="row tight">
                                  <button
                                    className="btn"
                                    onClick={() => setOpenKey(null)}
                                    disabled={busy}
                                  >
                                    收起
                                  </button>
                                  <span className="faint small">
                                    改动保存在本地，点上方「保存并生效」才会写进 config.json。
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
            这份名单库属于运行期配置，走 <code>PATCH /_goproxy/config</code> 的{' '}
            <code>ip_lists</code> 字段：先原子写回 <code>config.json</code>
            （旧文件备份为 <code>.bak</code>），再热重载；新配置在运行期加载不起来会自动回滚。
            改名时还会一并带上 <code>ip_list_renames</code>，让服务端把所有路由的引用
            在<b>同一次写</b>里改掉。
          </div>

          <Note kind="warn">
            删除一份<b>还被路由引用</b>的名单会被拒绝（<code>409 list_in_use</code>）：
            删掉它就会留下悬空引用，而「引用了一份不存在的名单」是不允许存在的状态 ——
            一条白名单引用写错名字如果被当成「没引用」，那就是静默放行所有人。
            要删就先去那些路由里取消勾选，或者直接用<b>改名</b>（改名会把引用一起改写）。
          </Note>
        </div>
      </Card>

      {/* ---------------- ② 全局黑名单 ---------------- */}
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

          <Note kind="info">
            全局黑名单<b>只有这一份，也不参与路由引用</b> —— 它对所有入口自动生效。
            这是刻意的：它的典型用途是「发现攻击源，立刻全网封禁」，
            拆成多份反而会让「我到底封干净了没有」这个最要紧的问题变难回答。
            需要按路由精细控制的部分放到上面的<b>地址列表</b>里。
          </Note>

          <Note kind="warn">
            它<b>同样作用于管理端口</b>。在这里加一条覆盖自己来源的规则，保存生效后
            这个控制台就打不开了 —— 后端因此会在保存前拦一道（自锁检查），
            真要封自己的网段只能改配置文件后重启。
            <br />
            正因为如此，保存全局黑名单只能靠<b>这个页面的写接口</b>；被封之后唯一的退路是
            改配置文件 + 重启，那条路不受护栏限制。
          </Note>
        </div>
      </Card>

      {/* ---------------- ③ 命中测试 ---------------- */}
      <Card title="名单命中测试" sub="只读，不改任何配置">
        <div className="stack">
          <Note kind="info">
            三层名单的先后顺序是固定的，光盯着配置列表很难在脑子里推出结果 ——
            特别是同一个地址既落在白名单里、又命中某份黑名单的时候。这里可以直接试一次：
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
                  {testResult.decision.list && (
                    <> · 来自名单「{testResult.decision.list}」</>
                  )}
                  {testResult.decision.layer && <> · 层：{testResult.decision.layer}</>}
                  {testResult.decision.note && <> · 备注：{testResult.decision.note}</>}
                </div>
              )}

              {!testResult.route_name && (
                <div className="small faint">
                  没选路由，所以路由引用的白名单 / 黑名单没有参与判定（下面两行会显示「未引用」）。
                  要连它们一起看，请在上面选一条路由再测一次。
                </div>
              )}

              {testResult.decision.steps?.length ? (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th className="nowrap">层</th>
                        <th className="nowrap">名单</th>
                        <th className="nowrap">是否配置</th>
                        <th className="nowrap">结果</th>
                        <th>说明</th>
                      </tr>
                    </thead>
                    <tbody>
                      {testResult.decision.steps.map((s, i) => (
                        <tr key={i}>
                          <td className="nowrap">{s.layer}</td>
                          <td className="nowrap">
                            {s.list ? (
                              <code className="mono-sm">{s.list}</code>
                            ) : (
                              <span className="faint">—</span>
                            )}
                          </td>
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

          {routeRev && (
            <div className="small faint">路由列表 revision {routeRev.slice(0, 12)}</div>
          )}
        </div>
      </Card>
    </div>
  )
}
