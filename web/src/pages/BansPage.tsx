import { useCallback, useEffect, useState, type ReactNode } from 'react'
import * as api from '../api'
import type { BanEntry, BansState } from '../types'
import { Badge, Card, ConfirmDialog, Empty, Field, Note, Spinner, Switch, toast } from '../ui'
import {
  datetime,
  duration,
  honeypotPortsToText,
  looksLikeCIDR,
  num,
  parseHoneypotPorts,
  splitList,
} from '../format'
import { usePolling } from '../hooks'

/**
 * 蜜罐与封禁页。
 *
 * 这一页要把三件互相印证的事摆在一起，缺一件就会误判：
 *
 *   1. **配置**：开着吗、什么模式、盯哪几个端口。模式尤其要看清楚 ——
 *      observe 会监听、会记录，但一个都不封。只看到「命中 300 次」就以为在防护，
 *      是这页最容易产生的误解，所以模式用整块提示写在最上面。
 *   2. **端口状态**：配置里写了不等于真的在监听（端口被占、权限不足都会失败），
 *      所以每个端口都单独报「在不在听」加失败原因。
 *   3. **结果**：封了谁、封多久、为什么封（命中的是哪个端口、对方说了什么）。
 *
 * 数据来源上有一点要和别处区分开：自动封禁与蜜罐状态**不属于配置**
 * （不进 revision、不进 config_history、不出现在 -config-export 里），
 * 所以保存它不带 If-Match，也就不会出现 409。
 */
export function BansPage({ active }: { active: boolean }) {
  const [state, setState] = useState<BansState | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  /** 正在进行的动作：'' | save | ban | unban */
  const [busy, setBusy] = useState('')

  // 表单状态。它们只在「用户没改过」时才跟随服务端刷新，见 dirty。
  const [enabled, setEnabled] = useState(false)
  const [mode, setMode] = useState('observe')
  const [portsText, setPortsText] = useState('')
  const [exemptText, setExemptText] = useState('')
  const [banSecs, setBanSecs] = useState(3600)
  const [portsBad, setPortsBad] = useState<string[]>([])
  /**
   * dirty 表示「表单里有还没保存的改动」。
   *
   * 需要这个标记，是因为本页每 5 秒轮询一次：不加判断地拿服务端数据回填表单，
   * 会把正在输入的内容当场冲掉 —— 而且是在人打字打到一半的时候。
   * 一旦脏了就不再回填，改为提示「有未保存的改动」并给一个「放弃修改」。
   */
  const [dirty, setDirty] = useState(false)

  // 手动封禁
  const [banIP, setBanIP] = useState('')
  const [banReason, setBanReason] = useState('')
  const [banSecsInput, setBanSecsInput] = useState(24 * 3600)
  const [confirm, setConfirm] = useState<
    null | { kind: 'clear' | 'unban'; ip?: string; title: string; message: ReactNode }
  >(null)

  const applyConfig = useCallback((cfg: BansState['config']) => {
    setEnabled(cfg.enabled)
    setMode(cfg.mode || 'observe')
    setPortsText(honeypotPortsToText(cfg.ports))
    setExemptText((cfg.exempt ?? []).join('\n'))
    setBanSecs(cfg.ban_secs || 3600)
    setPortsBad([])
    setDirty(false)
  }, [])

  const load = useCallback(
    async (opts: { syncForm?: boolean } = {}) => {
      try {
        const s = await api.getBans()
        setState(s)
        setErr(null)
        if (opts.syncForm) applyConfig(s.config)
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e))
      } finally {
        setLoading(false)
      }
    },
    [applyConfig],
  )

  // 进这一页读一次，并把表单填上服务端的值。
  useEffect(() => {
    if (active) void load({ syncForm: true })
  }, [active, load])

  // 之后每 5 秒刷新**数据**；表单只有在没被改过时才跟着刷新。
  usePolling(
    async () => {
      const s = await api.getBans()
      setState(s)
      setErr(null)
      if (!dirty) applyConfig(s.config)
    },
    5000,
    active,
  )

  const doSave = useCallback(async () => {
    const { ports, bad } = parseHoneypotPorts(portsText)
    setPortsBad(bad)
    if (bad.length > 0) {
      // 少一个诱饵端口在界面上是看不出来的（列表里那一行只是不见了），
      // 所以解析不出来的行必须拦住、并指名道姓地报出来。
      toast('err', `有 ${bad.length} 行端口没看懂，先改掉：${bad[0]}`)
      return
    }
    if (enabled && ports.length === 0) {
      toast('err', '开了蜜罐却一个端口都没配 —— 这等于没开。先填端口，或先关掉开关。')
      return
    }
    setBusy('save')
    try {
      const res = await api.saveHoneypotConfig({
        enabled,
        mode,
        ban_secs: banSecs,
        exempt: splitList(exemptText),
        ports,
      })
      applyConfig(res.config)
      setState((prev) => (prev ? { ...prev, config: res.config, traps: res.traps ?? prev.traps } : prev))
      if (res.problems) {
        // 配置已经存下了，只是其中几个端口没起来。服务端刻意**不回滚**：
        // 回滚会造成「库里是 A、实际行为是 B」，比端口没起来更难查。
        toast('warn', '配置已保存，但有端口没生效：' + res.problems)
      } else {
        toast('ok', '蜜罐配置已保存并生效')
      }
      await load()
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
    }
  }, [enabled, mode, banSecs, exemptText, portsText, applyConfig, load])

  const doBan = useCallback(async () => {
    const ip = banIP.trim()
    // 网段走「IP 名单」页的黑名单 —— 人工封禁只接受单个地址（后端也只认单个 IP）。
    if (!looksLikeCIDR(ip) || ip.includes('/')) {
      toast('err', '人工封禁要填单个 IP 地址；要封一个网段请去「IP 名单」页加一条黑名单')
      return
    }
    setBusy('ban')
    try {
      const e = await api.createBan({ ip, reason: banReason.trim(), secs: banSecsInput })
      toast('ok', `已封禁 ${e.ip}，${datetime(e.expires_at)} 到期`)
      setBanIP('')
      setBanReason('')
      await load()
    } catch (e2) {
      toast('err', e2 instanceof Error ? e2.message : String(e2))
    } finally {
      setBusy('')
    }
  }, [banIP, banReason, banSecsInput, load])

  const doUnban = useCallback(
    async (ip: string) => {
      setConfirm(null)
      setBusy('unban')
      try {
        const res = await api.unban(ip)
        toast('ok', ip === 'all' ? `已清空全部封禁（${res.removed ?? 0} 条）` : `已解封 ${ip}`)
        await load()
      } catch (e) {
        toast('err', e instanceof Error ? e.message : String(e))
      } finally {
        setBusy('')
      }
    },
    [load],
  )

  if (loading && !state) return <Spinner label="正在读取封禁状态" />

  const cfg = state?.config
  const stats = state?.stats
  const entries = state?.entries ?? []
  const traps = state?.traps ?? []
  const recent = state?.recent ?? []
  const ladder = state?.ladder ?? []
  const nowMs = Date.now()
  const activeBans = entries.filter((e) => new Date(e.expires_at).getTime() > nowMs)
  const expired = entries.length - activeBans.length
  const observing = cfg?.enabled === true && cfg.mode !== 'enforce'
  const paused = stats?.paused_till ? new Date(stats.paused_till).getTime() > nowMs : false

  const remaining = (e: BanEntry): string => {
    const secs = Math.round((new Date(e.expires_at).getTime() - nowMs) / 1000)
    return secs > 0 ? '剩 ' + duration(secs) : '已到期'
  }

  return (
    <div className="stack">
      {err && <Note kind="warn">封禁状态读取失败：{err}</Note>}

      {cfg && !cfg.enabled && (
        <Note kind="info">
          蜜罐<b>没开</b>。开它的理由只有一条：正常用户没有任何理由去连一个没有服务的端口，
          所以「连上了」本身就是扫描的充分证据 —— 不需要评分，也不需要频率阈值。
          建议先配几个端口、跑一段 observe（只记录不封禁）确认没有误报，再切 enforce。
        </Note>
      )}
      {observing && (
        <Note kind="warn">
          <b>当前是观察模式（observe）</b>：命中只记录、<b>一个都不封</b>。「最近命中」里
          那些地址就是<b>开启 enforce 之后会被封的</b>。确认里面没有自己人
          （NAT 出口、监控探针、你自己的扫描器）再切过去。
        </Note>
      )}
      {cfg?.enabled && cfg.mode === 'enforce' && (
        <Note kind="err">
          当前是<b>执行模式（enforce）</b>：命中即封禁，没有阈值、也没有观察窗。
          封禁只作用于本进程服务的业务端口 —— 管理端口不受自动封禁影响，所以不会被自己锁在门外。
          阶梯：{ladder.length > 0 ? ladder.join(' → ') : '按基准时长'}。
        </Note>
      )}
      {paused && (
        <Note kind="warn">
          自动封禁正处在<b>突发熔断</b>中（到 {datetime(stats?.paused_till)} 为止只记录、不写入）：
          一分钟内新增来源超过阈值，说明这更像一次全网扫描 —— 那类地址连一次就走，
          封禁收益很低，不值得把库撑爆。人工封禁不受影响。
        </Note>
      )}

      <Card
        title="概览"
        actions={
          <button className="btn ghost sm" onClick={() => void load({ syncForm: !dirty })} disabled={busy !== ''}>
            刷新
          </button>
        }
      >
        <div className="metrics">
          <div className="metric">
            <div className="label">当前生效</div>
            <div className="value">{num(stats?.active ?? 0)}</div>
            <div className="foot">正在被拒的地址数</div>
          </div>
          <div className="metric">
            <div className="label">记忆窗口内</div>
            <div className="value">{num(stats?.known ?? 0)}</div>
            <div className="foot">含已到期，决定下次从第几级开始</div>
          </div>
          <div className="metric">
            <div className="label">累计拦下请求</div>
            <div className="value">{num(stats?.blocked ?? 0)}</div>
            <div className="foot">被封地址在本进程被拒的次数</div>
          </div>
          <div className="metric">
            <div className="label">因豁免未封</div>
            <div className="value">{num(stats?.exempted ?? 0)}</div>
            <div className="foot">
              基准时长 <span className="mono">{stats?.base_duration || '-'}</span>
            </div>
          </div>
        </div>
      </Card>

      <Card
        title="蜜罐端口"
        sub="填那些本来就没有服务的端口，比如 23 / 3389 / 5900 —— 别填自己正在用的（会被服务端拦下）"
        actions={
          dirty ? (
            <span className="pill-row">
              <Badge kind="warn" dot>
                有未保存的改动
              </Badge>
              <button className="btn ghost sm" onClick={() => void load({ syncForm: true })} disabled={busy !== ''}>
                放弃修改
              </button>
            </span>
          ) : undefined
        }
      >
        <div className="stack">
          {/* 用 Field（标签在上、控件在下）而不是把标签和控件塞进同一行：
              后者会被父级的 flex 换行挤成两行，看着像排版坏了。这也是「配置」页
              一贯的写法，两页看起来才是一套东西。 */}
          <div className="grid3">
            <Field label="蜜罐开关" hint="默认关闭。先跑 observe 看一轮确认没有误报，再切 enforce。">
              <Switch
                checked={enabled}
                onChange={(v) => (setEnabled(v), setDirty(true))}
                label={enabled ? '已启用' : '已关闭'}
              />
            </Field>
            <Field label="模式" hint="observe 只记录；enforce 命中即封禁。">
              <select className="select" value={mode} onChange={(e) => (setMode(e.target.value), setDirty(true))}>
                <option value="observe">observe —— 只记录，不封禁</option>
                <option value="enforce">enforce —— 命中即封禁</option>
              </select>
            </Field>
            <Field label="基准时长（秒）" hint="第 1 次封这么久，之后 ×6 → ×24 → 封顶 7 天。">
              <input
                className="input"
                type="number"
                min={60}
                value={banSecs}
                onChange={(e) => (setBanSecs(Number(e.target.value)), setDirty(true))}
              />
            </Field>
          </div>

          <div className="grid2">
            <Field
              label="端口列表"
              hint={
                <>
                  每行一个，可写 <span className="mono">5900/udp</span>，备注跟在后面。
                </>
              }
              error={portsBad.length > 0 ? `这几行没看懂，保存会被拦下：${portsBad.join(' / ')}` : undefined}
            >
              <textarea
                className={`textarea${portsBad.length > 0 ? ' invalid' : ''}`}
                rows={5}
                spellCheck={false}
                placeholder={'23\n3389\n5900/udp   VNC'}
                value={portsText}
                onChange={(e) => {
                  const v = e.target.value
                  setPortsText(v)
                  setDirty(true)
                  setPortsBad(parseHoneypotPorts(v).bad)
                }}
              />
            </Field>

            <Field
              label="额外豁免"
              hint="本地网段、trusted_proxies、命中白名单、最近用过控制台的来源，都已在代码里硬豁免。这里只填「你知道、代码不知道」的地址。"
            >
              <textarea
                className="textarea"
                rows={5}
                spellCheck={false}
                placeholder={'203.0.113.0/24  办公网出口'}
                value={exemptText}
                onChange={(e) => (setExemptText(e.target.value), setDirty(true))}
              />
            </Field>
          </div>

          <div className="row">
            <button className="btn primary" onClick={() => void doSave()} disabled={busy !== ''}>
              {busy === 'save' ? '保存中' : '保存并生效'}
            </button>
            <span className="small faint">
              保存后立即生效，不用重启。切换模式不需要重配端口。
            </span>
          </div>
        </div>
      </Card>

      <Card title="端口状态" sub="配置里写了不等于真的在监听：端口被占或权限不足都会失败，逐个列出来" flush>
        {traps.length === 0 ? (
          <Empty text="没有配置任何蜜罐端口" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="nowrap">端口</th>
                  <th>状态</th>
                  <th className="nowrap">命中</th>
                  <th className="nowrap">去重来源</th>
                  <th className="nowrap">首次</th>
                  <th className="nowrap">最近</th>
                  <th>备注</th>
                </tr>
              </thead>
              <tbody>
                {traps.map((t) => (
                  <tr key={`${t.proto}/${t.port}`}>
                    <td className="mono nowrap">
                      {t.proto}/{t.port}
                    </td>
                    <td>
                      {t.listening ? (
                        <Badge kind="ok" dot>
                          监听中
                        </Badge>
                      ) : (
                        <Badge kind="err" dot title={t.error}>
                          没起来
                        </Badge>
                      )}
                      {t.error && <div className="small faint">{t.error}</div>}
                    </td>
                    <td className="mono-sm nowrap">{num(t.hits)}</td>
                    <td className="mono-sm nowrap">{num(t.distinct_ips)}</td>
                    <td className="small faint nowrap">{t.first_at ? datetime(t.first_at) : '-'}</td>
                    <td className="small faint nowrap">{t.last_at ? datetime(t.last_at) : '-'}</td>
                    <td className="small faint">{t.note || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="最近命中" sub="对方发来的前 64 字节 —— 多数扫描器连上就关，所以常常是空的" flush>
        {recent.length === 0 ? (
          <Empty text={cfg?.enabled ? '还没有命中' : '蜜罐没开，不会记录命中'} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="nowrap">时间</th>
                  <th className="nowrap">来源</th>
                  <th className="nowrap">端口</th>
                  <th>样本</th>
                </tr>
              </thead>
              <tbody>
                {recent
                  .slice(-50)
                  .reverse()
                  .map((p, i) => (
                    <tr key={`${p.time}-${p.ip}-${i}`}>
                      <td className="small faint nowrap">{datetime(p.time)}</td>
                      <td className="mono-sm nowrap">{p.ip}</td>
                      <td className="mono-sm nowrap">
                        {p.proto}/{p.port}
                      </td>
                      <td className="mono-sm" style={{ overflowWrap: 'anywhere' }}>
                        {p.head || <span className="faint">（连上就关，没有内容）</span>}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="small faint" style={{ padding: '8px 14px' }}>
          样本内容来自攻击者，这里按<b>纯文本</b>渲染（React 默认转义、不走 innerHTML）——
          否则它就成了一个能在控制台里执行脚本的入口。
        </div>
      </Card>

      <Card title="手动封禁" sub="人明确做出的决定：不看豁免、不参与突发熔断，并且立刻落盘">
        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <input
            className="input"
            style={{ maxWidth: 200 }}
            placeholder="1.2.3.4"
            value={banIP}
            onChange={(e) => setBanIP(e.target.value)}
          />
          <input
            className="input"
            style={{ maxWidth: 260 }}
            placeholder="原因（可空，默认 manual）"
            value={banReason}
            onChange={(e) => setBanReason(e.target.value)}
          />
          <label className="row" style={{ gap: 6 }}>
            <span className="small">时长（秒）</span>
            <input
              className="input"
              type="number"
              min={60}
              style={{ width: 120 }}
              value={banSecsInput}
              onChange={(e) => setBanSecsInput(Number(e.target.value))}
            />
          </label>
          <button className="btn" onClick={() => void doBan()} disabled={busy !== '' || banIP.trim() === ''}>
            封禁这个地址
          </button>
        </div>
        <div className="small faint" style={{ marginTop: 8 }}>
          封了之后，这个地址在本进程的所有业务端口上都会拿到 403（空响应体），管理端口不受影响。
          解封三条路：这里点解封、加进「IP 名单」页的白名单（立刻生效）、或等它到期。
        </div>
      </Card>

      <Card
        title="封禁列表"
        sub={
          activeBans.length > 0
            ? `生效 ${activeBans.length} 条${expired > 0 ? `，另有 ${expired} 条已到期（留着决定下次的阶梯层级）` : ''}`
            : expired > 0
              ? `没有生效中的封禁；${expired} 条已到期（留着决定下次的阶梯层级）`
              : '当前没有任何封禁'
        }
        actions={
          entries.length > 0 ? (
            <button
              className="btn danger sm"
              disabled={busy !== ''}
              onClick={() =>
                setConfirm({
                  kind: 'clear',
                  title: '清空全部封禁',
                  message: (
                    <>
                      将解除全部 {entries.length} 条封禁（含已到期的记录）。这些地址如果还在扫，
                      会被重新探测到并重新封上 —— 但阶梯会从第 1 级重新开始。
                    </>
                  ),
                })
              }
            >
              全部清空
            </button>
          ) : undefined
        }
        flush
      >
        {entries.length === 0 ? (
          <Empty text="没有封禁记录" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="nowrap">IP</th>
                  <th className="nowrap">来源</th>
                  <th>原因</th>
                  <th className="nowrap">阶梯</th>
                  <th className="nowrap">命中</th>
                  <th className="nowrap">到期</th>
                  <th>样本</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => {
                  const isActive = new Date(e.expires_at).getTime() > nowMs
                  const samples = e.samples ?? []
                  return (
                    <tr key={e.ip} style={isActive ? undefined : { opacity: 0.55 }}>
                      <td className="mono-sm nowrap">{e.ip}</td>
                      <td className="nowrap">
                        {e.source === 'manual' ? (
                          <Badge kind="info" dot title="人工封禁">
                            人工
                          </Badge>
                        ) : (
                          <Badge kind="warn" dot title="蜜罐命中后自动封禁">
                            蜜罐
                          </Badge>
                        )}
                      </td>
                      <td className="small">
                        <span className="mono-sm">{e.reason || '-'}</span>
                        {e.last_at && <span className="faint"> · 最近 {datetime(e.last_at)}</span>}
                      </td>
                      <td className="small nowrap">第 {e.level} 次</td>
                      <td className="mono-sm nowrap">{num(e.hits)}</td>
                      <td className="small nowrap">
                        {isActive ? (
                          <>
                            {datetime(e.expires_at)}
                            <span className="faint"> · {remaining(e)}</span>
                          </>
                        ) : (
                          <span className="faint">已到期（{datetime(e.expires_at)}）</span>
                        )}
                      </td>
                      <td className="mono-sm" style={{ overflowWrap: 'anywhere', maxWidth: 300 }}>
                        {samples.length === 0 ? (
                          <span className="faint">-</span>
                        ) : (
                          <span title={samples.join('\n')}>
                            {samples[0]}
                            {samples.length > 1 && <span className="faint"> +{samples.length - 1}</span>}
                          </span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn ghost sm"
                          disabled={busy !== ''}
                          onClick={() =>
                            setConfirm({
                              kind: 'unban',
                              ip: e.ip,
                              title: `解封 ${e.ip}`,
                              message: (
                                <>
                                  解除这一条。若这个地址继续扫，会被重新探测到并重新封上 ——
                                  阶梯层级留在记忆窗口里，7 天内再来就从下一级开始。
                                </>
                              ),
                            })
                          }
                        >
                          解封
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Note kind="info">
        本页的数据（封禁条目、蜜罐命中）不属于配置：不进 revision、不进 config_history，
        也不出现在 <span className="mono">-config-export</span> 里 —— 所以在这里保存，
        不会跟正在编辑路由的人撞 409。命令行的 <span className="mono">-bans</span> /{' '}
        <span className="mono">-unban</span> 读写的是同一份数据，改完这里最多一分钟就能看到。
      </Note>

      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          message={confirm.message}
          confirmText={confirm.kind === 'clear' ? '确认清空' : '确认解封'}
          danger
          busy={busy !== ''}
          onCancel={() => setConfirm(null)}
          onConfirm={() => void doUnban(confirm.kind === 'clear' ? 'all' : (confirm.ip ?? ''))}
        />
      )}
    </div>
  )
}
