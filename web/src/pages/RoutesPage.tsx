import { useCallback, useEffect, useMemo, useState } from 'react'
import * as api from '../api'
import { ApiError } from '../api'
import type { Route } from '../types'
import { Badge, Card, ConfirmDialog, Empty, Note, Spinner, Switch, toast } from '../ui'
import { usePolling } from '../hooks'
import { ms, num } from '../format'
import { RouteForm, summarize } from './RouteForm'

export function RoutesPage({
  active = true,
  onChanged,
}: {
  /** 当前是不是正显示这一页。切回来时会立刻重读一次配置。 */
  active?: boolean
  onChanged: () => void
}) {
  const [routes, setRoutes] = useState<Route[]>([])
  const [rev, setRev] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ route: Route | null; isCreate: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<Route | null>(null)
  const [query, setQuery] = useState('')
  const [onlyDisabled, setOnlyDisabled] = useState(false)
  const [adminPort, setAdminPort] = useState(0)

  const load = useCallback(async () => {
    try {
      const { routes: list, revision } = await api.listRoutes()
      setRoutes(list)
      setRev(revision)
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

  useEffect(() => {
    api
      .getConfig()
      .then(({ config }) => {
        const m = /:(\d+)$/.exec(config.admin_addr ?? '')
        setAdminPort(m ? Number(m[1]) : 0)
      })
      .catch(() => {
        /* 拿不到管理端口只是少一层前端校验，后端仍会拦 */
      })
  }, [])

  // 实时观测值由服务端每 5 秒同步一次，跟着它的节奏刷就够了。
  // 弹窗打开或正在提交时停掉：避免把用户正在编辑的那条路由的旧数据糊到界面上。
  //
  // active && 那一段是为了「切回本页时立刻重读」：usePolling 在启用时会马上跑一次。
  // 这很关键 —— revision 是给 If-Match 用的，而「IP 名单」页改的是**同一个**配置文件，
  // 拿着过期 revision 去保存会先撞一次 409（用户会看到「请再操作一次」）。
  // 顺带的好处：停在别的页签上时不再有后台请求。
  usePolling(load, 5000, active && !editing && !busy && !pendingDelete)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return routes.filter((r) => {
      if (onlyDisabled && r.enabled !== false) return false
      if (!q) return true
      return [r.id, r.name, r.host, r.path_prefix, r.target, String(r.listen_port)]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q))
    })
  }, [routes, query, onlyDisabled])

  const handleError = (e: unknown) => {
    if (e instanceof ApiError && e.isConflict) {
      toast('warn', '配置已被其它页面/进程修改，已为你重新加载，请再操作一次')
      void load()
      return
    }
    toast('err', e instanceof Error ? e.message : String(e))
  }

  const submit = async (route: Route) => {
    setBusy(true)
    try {
      if (editing?.isCreate) {
        const res = await api.createRoute(route, rev)
        toast('ok', `路由 ${res.route?.id ?? route.id} 已创建`)
      } else {
        await api.replaceRoute(route, rev)
        toast('ok', `路由 ${route.id} 已保存`)
      }
      setEditing(null)
      await load()
      onChanged()
    } catch (e) {
      handleError(e)
    } finally {
      setBusy(false)
    }
  }

  const toggle = async (route: Route, enabled: boolean) => {
    setBusy(true)
    // 乐观更新：开关立刻跟手，失败再回滚。整表重拉会有明显的卡顿感。
    setRoutes((prev) => prev.map((r) => (r.id === route.id ? { ...r, enabled } : r)))
    try {
      await api.patchRoute(route.id, { enabled }, rev)
      toast('ok', `路由 ${route.id} 已${enabled ? '启用' : '停用'}`)
      await load()
      onChanged()
    } catch (e) {
      setRoutes((prev) => prev.map((r) => (r.id === route.id ? { ...r, enabled: !enabled } : r)))
      handleError(e)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (route: Route) => {
    setBusy(true)
    try {
      const res = await api.deleteRoute(route.id, rev)
      toast(
        'ok',
        `已删除 ${route.id}；当前 ${res.routes} 条路由，监听端口 ${(res.ports ?? []).join(', ') || '无'}`,
      )
      setPendingDelete(null)
      await load()
      onChanged()
    } catch (e) {
      handleError(e)
    } finally {
      setBusy(false)
    }
  }

  const disabledCount = routes.filter((r) => r.enabled === false).length

  return (
    <div className="stack">
      {err && <Note kind="err">读取路由失败：{err}</Note>}

      <Card
        title="路由"
        sub={`共 ${routes.length} 条${disabledCount > 0 ? ` · 已停用 ${disabledCount}` : ''}`}
        flush
        actions={
          <>
            <div className="search toolbar" style={{ padding: 0, border: 0, background: 'transparent' }}>
              <input
                className="input"
                style={{ minWidth: 235 }}
                placeholder="搜 ID / 名称 / 域名 / 路径 / 后端"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <label className="check">
                <input
                  type="checkbox"
                  checked={onlyDisabled}
                  onChange={(e) => setOnlyDisabled(e.target.checked)}
                />
                <span>只看停用</span>
              </label>
            </div>
            <button className="btn ghost" onClick={() => void load()} disabled={busy}>
              刷新
            </button>
            <button
              className="btn primary"
              onClick={() => setEditing({ route: null, isCreate: true })}
              disabled={busy}
            >
              + 新建路由
            </button>
          </>
        }
      >
        {loading ? (
          <div style={{ padding: 20 }}>
            <Spinner label="正在读取路由…" />
          </div>
        ) : filtered.length === 0 ? (
          <Empty
            icon="⛓"
            text={
              routes.length === 0
                ? '还没有任何路由。点右上角「新建路由」加一条，或直接编辑 config.json（会自动热重载）。'
                : '没有匹配的条目'
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th className="nowrap">状态</th>
                  <th>路由</th>
                  <th className="nowrap">匹配规则</th>
                  <th>后端</th>
                  <th className="nowrap">能力</th>
                  <th className="right nowrap">请求</th>
                  <th className="right nowrap">拦截</th>
                  <th className="right nowrap">在途</th>
                  <th className="right nowrap">均值</th>
                  <th className="nowrap">熔断</th>
                  <th className="right nowrap">操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <RouteRow
                    key={r.id}
                    route={r}
                    busy={busy}
                    onToggle={(v) => void toggle(r, v)}
                    onEdit={() => setEditing({ route: r, isCreate: false })}
                    onDelete={() => setPendingDelete(r)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {editing && (
        <RouteForm
          initial={editing.route}
          isCreate={editing.isCreate}
          adminPort={adminPort}
          busy={busy}
          onSubmit={(r) => void submit(r)}
          onCancel={() => setEditing(null)}
        />
      )}

      {pendingDelete && (
        <ConfirmDialog
          danger
          busy={busy}
          title="删除路由"
          confirmText="删除"
          message={
            <>
              确定要删除路由 <code>{pendingDelete.id}</code>
              {pendingDelete.name ? `（${pendingDelete.name}）` : ''} 吗？
              <div style={{ marginTop: 8 }} className="faint small">
                配置会原子写回磁盘并立即热重载；如果这个端口上没有别的路由了，监听也会自动关掉。
                原配置会备份到 <code>config.json.bak</code>。
              </div>
            </>
          }
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => void remove(pendingDelete)}
        />
      )}
    </div>
  )
}

function RouteRow({
  route: r,
  busy,
  onToggle,
  onEdit,
  onDelete,
}: {
  route: Route
  busy: boolean
  onToggle: (v: boolean) => void
  onEdit: () => void
  onDelete: () => void
}) {
  const live = r.live
  const tags = summarize(r)
  const cb = live?.circuit_breaker
  const disabled = r.enabled === false

  return (
    <tr className={disabled ? 'disabled' : undefined}>
      <td className="nowrap">
        <Switch checked={!disabled} disabled={busy} onChange={onToggle} />
      </td>

      <td>
        <div className="row tight" style={{ gap: 7 }}>
          <code style={{ fontWeight: 600 }}>{r.id}</code>
          {disabled && <Badge kind="muted">已停用</Badge>}
        </div>
        {r.name && <div className="faint small">{r.name}</div>}
      </td>

      <td className="nowrap">
        <div className="tag-list">
          <Badge kind={r.listen_port ? 'info' : 'muted'}>
            {r.listen_port ? `:${r.listen_port}` : '全部端口'}
          </Badge>
          <Badge kind={r.host ? 'info' : 'muted'}>{r.host || '任意域名'}</Badge>
          <span className="mono-sm" style={{ alignSelf: 'center' }}>
            {r.path_prefix}
          </span>
        </div>
      </td>

      <td>
        <div className="mono-sm" style={{ overflowWrap: 'anywhere' }}>
          {r.target}
        </div>
        <div className="faint small">
          {r.strip_prefix && '剥离前缀'}
          {r.strip_prefix && r.preserve_host && ' · '}
          {r.preserve_host && '保留 Host'}
          {(r.strip_prefix || r.preserve_host) && r.timeout_ms ? ' · ' : ''}
          {r.timeout_ms ? `超时 ${ms(r.timeout_ms)}` : ''}
        </div>
      </td>

      <td className="nowrap">
        {tags.length === 0 ? (
          <span className="faint">—</span>
        ) : (
          <div className="tag-list">
            {tags.map((t) => (
              <Badge key={t} kind="warn">
                {t}
              </Badge>
            ))}
          </div>
        )}
      </td>

      <td className="right mono-sm">{num(live?.requests_total ?? 0)}</td>
      <td className="right mono-sm">
        {(live?.rejected_total ?? 0) + (live?.rate_limited_total ?? 0) > 0 ? (
          <span style={{ color: 'var(--warn)' }}>
            {num((live?.rejected_total ?? 0) + (live?.rate_limited_total ?? 0))}
          </span>
        ) : (
          <span className="faint">0</span>
        )}
      </td>
      <td className="right mono-sm">{num(live?.in_flight ?? 0)}</td>
      <td className="right mono-sm">{live && live.avg_ms > 0 ? ms(live.avg_ms) : <span className="faint">—</span>}</td>

      <td className="nowrap">
        {!cb ? (
          <span className="faint">—</span>
        ) : cb.state === 'open' ? (
          <Badge kind="err" dot>
            打开
          </Badge>
        ) : cb.state === 'half_open' ? (
          <Badge kind="warn" dot>
            半开
          </Badge>
        ) : (
          <Badge kind="ok" dot>
            闭合
          </Badge>
        )}
      </td>

      <td className="right nowrap">
        <button className="btn ghost sm" onClick={onEdit} disabled={busy}>
          编辑
        </button>
        <button className="btn ghost sm" onClick={onDelete} disabled={busy} title="删除">
          删除
        </button>
      </td>
    </tr>
  )
}
