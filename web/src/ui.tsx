import { useEffect, useState, type ReactNode } from 'react'
import { copyText } from './hooks'

/* ============ 吐司 ============ */

export type ToastKind = 'ok' | 'err' | 'warn' | 'info'
export interface ToastItem {
  id: number
  kind: ToastKind
  text: string
}

let toastSeq = 0
let toastItems: ToastItem[] = []
const toastListeners = new Set<(items: ToastItem[]) => void>()

function emitToasts() {
  for (const l of toastListeners) l(toastItems)
}

/** 全局吐司。写操作成功/失败都用它，省得每个页面自己维护一份状态。 */
export function toast(kind: ToastKind, text: string, ttlMs = 4500): void {
  const id = ++toastSeq
  toastItems = [...toastItems, { id, kind, text }]
  emitToasts()
  window.setTimeout(() => dismissToast(id), ttlMs)
}

export function dismissToast(id: number): void {
  const next = toastItems.filter((t) => t.id !== id)
  if (next.length === toastItems.length) return
  toastItems = next
  emitToasts()
}

export function ToastHost() {
  const [items, setItems] = useState<ToastItem[]>(toastItems)

  useEffect(() => {
    const on = (next: ToastItem[]) => setItems(next)
    toastListeners.add(on)
    on(toastItems)
    return () => {
      toastListeners.delete(on)
    }
  }, [])

  if (items.length === 0) return null
  const mark: Record<ToastKind, string> = { ok: '✓', err: '✕', warn: '!', info: 'i' }

  return (
    <div className="toasts">
      {items.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          <span className="ico">{mark[t.kind]}</span>
          <div style={{ flex: 1, overflowWrap: 'anywhere' }}>{t.text}</div>
          <button className="close" onClick={() => dismissToast(t.id)} title="关闭">
            ×
          </button>
        </div>
      ))}
    </div>
  )
}

/* ============ 基础块 ============ */

export function Card({
  title,
  sub,
  actions,
  children,
  flush,
  style,
}: {
  title?: ReactNode
  sub?: ReactNode
  actions?: ReactNode
  children: ReactNode
  flush?: boolean
  style?: React.CSSProperties
}) {
  return (
    <section className="card" style={style}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {sub && <span className="sub">{sub}</span>}
          <div className="spacer" />
          {actions}
        </header>
      )}
      <div className={flush ? 'card-body flush' : 'card-body'}>{children}</div>
    </section>
  )
}

export function Field({
  label,
  hint,
  error,
  children,
  span,
}: {
  label: ReactNode
  hint?: ReactNode
  error?: string
  children: ReactNode
  span?: boolean
}) {
  return (
    <div className="field" style={span ? { gridColumn: '1 / -1' } : undefined}>
      <label className="label">{label}</label>
      {children}
      {error ? <div className="err">{error}</div> : hint ? <div className="hint">{hint}</div> : null}
    </div>
  )
}

export function Note({
  kind = 'info',
  span,
  children,
}: {
  kind?: 'info' | 'warn' | 'err' | 'ok'
  span?: boolean
  children: ReactNode
}) {
  const mark: Record<string, string> = { info: 'i', warn: '!', err: '✕', ok: '✓' }
  return (
    <div className={`note ${kind}`} style={span ? { gridColumn: '1 / -1' } : undefined}>
      <span className="ico">{mark[kind]}</span>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  )
}

export function Badge({
  kind = 'muted',
  dot,
  children,
}: {
  kind?: 'ok' | 'warn' | 'err' | 'info' | 'muted'
  dot?: boolean
  children: ReactNode
}) {
  return <span className={`badge ${kind}${dot ? ' dot' : ''}`}>{children}</span>
}

export function Empty({ icon = '∅', text }: { icon?: string; text: ReactNode }) {
  return (
    <div className="empty">
      <div className="big">{icon}</div>
      <div>{text}</div>
    </div>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="row tight">
      <span className="spinner" />
      {label && <span className="muted">{label}</span>}
    </span>
  )
}

export function Switch({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  label?: ReactNode
}) {
  return (
    <label className="switch">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="track" />
      {label && <span>{label}</span>}
    </label>
  )
}

export function Checkbox({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: ReactNode
  disabled?: boolean
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
  )
}

export function CopyBtn({ text, label = '复制' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className="btn ghost sm"
      onClick={async () => {
        const ok = await copyText(text)
        if (ok) {
          setDone(true)
          window.setTimeout(() => setDone(false), 1400)
        } else {
          toast('warn', '浏览器拒绝了剪贴板访问，请手动选中复制')
        }
      }}
    >
      {done ? '已复制' : label}
    </button>
  )
}

/* ============ 弹窗 ============ */

export function Modal({
  title,
  sub,
  onClose,
  footer,
  children,
  width = 780,
}: {
  title: ReactNode
  sub?: ReactNode
  onClose: () => void
  footer?: ReactNode
  children: ReactNode
  width?: number
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [onClose])

  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${width <= 560 ? ' sm' : ''}`} style={{ maxWidth: width }} role="dialog">
        <header className="modal-head">
          <h2>{title}</h2>
          {sub && <span className="sub faint small">{sub}</span>}
          <div className="spacer" />
          <button className="btn ghost icon" onClick={onClose} title="关闭 (Esc)">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  )
}

export function ConfirmDialog({
  title,
  message,
  confirmText = '确认',
  danger,
  onConfirm,
  onCancel,
  busy,
}: {
  title: ReactNode
  message: ReactNode
  confirmText?: string
  danger?: boolean
  onConfirm: () => void
  onCancel: () => void
  busy?: boolean
}) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      width={480}
      footer={
        <>
          <div className="spacer" />
          <button className="btn" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm} disabled={busy}>
            {busy ? '处理中…' : confirmText}
          </button>
        </>
      }
    >
      <div style={{ lineHeight: 1.7 }}>{message}</div>
    </Modal>
  )
}

/* ============ 自绘曲线图 ============ */

export interface ChartSeries {
  name: string
  color: string
  values: number[]
  /** 填充面积（只给主序列用，多了会糊成一团） */
  fill?: boolean
}

/**
 * 极简折线/面积图。
 *
 * 不引图表库：控制台只需要「最近 5 分钟的走势」这一个诉求，
 * 引 echarts / recharts 会让产物多出几百 KB，而这些都要塞进 Go 二进制。
 */
export function LineChart({
  labels,
  series,
  height = 180,
  yFormat = (v: number) => String(v),
  yMinTicks = 4,
}: {
  labels: string[]
  series: ChartSeries[]
  height?: number
  yFormat?: (v: number) => string
  yMinTicks?: number
}) {
  const W = 1000
  const H = height
  const padL = 46
  const padR = 10
  const padT = 10
  const padB = 22
  const innerW = W - padL - padR
  const innerH = H - padT - padB

  const all = series.flatMap((s) => s.values)
  const rawMax = all.length ? Math.max(...all) : 0
  const max = rawMax <= 0 ? 1 : rawMax * 1.15

  const n = Math.max(labels.length, series[0]?.values.length ?? 0, 1)
  const x = (i: number) => padL + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW)
  const y = (v: number) => padT + innerH - (v / max) * innerH

  const ticks = Math.max(yMinTicks, Math.min(6, yMinTicks))
  const gridVals: number[] = []
  for (let i = 0; i <= ticks; i++) gridVals.push((max / ticks) * i)

  const labelEvery = Math.max(1, Math.ceil(n / 8))

  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ height }}>
      {gridVals.map((v, i) => (
        <g key={i}>
          <line className="grid-line" x1={padL} x2={W - padR} y1={y(v)} y2={y(v)} />
          <text className="axis-text" x={padL - 6} y={y(v) + 3.5} textAnchor="end">
            {yFormat(v)}
          </text>
        </g>
      ))}

      {labels.map((lb, i) =>
        i % labelEvery === 0 || i === n - 1 ? (
          <text className="axis-text" key={i} x={x(i)} y={H - 6} textAnchor="middle">
            {lb}
          </text>
        ) : null,
      )}

      {series.map((s) => {
        const pts = s.values.map((v, i) => `${x(i)},${y(v)}`)
        if (pts.length === 0) return null
        const d = `M${pts.join(' L')}`
        return (
          <g key={s.name}>
            {s.fill && (
              <path
                d={`${d} L${x(s.values.length - 1)},${padT + innerH} L${padL},${padT + innerH} Z`}
                // 颜色统一走 style 而不是 fill/stroke 属性：
                // 表现属性对 var() 的支持在各浏览器上不一致，style 一定生效
                style={{ fill: s.color }}
                opacity={0.14}
              />
            )}
            <path d={d} style={{ fill: 'none', stroke: s.color, strokeWidth: 1.8 }} strokeLinejoin="round" />
          </g>
        )
      })}
    </svg>
  )
}
