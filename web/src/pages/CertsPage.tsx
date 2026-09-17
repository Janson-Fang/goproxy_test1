import { useEffect, useState } from 'react'
import * as api from '../api'
import type { CertStatus, CertsResponse, PortInfo } from '../types'
import { Badge, Card, Empty, Note, Spinner } from '../ui'
import { datetime } from '../format'

/**
 * 证书页。
 *
 * 只读展示 —— 证书的增删改都发生在 config.json 里（路由的 tls_mode /
 * cert_file / key_file）。控制台刻意不做证书上传：在服务端接收私钥并落盘
 * 是个需要谨慎设计的动作（权限、路径穿越、覆盖已有文件），
 * 不适合在「TLS 刚打通」这一步顺手塞进来。
 */
export function CertsPage() {
  const [data, setData] = useState<CertsResponse | null>(null)
  const [ports, setPorts] = useState<PortInfo[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [c, p] = await Promise.all([api.getCerts(), api.getPorts()])
      setData(c)
      setPorts(p)
      setErr(null)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    const t = window.setInterval(() => void load(), 15_000)
    return () => window.clearInterval(t)
  }, [])

  if (loading) return <Spinner label="正在读取证书状态…" />

  return (
    <div className="stack">
      {err && (
        <Note kind="warn">
          证书状态读取失败：{err}
        </Note>
      )}

      <Card
        title="监听端口"
        sub="同一个端口要么全明文、要么全 TLS —— 加密与否只由端口决定，不由客户端决定"
        actions={
          <button className="btn ghost sm" onClick={() => void load()}>
            刷新
          </button>
        }
        flush
      >
        {ports.length === 0 ? (
          <Empty text="还没有监听任何端口" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>端口</th>
                  <th>传输</th>
                </tr>
              </thead>
              <tbody>
                {ports.map((p) => (
                  <tr key={p.port}>
                    <td className="mono">:{p.port}</td>
                    <td>
                      {p.tls ? (
                        <Badge kind="ok">TLS</Badge>
                      ) : (
                        <Badge kind="muted">明文 HTTP</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="证书"
        sub={
          data?.tls_enabled
            ? `TLS 已启用 · ACME 目录 ${data.acme_dir || 'Let\'s Encrypt 生产环境'}`
            : 'TLS 未启用'
        }
        flush
      >
        {!data?.tls_enabled ? (
          <div style={{ padding: 18 }}>
            <Note kind="info">
              顶层 <code>tls.enabled</code> 为 <code>false</code>，所有端口跑明文 HTTP。
              要启用 HTTPS，在 <code>config.json</code> 里加上：
              <pre className="code">{`"tls": {
  "enabled": true,
  "acme": { "email": "you@example.com" }
}`}</pre>
              打开后路由默认走 <code>auto</code>（ACME 自动签发），
              也可以逐条改成 <code>manual</code>（挂本地证书）或 <code>off</code>（保持明文）。
            </Note>
          </div>
        ) : (data.certs?.length ?? 0) === 0 ? (
          <Empty text="还没有任何证书 —— 给路由配上 tls_mode=auto 或 manual 即可" />
        ) : (
          <CertTable certs={data.certs} />
        )}
      </Card>
    </div>
  )
}

function CertTable({ certs }: { certs: CertStatus[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>域名</th>
            <th>来源</th>
            <th>签发者</th>
            <th>到期</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          {certs.map((c, i) => (
            <tr key={`${c.hosts.join(',')}-${c.source}-${i}`}>
              <td className="mono">
                {c.hosts.map((h) => (
                  <div key={h}>{h}</div>
                ))}
                {c.routes && c.routes.length > 0 && (
                  <div className="faint small">路由：{c.routes.join(', ')}</div>
                )}
              </td>
              <td>
                {c.source === 'auto' ? <Badge kind="info">ACME 自动</Badge> : <Badge kind="muted">手动挂载</Badge>}
              </td>
              <td className="small">{c.issuer || <span className="faint">—</span>}</td>
              <td className="small nowrap">
                {c.not_after ? (
                  <>
                    <div>{datetime(c.not_after)}</div>
                    <div className="faint">剩余 {c.days_left} 天</div>
                  </>
                ) : (
                  <span className="faint">—</span>
                )}
              </td>
              <td>
                <CertState cert={c} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/**
 * 证书状态徽章。
 *
 * 顺序有讲究：先判错误、再判过期、最后判临期。
 * 一张加载失败的证书 days_left 是 0，如果先判天数就会显示成「即将过期」，
 * 把「根本没读进来」这个更严重的问题掩盖掉。
 */
function CertState({ cert }: { cert: CertStatus }) {
  if (cert.error) {
    return (
      <div className="stack tight">
        <Badge kind="err" dot>
          异常
        </Badge>
        <div className="faint small" style={{ maxWidth: 320, overflowWrap: 'anywhere' }}>
          {cert.error}
        </div>
      </div>
    )
  }
  if (cert.expired) {
    return (
      <Badge kind="err" dot>
        已过期
      </Badge>
    )
  }
  if (cert.expiring) {
    return (
      <Badge kind="warn" dot>
        即将到期
      </Badge>
    )
  }
  return (
    <Badge kind="ok" dot>
      有效
    </Badge>
  )
}
