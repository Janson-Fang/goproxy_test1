import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import * as api from '../api'
import type { UpgradeCheck, UpgradeState } from '../types'
import { Badge, Card, ConfirmDialog, Empty, Note, Spinner, toast } from '../ui'
import { bytes, datetime } from '../format'
import { usePolling } from '../hooks'

/**
 * 升级页。
 *
 * 这是整套控制台里唯一会改动「二进制文件本身」的页面，所以它和别的页面
 * 有三点不同：
 *
 *  1. 每一步都先把「会发生什么」摆出来（目标版本、来源、sha256、备份到哪、
 *     重启方式），再让人点确认。升级失败不像改错一条路由那样容易挽回。
 *  2. 危险动作一律二次确认。
 *  3. 安装成功后进程会被替换掉，这中间接口是连不上的。页面自己盯着接口
 *     恢复，而不是把一个「请求失败」甩给用户：那个失败是预期内的。
 */
export function UpgradePage({ active }: { active: boolean }) {
  const [state, setState] = useState<UpgradeState | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  /** 正在进行的动作：'' | check | install | upload | rollback */
  const [busy, setBusy] = useState('')
  const [check, setCheck] = useState<UpgradeCheck | null>(null)
  const [pinned, setPinned] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [progress, setProgress] = useState<{ loaded: number; total: number } | null>(null)
  const [confirm, setConfirm] = useState<null | { kind: 'install' | 'rollback'; title: string; message: ReactNode }>(null)
  /** 安装完成之后等进程回来：记录从哪一版升到哪一版、等到什么时候为止 */
  const [pending, setPending] = useState<null | { from: string; to: string; until: number }>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    try {
      const s = await api.getUpgradeState()
      setState(s)
      setErr(null)
      // 上一次检查的结论由服务端记着，刷新页面不用重新联网检查一遍
      if (s.last_check) setCheck((c) => c ?? (s.last_check as UpgradeCheck))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (active) void load()
  }, [active, load])

  // 换进程那几秒接口必然连不上，这里按秒重试到它回来为止。
  usePolling(
    async () => {
      try {
        const s = await api.getUpgradeState()
        setState(s)
        setErr(null)
        if (!pending) return
        if (s.runtime.version !== pending.from) {
          toast('ok', `服务已恢复，当前版本 ${s.runtime.version}`)
          setPending(null)
        } else if (Date.now() > pending.until) {
          toast('warn', '服务回来了但还是旧版本：请到服务器上看进程日志（journalctl -u goproxy）')
          setPending(null)
        }
      } catch {
        if (pending && Date.now() > pending.until) {
          toast('warn', '重启后一分钟都没连上管理端口：请确认服务是不是起来了')
          setPending(null)
        }
      }
    },
    1000,
    pending !== null,
  )

  const doCheck = useCallback(async (version: string) => {
    setBusy('check')
    try {
      const res = await api.checkUpgrade(version)
      setCheck(res)
      toast(
        res.update_available ? 'info' : 'ok',
        res.update_available ? `发现新版本 ${res.latest}` : `已是最新（${res.latest}）`,
      )
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
    }
  }, [])

  const doInstall = useCallback(async (req: { source: 'github' | 'upload'; version?: string; sha256?: string; force?: boolean }) => {
    setConfirm(null)
    setBusy('install')
    try {
      const res = await api.installUpgrade(req)
      toast('info', `已写入 ${res.to}，正在重启服务`)
      setPending({ from: res.from, to: res.to, until: Date.now() + 60_000 })
      setFile(null)
      setProgress(null)
      if (fileRef.current) fileRef.current.value = ''
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
    }
  }, [])

  const doUpload = useCallback(async () => {
    if (!file) return
    setBusy('upload')
    setProgress({ loaded: 0, total: file.size })
    try {
      // 上传完服务端会顺手验证一遍（跑一次 -version 并算 sha256），
      // 所以这里拿回来的暂存信息就是「能装的东西」，不需要再问一次。
      const staged = await api.uploadUpgradeBinary(file, (loaded, total) => setProgress({ loaded, total }))
      toast('ok', `已接收并验证：${staged.version ?? '版本未知'}`)
      await load()
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
      setProgress(null)
    }
  }, [file, load])

  const doRollback = useCallback(async () => {
    setConfirm(null)
    setBusy('rollback')
    try {
      const res = await api.rollbackUpgrade()
      toast('info', `正在切回 ${res.to}`)
      setPending({ from: res.from, to: res.to, until: Date.now() + 60_000 })
    } catch (e) {
      toast('err', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
    }
  }, [])

  if (loading && !state) return <Spinner label="正在读取版本信息" />

  const rt = state?.runtime
  const supported = state?.supported ?? false

  return (
    <div className="stack">
      {err && <Note kind="warn">版本接口读取失败：{err}</Note>}

      {pending && (
        <Note kind="info">
          正在替换进程：{pending.from} 切换为 {pending.to}。这几秒里管理接口会短暂连不上，
          页面正在自动重试，恢复后会自动报出新版本。
        </Note>
      )}

      {!supported && state && (
        <Note kind="err">
          这台机器上不能自升级：{state.reason || '未知原因'}
          <br />
          <span className="faint small">
            上传、安装、回退三个动作都会被服务端拒绝（409），这是刻意的：升级一个跑在
            临时目录里、或目录不可写的实例，只会让人以为升级成功了。
          </span>
        </Note>
      )}

      <Card
        title="当前版本"
        sub="版本号由 git tag 驱动（见 Makefile），所以它同时告诉你「跑的是哪一段代码」"
        actions={
          <button className="btn ghost sm" onClick={() => void load()} disabled={busy !== ''}>
            刷新
          </button>
        }
        flush
      >
        {!rt ? (
          <Empty text="拿不到版本信息" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <tbody>
                <tr>
                  <th style={{ width: 160 }}>版本</th>
                  <td>
                    <span className="mono">{rt.version}</span>{' '}
                    {!rt.version_comparable && (
                      <Badge kind="warn" title="不是 vX.Y.Z 形式的发布版本，无法与发布版本比大小">
                        非发布版本
                      </Badge>
                    )}
                  </td>
                </tr>
                <tr>
                  <th>提交</th>
                  <td className="mono">{rt.commit || '未知'}</td>
                </tr>
                <tr>
                  <th>运行平台</th>
                  <td className="mono">
                    {rt.goos}/{rt.goarch}
                  </td>
                </tr>
                <tr>
                  <th>可执行文件</th>
                  <td className="mono" style={{ overflowWrap: 'anywhere' }}>
                    {rt.exe || '未知'}
                  </td>
                </tr>
                <tr>
                  <th>重启方式</th>
                  <td>
                    {rt.restart_strategy === 'reexec' ? (
                      <Badge kind="ok" dot title="原地替换进程镜像，PID 不变，不依赖服务管理器">
                        exec 原地替换
                      </Badge>
                    ) : rt.restart_strategy === 'spawn' ? (
                      <Badge kind="ok" dot title="Windows 上起新进程再退出旧进程">
                        起新进程替换
                      </Badge>
                    ) : (
                      <Badge kind="err" dot>
                        不支持
                      </Badge>
                    )}
                    <span className="faint small" style={{ marginLeft: 8 }}>
                      {rt.service === 'systemd' ? 'systemd 托管' : '非 systemd 托管'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <th>发布源</th>
                  <td className="small">
                    <span className="mono">{state?.source.repo}</span>
                    <div className="faint">
                      通道：{state?.source.channels.join(' / ')}（{state?.source.mode}）
                    </div>
                    <div className="faint">
                      资源：{state?.source.asset_name}
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="从 GitHub Releases 升级"
        sub="和 install.sh 走同一套约定：同一个仓库、同一个资源命名、同一份 SHA256SUMS、同一批镜像通道"
        actions={
          <div className="row">
            <input
              className="input"
              style={{ width: 130 }}
              placeholder="指定版本"
              value={pinned}
              onChange={(e) => setPinned(e.target.value)}
              disabled={!supported || busy !== ''}
            />
            <button className="btn sm" onClick={() => void doCheck(pinned.trim())} disabled={!supported || busy !== ''}>
              {busy === 'check' ? '检查中' : pinned.trim() ? '检查该版本' : '检查最新版本'}
            </button>
          </div>
        }
      >
        {!check ? (
          <Empty icon="" text="还没有检查过：点右上角「检查最新版本」" />
        ) : (
          <div className="stack">
            <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
              <Badge kind={check.update_available ? 'info' : 'ok'} dot>
                {check.update_available ? `有新版本 ${check.latest}` : `已是最新（${check.latest}）`}
              </Badge>
              <span className="faint small">当前 {check.current}</span>
              {check.asset.size > 0 && <span className="faint small">包大小 {bytes(check.asset.size)}</span>}
              {check.channel && <span className="faint small">通道 {check.channel}</span>}
              {check.sums_verified ? (
                <Badge kind="ok" title="已从发布方的 SHA256SUMS 拿到该包的 sha256">
                  有校验和
                </Badge>
              ) : (
                <Badge kind="warn" title="没拿到 SHA256SUMS：install.sh 在这种情况下会跳过完整性校验，这里保持一致">
                  无校验和
                </Badge>
              )}
              <span className="faint small">检查于 {datetime(check.checked_at)}</span>
            </div>

            {check.asset.sha256 && (
              <div className="small">
                发布包 sha256：<span className="mono">{check.asset.sha256}</span>
              </div>
            )}

            {!check.latest_comparable && (
              <Note kind="warn">
                发布版本号 {check.latest} 不是 vX.Y.Z 形式，服务端不会拿它和当前版本比大小，
                只能按你指定的版本去装。这种情况建议先确认发布页上的产物名。
              </Note>
            )}

            <div className="row" style={{ flexWrap: 'wrap' }}>
              <button
                className="btn primary"
                disabled={!supported || busy !== ''}
                onClick={() =>
                  setConfirm({
                    kind: 'install',
                    title: `安装 ${check.latest}`,
                    message: (
                      <>
                        <div>
                          来源：GitHub Releases（{state?.source.repo}）
                        </div>
                        <div>
                          目标版本：<span className="mono">{check.latest}</span>
                        </div>
                        <div>
                          资源：<span className="mono">{check.asset.name}</span>
                          {check.asset.size > 0 ? `（${bytes(check.asset.size)}）` : ''}
                        </div>
                        <div style={{ marginTop: 8 }}>
                          安装前的旧二进制会备份到 <span className="mono">*.old</span>，
                          换文件之前会先跑一次新文件的 <span className="mono">-version</span> 确认它能启动。
                          写入完成后进程会被替换，页面会短暂连不上。
                        </div>
                      </>
                    ),
                  })
                }
              >
                {busy === 'install' ? '安装中' : '安装这个版本'}
              </button>
              <button
                className="btn"
                disabled={!supported || busy !== ''}
                title="当前已经不低于这个版本时，用它可以强制重装一遍（用来修复被改坏的二进制）"
                onClick={() =>
                  setConfirm({
                    kind: 'install',
                    title: `强制重装 ${check.latest}`,
                    message: '即使当前版本已经不低于它，也重新下载并替换一次二进制。',
                  })
                }
              >
                强制重装
              </button>
              {check.release_url && (
                <a className="btn ghost" href={check.release_url} target="_blank" rel="noreferrer">
                  看发布页
                </a>
              )}
            </div>
          </div>
        )}
      </Card>

      <Card
        title="上传文件升级"
        sub="离线 / 内网用：直接传 goproxy 二进制，或者传发布用的 tar.gz（按文件头自动识别并解包）"
      >
        <div className="stack">
          <div className="row" style={{ flexWrap: 'wrap' }}>
            <input
              ref={fileRef}
              type="file"
              className="input"
              style={{ maxWidth: 380 }}
              disabled={!supported || busy !== ''}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            <button className="btn" onClick={() => void doUpload()} disabled={!file || !supported || busy !== ''}>
              {busy === 'upload' ? '上传中' : '上传并验证'}
            </button>
            {busy === 'upload' && (
              <span className="faint small">
                上传中 {progress ? Math.round((progress.loaded / Math.max(1, progress.total)) * 100) : 0}%
                {progress ? `（${bytes(progress.loaded)} / ${bytes(progress.total)}）` : ''}
              </span>
            )}
          </div>

          <div className="small faint">
            上传后服务端会先算 sha256 并跑一次 <span className="mono">-version</span>：
            跑不起来的文件会当场被拒（错误直接回给你），不会等到安装那一步才失败。
          </div>

          {state?.staged.present ? (
            <div className="stack tight">
              <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
                <Badge kind="info" dot>
                  待安装
                </Badge>
                {state.staged.version ? (
                  <span className="mono small">{state.staged.version}</span>
                ) : (
                  <span className="faint small">版本未验证（安装前会重新验证）</span>
                )}
                {typeof state.staged.size === 'number' && (
                  <span className="faint small">{bytes(state.staged.size)}</span>
                )}
                {state.staged.source && <span className="faint small">来源 {state.staged.source}</span>}
                {state.staged.mtime && <span className="faint small">暂存于 {datetime(state.staged.mtime)}</span>}
              </div>
              {state.staged.sha256 && (
                <div className="small">
                  sha256：<span className="mono">{state.staged.sha256}</span>
                </div>
              )}
              <div className="row">
                <button
                  className="btn primary"
                  disabled={!supported || busy !== ''}
                  onClick={() =>
                    setConfirm({
                      kind: 'install',
                      title: `安装暂存的文件${state.staged.version ? ` ${state.staged.version}` : ''}`,
                      message: (
                        <>
                          <div>
                            文件：<span className="mono">{state.staged.path}</span>
                          </div>
                          <div>
                            大小：{typeof state.staged.size === 'number' ? bytes(state.staged.size) : '未知'}
                          </div>
                          <div style={{ marginTop: 8 }}>
                            安装前会再验证一次这个文件（防的是「上传之后、安装之前」被换掉），
                            旧二进制备份到 <span className="mono">*.old</span>。
                          </div>
                        </>
                      ),
                    })
                  }
                >
                  {busy === 'install' ? '安装中' : '安装这个文件'}
                </button>
              </div>
            </div>
          ) : (
            <Empty text="服务端当前没有待安装的文件" />
          )}
        </div>
      </Card>

      <Card
        title="回退"
        sub="上一次升级前的二进制一直留着，命令行里 install.sh 给的提示也是这个文件"
      >
        {state?.backup.present ? (
          <div className="stack">
            <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
              <Badge kind="muted" dot>
                可回退
              </Badge>
              {state.backup.version ? (
                <span className="mono small">{state.backup.version}</span>
              ) : (
                <span className="faint small">版本无法识别</span>
              )}
              {state.backup.size !== undefined && <span className="faint small">{bytes(state.backup.size ?? 0)}</span>}
              {state.backup.mtime && <span className="faint small">备份于 {datetime(state.backup.mtime)}</span>}
            </div>
            <div className="small faint mono" style={{ overflowWrap: 'anywhere' }}>
              {state.backup.path}
            </div>
            <Note kind="warn">
              回退也是一次真实的二进制替换：会重启进程，并且把「当前这一版」写进同一个备份位置，
              所以回退之后还能再切回来。
            </Note>
            <div className="row">
              <button
                className="btn danger"
                disabled={!supported || busy !== ''}
                onClick={() =>
                  setConfirm({
                    kind: 'rollback',
                    title: `回退到 ${state.backup.version || '上一版'}`,
                    message: (
                      <>
                        <div>
                          将把 <span className="mono">{state.backup.path}</span> 装回去，
                          当前版本会被备份下来（所以还能再切回来）。
                        </div>
                        <div style={{ marginTop: 8 }}>替换完成后进程会重启，页面会短暂连不上。</div>
                      </>
                    ),
                  })
                }
              >
                {busy === 'rollback' ? '回退中' : '回退到上一版'}
              </button>
            </div>
          </div>
        ) : (
          <Empty text="没有备份：只有在本机做过一次升级之后才会有 .old 文件" />
        )}
      </Card>

      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          message={confirm.message}
          confirmText={confirm.kind === 'rollback' ? '确认回退' : '确认安装'}
          danger={confirm.kind === 'rollback'}
          busy={busy !== ''}
          onCancel={() => setConfirm(null)}
          onConfirm={() => {
            if (confirm.kind === 'rollback') {
              void doRollback()
              return
            }
            // 上传源装的是暂存文件，GitHub 源装的是检查出来的那个版本
            if (state?.staged.present && confirm.title.includes('暂存')) {
              void doInstall({ source: 'upload', sha256: state.staged.sha256 })
              return
            }
            void doInstall({
              source: 'github',
              version: check?.latest,
              force: confirm.title.includes('强制'),
            })
          }}
        />
      )}
    </div>
  )
}