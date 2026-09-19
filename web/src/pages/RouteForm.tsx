import { useMemo, useState } from 'react'
import type {
  AuthMode,
  BasicAuthEntry,
  CBConfig,
  IPListDef,
  JWTConfig,
  RateLimitScope,
  Route,
  RouteAuthConfig,
  TLSMode,
} from '../types'
import { Checkbox, Field, Modal, Note, Switch, toast } from '../ui'
import {
  ipListKindLabel,
  normalizeIPRules,
  pairList,
  parsePairs,
  parsePorts,
  splitList,
} from '../format'

/* ============ 表单状态 ============ */

interface AccountRow {
  username: string
  password: string
  password_hash: string
}

interface FormState {
  id: string
  name: string
  enabled: boolean

  listen_port: string
  host: string
  path_prefix: string
  target: string
  strip_prefix: boolean
  preserve_host: boolean
  timeout_ms: string

  tlsMode: TLSMode
  certFile: string
  keyFile: string
  redirectHttp: boolean

  rlEnabled: boolean
  rlRps: string
  rlBurst: string
  rlScope: RateLimitScope

  cbEnabled: boolean
  cbErrorRate: string // 百分比，0~100
  cbMinCalls: string
  cbOpenSecs: string
  cbHalfOpenCalls: string
  cbWindowSecs: string

  authMode: AuthMode
  authRealm: string
  accounts: AccountRow[]
  jwtSecret: string
  jwtPublicKey: string
  jwtAlgs: string
  jwtIssuer: string
  jwtAudience: string
  jwtLeeway: string
  jwtForward: string

  /**
   * 这条路由引用到的地址列表名（就是 IPListDef.name）。
   *
   * 规则本身不在这张表单里 —— 表单一律只放「引用哪几份」，
   * 名单的内容在「IP 名单」页签维护。这样同一段网段只需要维护一处。
   */
  aclLists: string[]
}

function emptyForm(): FormState {
  return {
    id: '',
    name: '',
    enabled: true,
    listen_port: '',
    host: '',
    path_prefix: '/',
    target: 'http://127.0.0.1:9000',
    strip_prefix: false,
    preserve_host: false,
    timeout_ms: '',
    tlsMode: '',
    certFile: '',
    keyFile: '',
    redirectHttp: true,
    rlEnabled: false,
    rlRps: '100',
    rlBurst: '200',
    rlScope: 'ip',
    cbEnabled: false,
    cbErrorRate: '50',
    cbMinCalls: '20',
    cbOpenSecs: '30',
    cbHalfOpenCalls: '5',
    cbWindowSecs: '10',
    authMode: 'none',
    authRealm: '',
    accounts: [{ username: '', password: '', password_hash: '' }],
    jwtSecret: '',
    jwtPublicKey: '',
    jwtAlgs: '',
    jwtIssuer: '',
    jwtAudience: '',
    jwtLeeway: '',
    jwtForward: '',
    aclLists: [],
  }
}

function fromRoute(r: Route): FormState {
  const f = emptyForm()
  f.id = r.id ?? ''
  f.name = r.name ?? ''
  f.enabled = r.enabled !== false
  f.listen_port = r.listen_port ? String(r.listen_port) : ''
  f.host = r.host ?? ''
  f.path_prefix = r.path_prefix || '/'
  f.target = r.target ?? ''
  f.strip_prefix = !!r.strip_prefix
  f.preserve_host = !!r.preserve_host
  f.timeout_ms = r.timeout_ms ? String(r.timeout_ms) : ''
  f.tlsMode = r.tls_mode ?? ''
  f.certFile = r.cert_file ?? ''
  f.keyFile = r.key_file ?? ''
  f.redirectHttp = r.redirect_http !== false

  if (r.rate_limit) {
    f.rlEnabled = true
    f.rlRps = r.rate_limit.rps ? String(r.rate_limit.rps) : '0'
    f.rlBurst = r.rate_limit.burst ? String(r.rate_limit.burst) : '0'
    f.rlScope = r.rate_limit.scope === 'global' ? 'global' : 'ip'
  }

  if (r.circuit_breaker) {
    const cb = r.circuit_breaker
    f.cbEnabled = true
    // 服务端存的是 0~1 的比例，界面上用百分比更直观
    f.cbErrorRate = String(Math.round((cb.error_rate ?? 0.5) * 100))
    f.cbMinCalls = String(cb.min_calls ?? '')
    f.cbOpenSecs = String(cb.open_secs ?? '')
    f.cbHalfOpenCalls = String(cb.half_open_calls ?? '')
    f.cbWindowSecs = String(cb.window_secs ?? '')
  }

  const a = r.auth
  if (a && a.mode && a.mode !== 'none') {
    f.authMode = a.mode
    f.authRealm = a.realm ?? ''
    if (a.mode === 'basic' && a.basic && a.basic.length > 0) {
      f.accounts = a.basic.map((e) => ({
        username: e.username ?? '',
        password: e.password ?? '',
        password_hash: e.password_hash ?? '',
      }))
    }
    if (a.mode === 'jwt' && a.jwt) {
      f.jwtSecret = a.jwt.secret ?? ''
      f.jwtPublicKey = a.jwt.public_key_pem ?? ''
      f.jwtAlgs = (a.jwt.algs ?? []).join(', ')
      f.jwtIssuer = a.jwt.issuer ?? ''
      f.jwtAudience = a.jwt.audience ?? ''
      f.jwtLeeway = a.jwt.leeway_secs ? String(a.jwt.leeway_secs) : ''
      f.jwtForward = pairList(a.jwt.forward_claims)
    }
  }

  // 名单只取「引用」，规则本身在「IP 名单」页签维护。
  // 这里必须把已有的引用读全 —— PUT 是整条替换，读漏了就等于把人家配好的名单抹掉。
  f.aclLists = (r.acl?.lists ?? []).filter((n) => typeof n === 'string' && n.trim() !== '')

  return f
}

function numOr(v: string, fallback: number): number {
  const n = Number(v.trim())
  return v.trim() !== '' && Number.isFinite(n) ? n : fallback
}

function toRoute(f: FormState): Route {
  const route: Route = {
    id: f.id.trim(),
    name: f.name.trim(),
    enabled: f.enabled,
    listen_port: numOr(f.listen_port, 0),
    host: f.host.trim(),
    path_prefix: f.path_prefix.trim() || '/',
    target: f.target.trim(),
    strip_prefix: f.strip_prefix,
    preserve_host: f.preserve_host,
    timeout_ms: numOr(f.timeout_ms, 0),
    tls_mode: f.tlsMode,
    cert_file: f.certFile.trim(),
    key_file: f.keyFile.trim(),
    redirect_http: f.redirectHttp,
    rate_limit: null,
    circuit_breaker: null,
    auth: null,
  }

  if (f.rlEnabled) {
    route.rate_limit = {
      rps: numOr(f.rlRps, 0),
      burst: numOr(f.rlBurst, 0),
      scope: f.rlScope,
    }
  }

  if (f.cbEnabled) {
    const cb: CBConfig = {
      error_rate: numOr(f.cbErrorRate, 50) / 100,
      min_calls: numOr(f.cbMinCalls, 0),
      open_secs: numOr(f.cbOpenSecs, 0),
      half_open_calls: numOr(f.cbHalfOpenCalls, 0),
      window_secs: numOr(f.cbWindowSecs, 0),
    }
    route.circuit_breaker = cb
  }

  if (f.authMode === 'basic') {
    const basic: BasicAuthEntry[] = f.accounts
      .filter((a) => a.username.trim() !== '')
      .map((a) => {
        const e: BasicAuthEntry = { username: a.username.trim() }
        if (a.password_hash.trim()) e.password_hash = a.password_hash.trim()
        else if (a.password) e.password = a.password
        return e
      })
    const auth: RouteAuthConfig = { mode: 'basic', basic }
    if (f.authRealm.trim()) auth.realm = f.authRealm.trim()
    route.auth = auth
  } else if (f.authMode === 'jwt') {
    const jwt: JWTConfig = {}
    if (f.jwtSecret) jwt.secret = f.jwtSecret
    if (f.jwtPublicKey.trim()) jwt.public_key_pem = f.jwtPublicKey
    const algs = splitList(f.jwtAlgs)
    if (algs.length > 0) jwt.algs = algs
    if (f.jwtIssuer.trim()) jwt.issuer = f.jwtIssuer.trim()
    if (f.jwtAudience.trim()) jwt.audience = f.jwtAudience.trim()
    if (f.jwtLeeway.trim()) jwt.leeway_secs = numOr(f.jwtLeeway, 60)
    const fw = parsePairs(f.jwtForward)
    if (Object.keys(fw).length > 0) jwt.forward_claims = fw
    const auth: RouteAuthConfig = { mode: 'jwt', jwt }
    if (f.authRealm.trim()) auth.realm = f.authRealm.trim()
    route.auth = auth
  }

  // 名单引用。一份都没选就写 null 而不是省略 —— PATCH 是合并语义，
  // 「不出现」等于「保持原值」；在这里省略会让用户取消勾选之后引用还在。
  // 保存走 PUT（整条替换）时写 null 也是对的：那条路由就是不做 IP 限制了。
  route.acl = f.aclLists.length > 0 ? { lists: [...f.aclLists] } : null

  return route
}

/* ============ 校验（对齐 config.go 的 validate） ============ */

function validate(f: FormState, isCreate: boolean, adminPort: number): Record<string, string> {
  const e: Record<string, string> = {}

  if (isCreate && f.id.trim() && !/^[A-Za-z0-9._-]{1,64}$/.test(f.id.trim())) {
    e.id = 'ID 只能是字母、数字、点、下划线和短横线，且不超过 64 字符'
  }

  if (f.listen_port.trim() !== '') {
    const n = Number(f.listen_port.trim())
    if (!Number.isInteger(n) || n < 0 || n > 65535) e.listen_port = '端口必须是 0~65535 的整数'
    else if (n === adminPort) e.listen_port = `不能和管理端口 ${adminPort} 相同`
  }

  if (!f.path_prefix.trim().startsWith('/')) e.path_prefix = '必须以 / 开头'

  const target = f.target.trim()
  if (!/^https?:\/\//i.test(target)) {
    e.target = '必须以 http:// 或 https:// 开头'
  } else {
    try {
      const u = new URL(target)
      if (!u.hostname) e.target = '缺少主机地址'
    } catch {
      e.target = '不是合法的 URL'
    }
  }

  if (f.timeout_ms.trim() !== '' && numOr(f.timeout_ms, -1) < 0) e.timeout_ms = '不能为负'
  if (f.host.trim() && f.host.includes('*') && !f.host.trim().startsWith('*.')) {
    e.host = '通配只支持 *.example.com 这种前缀形式'
  }

  // TLS 校验与后端 validateTLS 对齐。这里拦一道是为了不让用户白跑一趟 ——
  // 后端才是权威，但 400 回来时表单已经关了，改起来很难受。
  const host = f.host.trim()
  if (f.tlsMode === 'manual') {
    if (!f.certFile.trim()) e.certFile = 'manual 模式必须填证书文件'
    if (!f.keyFile.trim()) e.keyFile = 'manual 模式必须填私钥文件'
  } else if (f.tlsMode === 'auto') {
    if (!host) {
      e.tlsMode = 'ACME 无法为裸 IP 或任意域名签发证书，请先填 host'
    } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      e.tlsMode = "Let's Encrypt 不对裸 IP 签发证书，请改用域名或 manual"
    } else if (host.startsWith('*.')) {
      e.tlsMode = '通配域名需要 DNS-01 挑战，自动签发不支持，请用 manual 挂通配证书'
    } else {
      const p = numOr(f.listen_port, 0)
      if (p !== 0 && p !== 80 && p !== 443) {
        e.tlsMode = `ACME 挑战固定走 80/443，监听在 ${p} 上拿不到自动证书`
      }
    }
  }

  if (f.rlEnabled) {
    if (numOr(f.rlRps, -1) <= 0) e.rlRps = '必须大于 0'
    if (numOr(f.rlBurst, -1) < 0) e.rlBurst = '不能为负'
  }

  if (f.cbEnabled) {
    const rate = numOr(f.cbErrorRate, -1)
    if (rate < 0 || rate > 100) e.cbErrorRate = '必须在 0~100 之间'
    if (numOr(f.cbMinCalls, -1) < 0) e.cbMinCalls = '不能为负'
    if (numOr(f.cbOpenSecs, -1) <= 0) e.cbOpenSecs = '必须大于 0'
    if (numOr(f.cbHalfOpenCalls, -1) <= 0) e.cbHalfOpenCalls = '必须大于 0'
    const w = numOr(f.cbWindowSecs, -1)
    if (w < 2 || w > 300) e.cbWindowSecs = '必须在 2~300 秒之间'
  }

  if (f.authMode === 'basic') {
    const usable = f.accounts.filter((a) => a.username.trim() !== '')
    if (usable.length === 0) e.accounts = 'basic 认证至少需要配置一个账号'
    usable.forEach((a, i) => {
      if (!a.password && !a.password_hash.trim()) {
        e[`account-${i}`] = '密码和 password_hash 至少填一个'
      }
      if (a.password_hash.trim() && !/^\$2[aby]?\$\d{2}\$/.test(a.password_hash.trim())) {
        e[`account-${i}`] = 'password_hash 看起来不是 bcrypt（应以 $2a$ / $2b$ / $2y$ 开头）'
      }
    })
  }

  if (f.authMode === 'jwt') {
    if (!f.jwtSecret && !f.jwtPublicKey.trim()) e.jwtSecret = 'secret 和 public_key_pem 至少要填一个'
    if (f.jwtPublicKey.trim() && !f.jwtPublicKey.includes('-----BEGIN')) {
      e.jwtPublicKey = '不是 PEM 格式（应包含 -----BEGIN ...-----）'
    }
    const algs = splitList(f.jwtAlgs).map((a) => a.toUpperCase())
    const allowed = ['HS256', 'HS384', 'HS512', 'RS256']
    const bad = algs.filter((a) => !allowed.includes(a))
    if (bad.length > 0) e.jwtAlgs = `不支持的算法：${bad.join(', ')}（alg=none 永远被拒绝）`
    if (algs.some((a) => a.startsWith('HS')) && !f.jwtSecret) e.jwtSecret = '选择了 HS* 算法，必须填 secret'
    if (algs.includes('RS256') && !f.jwtPublicKey.trim()) e.jwtPublicKey = '选择了 RS256，必须填公钥'
    if (algs.length === 0 && f.jwtPublicKey.trim() === '' && !f.jwtSecret) e.jwtSecret = '缺少验签凭据'
  }

  // 名单条目的形状检查已随名单一起搬到「IP 名单」页签的 IPListPage 里。

  return e
}

/* ============ 组件 ============ */

type TabKey = 'basic' | 'forward' | 'tls' | 'limit' | 'breaker' | 'guard' | 'ip'

export function RouteForm({
  initial,
  isCreate,
  adminPort,
  lists,
  busy,
  onSubmit,
  onCancel,
}: {
  initial: Route | null
  isCreate: boolean
  adminPort: number
  /** 当前可引用的地址列表。来自 /_goproxy/config 的 ip_lists。 */
  lists: IPListDef[]
  busy: boolean
  onSubmit: (route: Route) => void
  onCancel: () => void
}) {
  const [form, setForm] = useState<FormState>(() => (initial ? fromRoute(initial) : emptyForm()))
  const [tab, setTab] = useState<TabKey>('basic')
  const [touched, setTouched] = useState(false)

  const errors = useMemo(() => validate(form, isCreate, adminPort), [form, isCreate, adminPort])
  const hasError = Object.keys(errors).length > 0

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }))

  const flag = (on: boolean) => (on ? <span className="flag">●</span> : null)

  const submit = () => {
    setTouched(true)
    if (hasError) {
      // 把用户直接送到第一个出错的页签，而不是让他在 7 个页签里找
      const order: TabKey[] = ['basic', 'forward', 'tls', 'limit', 'breaker', 'guard', 'ip']
      const where: Record<TabKey, string[]> = {
        basic: ['id', 'listen_port', 'path_prefix', 'target', 'timeout_ms', 'host'],
        forward: [],
        tls: ['tlsMode', 'certFile', 'keyFile'],
        limit: ['rlRps', 'rlBurst'],
        breaker: ['cbErrorRate', 'cbMinCalls', 'cbOpenSecs', 'cbHalfOpenCalls', 'cbWindowSecs'],
        guard: ['accounts', 'jwtSecret', 'jwtPublicKey', 'jwtAlgs'],
        ip: [],
      }
      for (const t of order) {
        const keys = where[t]
        if (keys.some((k) => errors[k]) || (t === 'guard' && Object.keys(errors).some((k) => k.startsWith('account-')))) {
          setTab(t)
          break
        }
      }
      toast('err', '还有必填项没填对，已跳到对应分组')
      return
    }

    // 引用的名单可能刚被别处删掉（表单开着的时候）。后端会拒，但那时弹窗已经关了；
    // 在这里先拦一道，用户还能就地把勾去掉。
    const known = new Set(lists.map((d) => d.name))
    const gone = form.aclLists.filter((n) => !known.has(n))
    if (gone.length > 0) {
      setTab('ip')
      toast('err', `引用的名单已经不存在了：${gone.join('、')}。请重新勾选。`)
      return
    }

    onSubmit(toRoute(form))
  }

  const err = (k: string) => (touched ? errors[k] : undefined)

  // 已勾选的名单，拆成两组，回显在顶部提示里（也让「有没有配」一眼可见）。
  const pickedAllow = form.aclLists.filter(
    (n) => lists.find((d) => d.name === n)?.kind === 'allow',
  )
  const pickedDeny = form.aclLists.filter((n) => lists.find((d) => d.name === n)?.kind === 'deny')
  const pickedUnknown = form.aclLists.filter((n) => !lists.some((d) => d.name === n))
  const allowOptions = lists.filter((d) => d.kind === 'allow')
  const denyOptions = lists.filter((d) => d.kind === 'deny')

  return (
    <Modal
      title={isCreate ? '新建路由' : `编辑路由 ${initial?.id ?? ''}`}
      sub={isCreate ? 'listen_port → host → path_prefix 三级匹配' : undefined}
      onClose={onCancel}
      footer={
        <>
          {touched && hasError && (
            <span className="small" style={{ color: 'var(--err)' }}>
              还有 {Object.keys(errors).length} 处需要修正
            </span>
          )}
          <div className="spacer" />
          <button className="btn" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button className="btn primary" onClick={submit} disabled={busy}>
            {busy ? '保存中…' : isCreate ? '创建' : '保存'}
          </button>
        </>
      }
    >
      <div className="subtabs">
        <button className="subtab" aria-selected={tab === 'basic'} onClick={() => setTab('basic')}>
          基础
        </button>
        <button className="subtab" aria-selected={tab === 'forward'} onClick={() => setTab('forward')}>
          转发
        </button>
        <button className="subtab" aria-selected={tab === 'tls'} onClick={() => setTab('tls')}>
          TLS{flag(form.tlsMode === 'auto' || form.tlsMode === 'manual')}
        </button>
        <button className="subtab" aria-selected={tab === 'limit'} onClick={() => setTab('limit')}>
          限流{flag(form.rlEnabled)}
        </button>
        <button className="subtab" aria-selected={tab === 'breaker'} onClick={() => setTab('breaker')}>
          熔断{flag(form.cbEnabled)}
        </button>
        <button
          className="subtab"
          aria-selected={tab === 'guard'}
          onClick={() => setTab('guard')}
        >
          {/* 这一页签以前叫「认证与 ACL」。名单独立成「IP 名单」页签之后
              再叫什么 ACL 只会把人引到一个改不了名单的地方，所以就叫「认证」。 */}
          认证{flag(form.authMode !== 'none')}
        </button>
        <button className="subtab" aria-selected={tab === 'ip'} onClick={() => setTab('ip')}>
          名单{flag(form.aclLists.length > 0)}
        </button>
      </div>

      {/*
        名单的**内容**在「IP 名单」页签维护，这张表单只负责「引用哪几份」。
        这段指路放在子页签**外面** —— 每一屏都能看到：有人打开这张表单本来是
        想改名单内容的，他不会想到要去某个子页签里翻。
      */}
      <Note kind="info">
        <b>名单的规则不在这张表单里，这里只挑用哪几份。</b>
        {isCreate ? (
          <>不选就是不做 IP 限制。名单本身要先到「IP 名单」页签建。</>
        ) : (
          <>
            当前引用：
            {pickedAllow.length > 0 ? ` 白名单 ${pickedAllow.join('、')}` : ' 不限来源'}
            {pickedDeny.length > 0 ? `，黑名单 ${pickedDeny.join('、')}` : ''}
            {pickedUnknown.length > 0 ? `，以及已不存在的 ${pickedUnknown.join('、')}` : ''}。
            要改规则内容（加减 IP），去「IP 名单」页签 —— 那里改一次，
            所有引用它的路由一起生效。
          </>
        )}
        <br />
        判定顺序固定为：全局黑名单 → 引用的白名单 → 引用的黑名单 → 放行；
        那一页带<b>命中测试</b>，可以拿个地址先试一次。
      </Note>

      {tab === 'basic' && (
        <div className="grid2">
          <Field label="路由 ID" error={err('id')} hint={isCreate ? '留空则自动生成 rt-xxxxxx' : '创建后不可修改'}>
            <input
              className={`input mono${err('id') ? ' invalid' : ''}`}
              value={form.id}
              disabled={!isCreate}
              placeholder={isCreate ? '自动生成' : ''}
              onChange={(e) => set('id', e.target.value)}
            />
          </Field>

          <Field label="名称" hint="只是给人看的备注，不参与匹配">
            <input
              className="input"
              value={form.name}
              placeholder="例如：订单服务"
              onChange={(e) => set('name', e.target.value)}
            />
          </Field>

          <Field
            label="监听端口 listen_port"
            error={err('listen_port')}
            hint="留空 = 挂在所有监听端口上；填了就只匹配从该端口进来的请求，并自动开这个端口的监听"
          >
            <input
              className={`input mono${err('listen_port') ? ' invalid' : ''}`}
              value={form.listen_port}
              placeholder="全部端口"
              inputMode="numeric"
              onChange={(e) => set('listen_port', e.target.value)}
            />
          </Field>

          <Field
            label="域名 host"
            error={err('host')}
            hint="留空 = 任意域名；支持 *.example.com 通配"
          >
            <input
              className={`input mono${err('host') ? ' invalid' : ''}`}
              value={form.host}
              placeholder="任意"
              onChange={(e) => set('host', e.target.value)}
            />
          </Field>

          <Field label="路径前缀 path_prefix" error={err('path_prefix')} hint="最长前缀优先；/ 表示兜底">
            <input
              className={`input mono${err('path_prefix') ? ' invalid' : ''}`}
              value={form.path_prefix}
              onChange={(e) => set('path_prefix', e.target.value)}
            />
          </Field>

          <Field label="超时 timeout_ms" error={err('timeout_ms')} hint="留空用全局默认 60s">
            <input
              className={`input mono${err('timeout_ms') ? ' invalid' : ''}`}
              value={form.timeout_ms}
              placeholder="60000"
              inputMode="numeric"
              onChange={(e) => set('timeout_ms', e.target.value)}
            />
          </Field>

          <Field label="启用状态" span hint="停用后该路由立即从路由表移除，端口上没有其它路由时会自动关闭监听">
            <Switch
              checked={form.enabled}
              onChange={(v) => set('enabled', v)}
              label={form.enabled ? '已启用' : '已停用'}
            />
          </Field>
        </div>
      )}

      {tab === 'forward' && (
        <div className="stack">
          <Field label="后端地址 target" error={err('target')} hint="http:// 或 https://">
            <input
              className={`input mono${err('target') ? ' invalid' : ''}`}
              value={form.target}
              onChange={(e) => set('target', e.target.value)}
            />
          </Field>

          <fieldset className="group">
            <legend>转发细节</legend>
            <div className="stack" style={{ gap: 10 }}>
              <Checkbox
                checked={form.strip_prefix}
                onChange={(v) => set('strip_prefix', v)}
                label={
                  <>
                    剥离路径前缀（<code>StripPrefix</code>）
                    <span className="faint small">
                      {' '}
                      · /api/orders → 后端收到 /orders
                    </span>
                  </>
                }
              />
              <Checkbox
                checked={form.preserve_host}
                onChange={(v) => set('preserve_host', v)}
                label={
                  <>
                    保留原始 Host 头（<code>PreserveHost</code>）
                    <span className="faint small"> · 默认改写为后端地址</span>
                  </>
                }
              />
            </div>
          </fieldset>

          <Note kind="info">
            匹配顺序是 <b>端口 → 域名 → 路径前缀</b>，路径取<b>最长前缀</b>。
            所以同端口下 <code>/api/v2</code> 会优先于 <code>/api</code>，<code>/</code> 是最后的兜底。
          </Note>
        </div>
      )}

      {tab === 'tls' && (
        <div className="stack">
          <Field
            label="TLS 模式"
            error={err('tlsMode')}
            hint="留空表示按顶层 tls.enabled 推导：开关打开→auto，关闭→off"
          >
            <select
              className={`input${err('tlsMode') ? ' invalid' : ''}`}
              value={form.tlsMode}
              onChange={(e) => set('tlsMode', e.target.value as TLSMode)}
            >
              <option value="">（继承全局）</option>
              <option value="off">off —— 明文 HTTP</option>
              <option value="manual">manual —— 挂本地证书</option>
              <option value="auto">auto —— ACME 自动签发</option>
            </select>
          </Field>

          {form.tlsMode === 'manual' && (
            <fieldset className="group">
              <legend>证书文件</legend>
              <div className="stack" style={{ gap: 10 }}>
                <Field
                  label="证书 cert_file"
                  error={err('certFile')}
                  hint="fullchain.pem。相对路径相对 tls.cert_dir 解析。"
                >
                  <input
                    className={`input mono${err('certFile') ? ' invalid' : ''}`}
                    value={form.certFile}
                    placeholder="certs/example.com/fullchain.pem"
                    onChange={(e) => set('certFile', e.target.value)}
                  />
                </Field>
                <Field
                  label="私钥 key_file"
                  error={err('keyFile')}
                  hint="证书与私钥必须是同一对，后端会在保存前真实验证。"
                >
                  <input
                    className={`input mono${err('keyFile') ? ' invalid' : ''}`}
                    value={form.keyFile}
                    placeholder="certs/example.com/privkey.pem"
                    onChange={(e) => set('keyFile', e.target.value)}
                  />
                </Field>
                <Note kind="info">
                  证书文件变更后 30 秒内自动热重载，不需要重启进程。
                </Note>
              </div>
            </fieldset>
          )}

          {form.tlsMode === 'auto' && (
            <Note kind="warn">
              ACME 只在 <b>80 / 443</b> 上能完成挑战，且<b>不能签发裸 IP 或通配域名</b>的证书。
              当前路由的 <code>host</code> 必须是具体域名、<code>listen_port</code> 为 0 或 80/443，
              否则保存时会报错。
              <div className="faint small" style={{ marginTop: 6 }}>
                调试阶段建议在顶层 <code>tls.acme.staging</code> 打开测试环境，
                避免反复申请烧掉生产配额。
              </div>
            </Note>
          )}

          {(form.tlsMode === 'auto' || form.tlsMode === 'manual') && (
            <fieldset className="group">
              <legend>明文访问</legend>
              <Checkbox
                checked={form.redirectHttp}
                onChange={(v) => set('redirectHttp', v)}
                label={
                  <>
                    把 HTTP 请求跳到 HTTPS（<code>redirect_http</code>）
                    <span className="faint small"> · 默认开启</span>
                  </>
                }
              />
              <div className="faint small" style={{ marginTop: 8 }}>
                关掉后该路由的两种协议都能访问。仅建议给只认 HTTP 的健康检查探针或老客户端用。
              </div>
            </fieldset>
          )}
        </div>
      )}

      {tab === 'limit' && (
        <div className="stack">
          <Switch checked={form.rlEnabled} onChange={(v) => set('rlEnabled', v)} label="启用限流" />
          {form.rlEnabled && (
            <>
              <div className="grid3">
                <Field label="速率 rps" error={err('rlRps')} hint="每秒放行的请求数">
                  <input
                    className={`input mono${err('rlRps') ? ' invalid' : ''}`}
                    value={form.rlRps}
                    inputMode="decimal"
                    onChange={(e) => set('rlRps', e.target.value)}
                  />
                </Field>
                <Field label="突发 burst" error={err('rlBurst')} hint="允许的瞬时突发量">
                  <input
                    className={`input mono${err('rlBurst') ? ' invalid' : ''}`}
                    value={form.rlBurst}
                    inputMode="decimal"
                    onChange={(e) => set('rlBurst', e.target.value)}
                  />
                </Field>
                <Field label="维度 scope" hint="按 IP 还是整条路由共享一个桶">
                  <select
                    className="select"
                    value={form.rlScope}
                    onChange={(e) => set('rlScope', e.target.value as RateLimitScope)}
                  >
                    <option value="ip">按客户端 IP</option>
                    <option value="global">整条路由共享</option>
                  </select>
                </Field>
              </div>
              <Note kind="info">
                被限流的请求返回 <code>429</code>，并带 <code>Retry-After: 1</code>。
                限流结果<b>不会</b>计入熔断，避免限流自己把后端判成故障。
              </Note>
            </>
          )}
        </div>
      )}

      {tab === 'breaker' && (
        <div className="stack">
          <Switch checked={form.cbEnabled} onChange={(v) => set('cbEnabled', v)} label="启用熔断" />
          {form.cbEnabled && (
            <>
              <div className="grid3">
                <Field label="错误率阈值 %" error={err('cbErrorRate')} hint="窗口内达到就跳闸">
                  <input
                    className={`input mono${err('cbErrorRate') ? ' invalid' : ''}`}
                    value={form.cbErrorRate}
                    inputMode="numeric"
                    onChange={(e) => set('cbErrorRate', e.target.value)}
                  />
                </Field>
                <Field label="最少调用数" error={err('cbMinCalls')} hint="避免刚启动就被零星错误打跳闸">
                  <input
                    className={`input mono${err('cbMinCalls') ? ' invalid' : ''}`}
                    value={form.cbMinCalls}
                    inputMode="numeric"
                    onChange={(e) => set('cbMinCalls', e.target.value)}
                  />
                </Field>
                <Field label="窗口长度 秒" error={err('cbWindowSecs')} hint="2 ~ 300">
                  <input
                    className={`input mono${err('cbWindowSecs') ? ' invalid' : ''}`}
                    value={form.cbWindowSecs}
                    inputMode="numeric"
                    onChange={(e) => set('cbWindowSecs', e.target.value)}
                  />
                </Field>
                <Field label="打开持续 秒" error={err('cbOpenSecs')} hint="之后进入半开探测">
                  <input
                    className={`input mono${err('cbOpenSecs') ? ' invalid' : ''}`}
                    value={form.cbOpenSecs}
                    inputMode="numeric"
                    onChange={(e) => set('cbOpenSecs', e.target.value)}
                  />
                </Field>
                <Field label="半开探测数" error={err('cbHalfOpenCalls')} hint="全部成功才恢复闭合">
                  <input
                    className={`input mono${err('cbHalfOpenCalls') ? ' invalid' : ''}`}
                    value={form.cbHalfOpenCalls}
                    inputMode="numeric"
                    onChange={(e) => set('cbHalfOpenCalls', e.target.value)}
                  />
                </Field>
              </div>
              <Note kind="info">
                只有 <b>5xx</b> 和<b>连不上后端</b>算失败。4xx 是客户端的问题、429 是限流的锅，
                都不计入错误率，否则一次扫描就能把后端冤枉到跳闸。
                熔断期间请求直接返回 <code>503</code>。
              </Note>
            </>
          )}
        </div>
      )}

      {tab === 'guard' && (
        <div className="stack">
          <Field label="认证方式" hint="作用在转发之前；失败一律 401">
            <select
              className="select"
              value={form.authMode}
              onChange={(e) => set('authMode', e.target.value as AuthMode)}
            >
              <option value="none">不认证</option>
              <option value="basic">HTTP Basic</option>
              <option value="jwt">JWT（仅校验，不签发）</option>
            </select>
          </Field>

          {form.authMode !== 'none' && (
            <Field label="Realm" hint="出现在 WWW-Authenticate 头里，留空用 goproxy">
              <input
                className="input"
                value={form.authRealm}
                onChange={(e) => set('authRealm', e.target.value)}
              />
            </Field>
          )}

          {form.authMode === 'basic' && (
            <fieldset className="group">
              <legend>账号</legend>
              {err('accounts') && (
                <div className="err" style={{ marginBottom: 8 }}>
                  {errors.accounts}
                </div>
              )}
              <div className="stack" style={{ gap: 10 }}>
                {form.accounts.map((a, i) => (
                  <div key={i} className="row" style={{ alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ flex: '1 1 130px' }}>
                      <input
                        className="input"
                        placeholder="用户名"
                        value={a.username}
                        onChange={(e) => {
                          const next = [...form.accounts]
                          next[i] = { ...next[i], username: e.target.value }
                          set('accounts', next)
                        }}
                      />
                    </div>
                    <div style={{ flex: '1 1 150px' }}>
                      <input
                        className="input mono"
                        placeholder="明文密码（仅测试）"
                        value={a.password}
                        onChange={(e) => {
                          const next = [...form.accounts]
                          next[i] = { ...next[i], password: e.target.value }
                          set('accounts', next)
                        }}
                      />
                    </div>
                    <div style={{ flex: '2 1 240px' }}>
                      <input
                        className={`input mono${err(`account-${i}`) ? ' invalid' : ''}`}
                        placeholder="password_hash（bcrypt，推荐）"
                        value={a.password_hash}
                        onChange={(e) => {
                          const next = [...form.accounts]
                          next[i] = { ...next[i], password_hash: e.target.value }
                          set('accounts', next)
                        }}
                      />
                    </div>
                    <button
                      className="btn ghost icon"
                      title="删除该账号"
                      disabled={form.accounts.length <= 1}
                      onClick={() => set('accounts', form.accounts.filter((_, j) => j !== i))}
                    >
                      ×
                    </button>
                  </div>
                ))}
                {form.accounts.map((_, i) =>
                  err(`account-${i}`) ? (
                    <div key={`err-${i}`} className="err small">
                      第 {i + 1} 行：{errors[`account-${i}`]}
                    </div>
                  ) : null,
                )}
              </div>
              <div style={{ marginTop: 10 }}>
                <button
                  className="btn sm"
                  onClick={() => set('accounts', [...form.accounts, { username: '', password: '', password_hash: '' }])}
                >
                  + 添加账号
                </button>
              </div>
              <div className="hint" style={{ marginTop: 8 }}>
                密码填明文时后端会转成 bcrypt，但<b>明文会留在 config.json 里</b>。生产环境请直接填 hash。
              </div>
            </fieldset>
          )}

          {form.authMode === 'jwt' && (
            <fieldset className="group">
              <legend>JWT 校验</legend>
              <div className="grid2">
                <Field label="HS* 密钥 secret" error={err('jwtSecret')} hint="HS256/384/512 用">
                  <input
                    className={`input mono${err('jwtSecret') ? ' invalid' : ''}`}
                    type="password"
                    value={form.jwtSecret}
                    placeholder="留空表示只用公钥"
                    onChange={(e) => set('jwtSecret', e.target.value)}
                  />
                </Field>
                <Field label="算法白名单 algs" error={err('jwtAlgs')} hint="逗号分隔，留空按凭据推断">
                  <input
                    className={`input mono${err('jwtAlgs') ? ' invalid' : ''}`}
                    value={form.jwtAlgs}
                    placeholder="HS256 或 RS256"
                    onChange={(e) => set('jwtAlgs', e.target.value)}
                  />
                </Field>
                <Field label="签发方 issuer" hint="填了就要求 iss 一致">
                  <input
                    className="input mono"
                    value={form.jwtIssuer}
                    onChange={(e) => set('jwtIssuer', e.target.value)}
                  />
                </Field>
                <Field label="受众 audience" hint="填了就要求 aud 一致">
                  <input
                    className="input mono"
                    value={form.jwtAudience}
                    onChange={(e) => set('jwtAudience', e.target.value)}
                  />
                </Field>
                <Field label="时钟容忍 秒" hint="默认 60">
                  <input
                    className="input mono"
                    value={form.jwtLeeway}
                    inputMode="numeric"
                    onChange={(e) => set('jwtLeeway', e.target.value)}
                  />
                </Field>
                <Field label="claim 透传" hint="每行一条，如 sub: X-User-Id">
                  <textarea
                    className="textarea mono"
                    value={form.jwtForward}
                    onChange={(e) => set('jwtForward', e.target.value)}
                  />
                </Field>
                <Field label="RS256 公钥 PEM" error={err('jwtPublicKey')} span>
                  <textarea
                    className={`textarea mono${err('jwtPublicKey') ? ' invalid' : ''}`}
                    value={form.jwtPublicKey}
                    placeholder="-----BEGIN PUBLIC KEY-----"
                    onChange={(e) => set('jwtPublicKey', e.target.value)}
                  />
                </Field>
              </div>
              <div className="hint" style={{ marginTop: 8 }}>
                <code>alg=none</code> 与算法混淆攻击（拿公钥当 HMAC 密钥）都会被后端拒绝。
              </div>
            </fieldset>
          )}

          {/*
            trusted_proxies 的提醒跟着名单一起搬到了「IP 名单」页签：
            它讲的是「名单看到的到底是哪个地址」，属于名单那一页的事。
          */}
        </div>
      )}

      {tab === 'ip' && (
        <div className="stack">
          {lists.length === 0 ? (
            <Note kind="warn">
              还没有任何地址列表。名单的<b>内容</b>要到「IP 名单」页签里建 ——
              那里可以新建名单、写规则、看每份名单被哪些路由用着。
              这张表单只负责「引用哪几份」。
            </Note>
          ) : (
            <>
              <div className="faint small">
                勾几份就用几份。同一层的多份名单取<b>并集</b>：
                白名单命中其中任意一份就继续，黑名单命中任意一份就拒绝。
                所以「只允许办公网 + 只允许内网跳板」就是勾两份白名单，
                各自维护、互不干扰。
              </div>

              {[
                { kind: 'allow' as const, opts: allowOptions, legend: '白名单（勾了就只剩一个含义：只允许名单内的地址）' },
                { kind: 'deny' as const, opts: denyOptions, legend: '黑名单（把名单内的地址剔掉）' },
              ].map(({ kind, opts, legend }) => (
                <fieldset className="group" key={kind}>
                  <legend>{legend}</legend>
                  {opts.length === 0 ? (
                    <div className="faint small">还没有{ipListKindLabel(kind)}类型的名单。</div>
                  ) : (
                    <div className="stack" style={{ gap: 10 }}>
                      {opts.map((d) => {
                        const rules = normalizeIPRules(d.rules)
                        const preview = rules
                          .slice(0, 2)
                          .map((x) => x.cidr)
                          .join('、')
                        return (
                          <Checkbox
                            key={d.name}
                            checked={form.aclLists.includes(d.name)}
                            onChange={(v) =>
                              set(
                                'aclLists',
                                v
                                  ? [...form.aclLists, d.name]
                                  : form.aclLists.filter((n) => n !== d.name),
                              )
                            }
                            label={
                              <>
                                <code>{d.name}</code>
                                <span className="faint small"> · {rules.length} 条规则</span>
                                {preview && (
                                  <span className="faint small">
                                    {' '}
                                    · {preview}
                                    {rules.length > 2 ? ' 等' : ''}
                                  </span>
                                )}
                              </>
                            }
                          />
                        )
                      })}
                    </div>
                  )}
                </fieldset>
              ))}

              {pickedUnknown.length > 0 && (
                <Note kind="err">
                  这条路由引用了<b>已经不存在的名单</b>：{pickedUnknown.join('、')}。
                  它们大概是在「IP 名单」页签里被删掉了 —— 取消勾选（或重新建一份同名的）
                  之后才能保存。
                </Note>
              )}

              <Note kind="info">
                不勾任何一份 = 这条路由<b>不做 IP 限制</b>（但全局黑名单仍然管着它）。
                <br />
                想改某份名单里到底封了哪些地址，去「IP 名单」页签 ——
                在那里改一次，所有引用它的路由一起生效，
                不用回来逐条路由重勾。
              </Note>
            </>
          )}
        </div>
      )}
    </Modal>
  )
}

/** 供列表页做预览用：把关键配置压成一行摘要。 */
export function summarize(r: Route): string[] {
  const tags: string[] = []
  if (r.rate_limit) tags.push(`限流 ${r.rate_limit.rps}/s`)
  if (r.circuit_breaker) tags.push(`熔断 ${Math.round((r.circuit_breaker.error_rate ?? 0) * 100)}%`)
  if (r.auth && r.auth.mode && r.auth.mode !== 'none') tags.push(`认证 ${r.auth.mode}`)
  // 名单不在这里列：路由表有**专门的「IP 名单」列**显示引用了哪几份
  // （要带上白/黑角色和全局黑名单是否生效）。同一件事写两处，
  // 改的时候必然漏一处，而且两处措辞会慢慢分叉。
  return tags
}

/** 端口列表的解析也走这里，保证新建时用的是同一套校验。 */
export function parseListenPort(raw: string): number | null {
  if (raw.trim() === '') return 0
  const ports = parsePorts(raw)
  return ports && ports.length === 1 ? ports[0] : null
}
