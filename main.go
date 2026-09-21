package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	// configDB 是配置数据库（SQLite）的路径。
	//
	// v0.9.0 起它是配置的唯一真相源。以前这里放的是 config.json 的路径，
	// 进程每秒轮询它的 mtime 来发现「有人手工改了配置」—— 那条路随之下线：
	// 配置只经管理接口修改，保存即生效（见 admin_api.go 的 mutate）。
	configDB  string
	transport *http.Transport
	listeners *ListenerManager
	metrics   *Metrics
	table     atomic.Pointer[RouteTable]

	// logs 是访问记录的内存环形缓冲，管理台的实时日志与 SSE 都读它。
	logs *logBuffer

	mu        sync.Mutex
	adminAddr string

	// adminToken 管理接口令牌，用于 Authorization: Bearer。
	// v0.6.0 起回环不再免认证，所以它不再是「只有外部访问才需要」的东西。
	adminToken string

	// adminAccounts 控制台的管理员账号（用户名 + bcrypt 哈希）。
	// 与 adminToken 并存：前者给浏览器登录用，后者给脚本用。
	adminAccounts *adminAccounts

	// sessions 管理控制台的登录会话。内存存储：进程重启即全部失效，
	// 对单机自托管是可接受的取舍（换来的是「不引入存储依赖」）。
	sessions *sessionStore

	// trusted 是可信代理网段快照，登录限流解析真实 IP 时要用。
	trusted atomic.Pointer[[]*net.IPNet]

	// tlsmgr 证书管理器。顶层 tls.enabled=false 时为 nil，
	// 这时所有端口跑明文，行为与引入 TLS 之前完全一致。
	tlsmgr atomic.Pointer[tlsManager]

	// tlsCfg 当前生效的 TLS 配置快照，供构造端口 spec 时读取。
	tlsCfg atomic.Pointer[Config]

	// writeMu 串行化「读配置 → 改 → 写回 → 热重载」这一个事务，
	// 防止两个并发写各自读到旧文件、互相覆盖（经典 lost update）。
	// 单独一把锁而不复用 mu：写事务会先拿 writeMu，再在 reload() 里拿 mu,
	// 加锁顺序固定单向，不会成环。
	writeMu sync.Mutex

	accessLog atomic.Bool

	// upgrade 是控制台「升级」页的后端状态：当前可执行文件、发布源、
	// 以及一份等着被换上去的暂存二进制（实现见 upgrade.go）。
	//
	// 它是 App 上唯一会去改动「自己这个二进制文件」的东西，所以所有写动作
	// 都串在它自己的 busy 标记里，并且只经管理接口触发。
	upgrade *upgradeManager

	// store 是配置库的连接（进程内按路径缓存，见 storeFor）。
	// 只给「配置之外」的读写用：封禁表、蜜罐设置 —— 它们同样在库里，
	// 但不属于 Config，所以走这条直达连接而不是 loadConfig。
	store *configStore

	// bans 是自动封禁的运行态（实现见 banlist.go）。
	//
	// 它**不是配置**：条目不进 revision、不进 config_history、不进 -config-export，
	// 只在自己的表里（ban_entries）。理由见 banlist.go 开头的说明 ——
	// 一句话是「自动封禁每跳一次都撞 revision 的话，控制台就没法编辑了」。
	bans *banList

	// trap 是蜜罐端口监听（实现见 honeypot.go）：在不该有人访问的端口上等着，
	// 谁连上来谁就是扫描来源。
	//
	// 它补的是「纯 L4 扫描在应用层完全看不见」这个盲区：被动检测那条路
	// 对 connect 完就关的扫描是断的，主动提供一个诱饵才是可行的做法。
	trap *honeypot

	// honeypotCfg 是蜜罐配置的不可变快照（含预解析的豁免网段）。
	// 蜜罐路径只读它，不取锁 —— 它会在 reload 持锁期间被回调读取。
	honeypotCfg atomic.Pointer[honeypotRuntime]

	// consoleSeen 记住最近用过控制台的来源地址，用于自动封禁的豁免
	// （别把正在操作的人关在门外）。蜜罐路径没有 HTTP 上下文，
	// 拿不到 consoleClientIPs(r)，只能在鉴权通过时顺手记一笔。
	consoleSeen *recentIPs

	// trapLog 是蜜罐日志的限流器：被刷时不能每个包写一行日志。
	trapLog *logLimiter

	// trapObserved 是观察模式下记下的命中次数 —— 它回答的是
	// 「如果现在开启 enforce，会封掉哪些」这个问题。
	trapObserved atomic.Int64
}

func NewApp(configDB string) (*App, error) {
	if err := prepareConfigStore(configDB); err != nil {
		return nil, err
	}
	// 先放一个空账号表而不是留 nil：nil 会让「还没 reload」这个很短的时间窗里
	// 出现 nil 解引用。空表在行为上等价于「没配账号」，语义上也更准确。
	empty, err := newAdminAccounts(nil)
	if err != nil {
		return nil, err
	}
	st, err := storeFor(configDB)
	if err != nil {
		return nil, err
	}
	a := &App{
		configDB:      configDB,
		transport:     newTransport(),
		listeners:     NewListenerManager(),
		metrics:       NewMetrics(),
		logs:          newLogBuffer(logRingSize),
		sessions:      newSessionStore(),
		adminAccounts: empty,
		upgrade:       newUpgradeManager(executablePath(), configDB),
		store:         st,
		consoleSeen:   newRecentIPs(10 * time.Minute),
		trapLog:       newLogLimiter(5, 10*time.Second),
	}
	a.bans = newBanList(st, time.Now)
	a.bans.SetExempt(a.banExempt)
	a.trap = newHoneypot(a.onTrapProbe)

	// 把上次进程留下的封禁读回来。
	//
	// 失败只告警、不阻止启动：一张读不出来的封禁表不该让反代起不来 ——
	// 起不来才是攻击者想要的结果（重启即解封 + 服务中断）。
	if err := a.bans.load(); err != nil {
		slog.Warn("读取封禁表失败，本次从零开始（不影响代理功能）", "err", err)
	}
	return a, nil
}

// prepareConfigStore 打开配置数据库，并在库还是空的时候用旁边的 config.json
// 初始化一次 —— 这是给「已经跑着 config.json 的老部署」准备的升级通道。
//
// 只导入一次：之后 config.json 不再被读取。如果每次都「库为空就导入」，
// 那么用户哪天清空配置（删光所有路由）重启后，旧文件里的内容会突然复活，
// 那比不导入更难排查。
func prepareConfigStore(configDB string) error {
	// 最常见的升级误操作：-c 还指在 config.json 上。
	// 不拦的话会安静地在旁边建一个新的空库，而用户的配置还在原文件里没人读 ——
	// 现象是「升级完配置全没了」，但文件明明还在。
	if fi, err := os.Stat(configDB); err == nil && !fi.IsDir() && !isSQLiteFile(configDB) {
		return fmt.Errorf(
			"%s 不是 SQLite 数据库（看起来还是旧版的 JSON 配置文件）。\n"+
				"    配置源已经换成 SQLite，请二选一：\n"+
				"      1. 保留 -c 指向它，另外执行一次导入：goproxy -config-import %s -c goproxy.db\n"+
				"      2. 直接把 -c 改成 goproxy.db，启动时会自动导入同目录下的 config.json（只导一次）\n"+
				"    详见 README 的「从 v0.8.x 升级」",
			configDB, configDB)
	}

	st, err := storeFor(configDB)
	if err != nil {
		return err
	}
	empty, err := st.isEmpty()
	if err != nil {
		return err
	}
	if !empty {
		return nil
	}

	seed := filepath.Join(filepath.Dir(configDB), "config.json")
	if seed == configDB {
		return nil // -c 指的就是那个 config.json，上面已经拦过了
	}
	imported, err := st.seedFromJSONFile(seed)
	if err != nil {
		return err
	}
	if imported {
		slog.Info("已把旧的 config.json 导入配置数据库（只导入这一次）",
			"file", seed, "db", configDB)
		slog.Info("从现在起配置以数据库为准，config.json 不再被读取，可以留作备份或自行删除")
	}
	return nil
}

// warnIfNoAdminCredentials 在管理端口开着但没有任何凭据时给出明确指引。
//
// 这种状态下管理接口完全打不开，这是有意为之：宁可打不开，也不能出现
// 「没配凭据却谁都能改路由」的情况。但「有意拒绝」和「配置漏了」在现象上
// 是一样的，都会让人对着 401/403 反复试，所以启动时就把话说清楚，
// 并给出可以直接照抄的命令。
func (a *App) warnIfNoAdminCredentials() {
	a.mu.Lock()
	enabled := a.adminAddr != ""
	hasCred := a.hasAnyAdminCredentialLocked()
	a.mu.Unlock()

	if !enabled || hasCred {
		return
	}
	slog.Warn("管理端口已开启，但配置里没有任何管理凭据，所有管理接口都会拒绝访问",
		"admin_addr", a.adminAddr,
		"控制台", "/_goproxy/ui/")
	slog.Warn("请二选一配置后保存，保存后会自动热重载：" +
		"admin_users（用户名加 bcrypt 密码哈希，推荐给浏览器登录）" +
		" 或 admin_token（一个令牌，推荐给脚本和 Prometheus）")
	slog.Warn("生成 password_hash 的命令", "cmd", "goproxy -hash-password <你的密码>")
}

// warnIfConfigUnwritable 启动时探一下配置数据库所在目录能不能写。
//
// 为什么换成 SQLite 之后这件事**没有变简单、反而更要注意**：数据库写入时要在
// 库文件旁边建 -wal / -shm（回滚时还有 -journal）这类临时文件，要求的是
// 「整个目录可写」，而不只是「库文件本身可写」。目录不可写时读取一切正常、
// 只有写入失败 —— 现象是「看得到、改不了」，很容易被当成接口 bug 去查。
//
// 实际踩过：systemd 的 ProtectSystem=strict 把 /etc 挂成只读，单元里
// ReadWritePaths 又只放行了状态目录，于是「删除路由」报
//
//	attempt to write a readonly database
//
// 只告警不退出：配置只读时纯转发仍然完全可用，不该因此起不来。
func (a *App) warnIfConfigUnwritable() {
	if err := a.configWriteProbe(); err != nil {
		slog.Warn("配置目录不可写：管理接口的增删改路由会全部失败",
			"dir", filepath.Dir(a.configDB),
			"err", err,
			"hint", "systemd 需要把该目录加进 ProtectSystem=strict 的 ReadWritePaths，并让服务账号拥有它；"+
				"Docker 要挂目录而不是单个文件（数据库要在旁边写 -wal / -shm，单文件挂载会让它们建不出来）")
	}
}

// configWriteProbe 探一下能不能在配置目录里建文件，返回 nil 表示数据库还能写。
//
// 用 CreateTemp + 立即删除，而不是看权限位：ACL、只读挂载、SELinux
// 都能让权限位显示「可写」而实际写不进去。真正建一个文件才算数。
func (a *App) configWriteProbe() error {
	f, err := os.CreateTemp(filepath.Dir(a.configDB), ".writable-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// reload 重新加载配置并原子替换路由表。
// 整个过程不停机：旧请求继续用旧表跑完，新请求用新表。
func (a *App) reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	cfg, err := loadConfig(a.configDB)
	if err != nil {
		return err
	}
	nets, err := cfg.trustedNets()
	if err != nil {
		return err
	}

	old := a.table.Load()
	tbl, err := buildTable(cfg, old, a.transport)
	if err != nil {
		return err
	}
	// 可信代理网段挂进快照。这里还没 Store，没有并发读者，不需要额外同步。
	tbl.trusted = nets
	// 登录限流也要解析真实 IP，单独存一份引用（它不跟着 tbl 的原子替换走，
	// 但网段本身在配置里很少变，重载时会一起更新）。
	a.trusted.Store(&nets)

	// 释放已经不存在的路由上的限流器（它们各自跑着清理 goroutine）
	if old != nil {
		live := make(map[string]struct{}, len(tbl.routes))
		for _, r := range tbl.routes {
			live[r.ID] = struct{}{}
		}
		for _, r := range old.routes {
			if _, ok := live[r.ID]; !ok && r.limiter != nil {
				r.limiter.Close()
			}
		}
	}

	// 显式关掉管理端口时存空串，Run() 里判空即可，不用再判断一次哨兵
	if cfg.adminEnabled() {
		a.adminAddr = cfg.AdminAddr
	} else {
		a.adminAddr = ""
	}

	// 管理员账号在重载时重建。这一步**同时**实现了「改密码 / 删账号 → 其会话
	// 立刻失效」：会话每次请求都会拿当前账号表的指纹去比对，
	// 账号表一变，旧会话的指纹就对不上了（见 identifyAdminRequest）。
	accounts, err := newAdminAccounts(cfg.AdminUsers)
	if err != nil {
		return err
	}
	a.adminAccounts = accounts
	a.adminToken = cfg.AdminToken
	a.accessLog.Store(cfg.AccessLog)
	a.table.Store(tbl)

	// 构建证书管理器。这是唯一可能失败的新步骤：证书读不出来、
	// ACME 缓存目录建不了，都应该让 reload 报错而不是带病运行。
	tlsmgr, err := newTLSManager(cfg)
	if err != nil {
		return err
	}
	a.tlsmgr.Store(tlsmgr)
	a.tlsCfg.Store(cfg)

	if err := a.listeners.Sync(a.portSpecs(cfg, tlsmgr), a.handler()); err != nil {
		// 单个端口失败不影响其它端口，只告警
		slog.Warn("部分端口监听失败", "err", err)
	}

	// 蜜罐端口：把配置里的端口集合同步过来（幂等的增/删）。
	//
	// 放在 listeners.Sync 之后：本进程要监听的端口集合这时才确定，
	// 冲突判断才有依据 —— 蜜罐绝不能占掉一条真实路由的端口，
	// 那会让那条路由静默失效，比蜜罐不生效糟得多。
	if a.store != nil {
		if hc, err := a.store.readHoneypot(); err != nil {
			slog.Warn("读取蜜罐配置失败，本次不启用蜜罐", "err", err)
		} else if err := a.applyHoneypot(hc, cfg); err != nil {
			slog.Warn("蜜罐端口部分未能生效", "err", err)
		} else if hc.Enabled {
			slog.Info("蜜罐已启用", "mode", hc.Mode, "ports", len(hc.Ports),
				"hint", "连上这些端口的来源会被记账；observe 模式只记录不封禁")
		}
	}
	a.metrics.SetRouteCount(len(tbl.routes))
	a.metrics.IncReload()
	adminShown := a.adminAddr
	if adminShown == "" {
		adminShown = "(已关闭)"
	}
	tlsShown := "off"
	if cfg.TLS.Enabled {
		tlsShown = fmt.Sprintf("on (%d 个 TLS 端口)", len(cfg.tlsPorts()))
	}
	// 全局黑名单非空时单独告警一句。它会影响**所有**入口，包括你正在用的
	// 控制台 —— 所以「现在有几条全局封禁在生效」值得在启动/重载日志里显式出现，
	// 而不是埋在字段里等人自己发现。
	if n := tbl.globalDeny.Len(); n > 0 {
		slog.Warn("全局黑名单已生效", "rules", n, "scope", "所有入口，含管理端口")
	}

	slog.Info("配置已生效",
		"routes", len(tbl.routes),
		"ports", tbl.ListenPorts(),
		"tls", tlsShown,
		"admin", adminShown)
	return nil
}

// portSpecs 把「要监听哪些端口 + 哪些端口跑 TLS」算成 ListenerManager 要的形式。
func (a *App) portSpecs(cfg *Config, m *tlsManager) []portSpec {
	ports := cfg.allListenPorts()
	tlsSet := cfg.tlsPorts()

	specs := make([]portSpec, 0, len(ports))
	for _, p := range ports {
		spec := portSpec{port: p}
		if tlsSet[p] && m != nil {
			spec.tls = tlsListenerInfo{
				enabled: true,
				config:  cfg.tlsConfigFor(m),
			}
		}
		specs = append(specs, spec)
	}
	return specs
}

// acmeChallengePrefix 是 ACME HTTP-01 挑战的固定路径前缀（RFC 8555）。
const acmeChallengePrefix = "/.well-known/acme-challenge/"

// httpsRedirectURL 把当前明文请求改写成对应的 HTTPS 地址。
//
// 几个必须做对的细节：
//   - 端口：HTTPS 端口是 443 时**不写端口**。写成 "https://a.com:443/"
//     虽然功能上等价，但地址栏里会一直显示 :443，容易让人误判成配错了。
//   - Host：用 r.Host 保留客户端请求的域名（它自带端口则剥掉）。
//   - 路径与查询串原样带上，否则跳转后会丢参数。
func (a *App) httpsRedirectURL(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	httpsPort := 0
	if cfg := a.tlsCfg.Load(); cfg != nil {
		httpsPort = cfg.TLS.HTTPSPort
	}

	var b strings.Builder
	b.WriteString("https://")
	b.WriteString(host)
	if httpsPort != 0 && httpsPort != defaultHTTPSPort {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(httpsPort))
	}
	b.WriteString(r.URL.EscapedPath())
	if q := r.URL.RawQuery; q != "" {
		b.WriteByte('?')
		b.WriteString(q)
	}
	return b.String()
}

// handler 是所有监听端口共用的入口。端口从 context 里取。
//
// 请求处理拆成一条顺序管线：每一关是一个独立方法，返回 true 表示「已在
// 这一关拦截并写好了响应」，主函数随即 return。顺序即语义（全局黑名单必须在
// 路由匹配之前，明文端口上的 ACME 挑战绝不能先跳转），不可随意调整。
func (a *App) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		port := 0
		if v, ok := r.Context().Value(ctxKeyPort{}).(int); ok {
			port = v
		}

		// 状态码在这一层统一记录：转发分支之外的 ACL / 限流 / 熔断 / 认证
		// 也会提前返回，只有包住整个 handler 才能把它们的状态码一起拿到。
		rec := newStatusRecorder(w)

		tbl := a.table.Load()
		var trusted []*net.IPNet
		if tbl != nil {
			trusted = tbl.trusted
		}
		ip := clientIP(r, trusted)

		// 每次请求只记一条访问日志，所以收口在 defer 里，
		// 而不是在下面每个拦截分支各写一遍（漏一处就少一类日志）。
		// rt / blocked 是跨关共享的可变状态：defer 读的是它们的最新值。
		var (
			rt      *Route
			blocked string
		)
		defer func() {
			a.logAccess(r, port, rt, blocked, ip, rec.code, start)
		}()

		if tbl == nil {
			writeJSON(rec, http.StatusServiceUnavailable, map[string]string{"error": "路由表尚未就绪"})
			return
		}

		// 0) 全局黑名单（在路由匹配之前，见 checkGlobalDeny）
		if a.checkGlobalDeny(rec, tbl, ip, &blocked) {
			return
		}

		// 0.5) 自动封禁（实现见 banlist.go / banapi.go）
		//
		// 必须在路由匹配**之前**，理由和全局黑名单完全一样：扫描流量大多
		// 匹配不到任何路由，放在后面等于对它们完全失效。
		// 放在人工黑名单之后：人工声明是权威、自动判据是临时态。
		if a.checkAutoBan(rec, r, ip, &blocked) {
			return
		}

		// 明文端口：ACME 挑战、HTTP→HTTPS 跳转
		if a.handlePlaintext(rec, r, tbl, port, &blocked) {
			return
		}

		// 路由匹配
		rt = tbl.Match(port, r.Host, r.URL.Path)
		if rt == nil {
			// blocked 标签这里必须有名字。
			//
			// 不设的话，访问日志里「未匹配到路由」与普通请求长得一模一样 ——
			// 而它恰恰是最重要的一个信号：扫描器挨个路径试过来时，
			// 绝大多数请求就落在这一支（日志页看不出来，行为检测也没有抓手）。
			blocked = "no_route"
			a.metrics.IncRequest("", http.StatusNotFound)
			writeJSON(rec, http.StatusNotFound, map[string]any{
				"error": "no_route_matched",
				"port":  port,
				"host":  r.Host,
				"path":  r.URL.Path,
			})
			slog.Debug("未匹配到路由", "port", port, "host", r.Host, "path", r.URL.Path)
			return
		}

		// 1) 路由级 IP 名单 → 2) 限流 → 3) 熔断 → 4) 认证
		if a.checkRouteACL(rec, rt, ip, &blocked) {
			return
		}
		if a.checkRateLimit(rec, rt, ip, &blocked) {
			return
		}
		if a.checkCircuit(rec, rt, &blocked) {
			return
		}
		if a.checkAuth(rec, r, rt, &blocked) {
			return
		}

		// 5) 转发
		a.metrics.IncInFlight(rt.ID)
		rt.proxy.ServeHTTP(rec, r)
		a.metrics.DecInFlight(rt.ID)

		if rt.cb != nil {
			rt.cb.Record(isBackendFailure(rec.code))
		}

		a.metrics.Observe(rt.ID, time.Since(start).Seconds())
		a.metrics.IncRequest(rt.ID, rec.code)
	})
}

// checkGlobalDeny 是请求管线的第 0 关：全局黑名单。
//
// 必须排在路由匹配**之前**：它管的是「所有入口」，其中恰恰包括
// **匹配不到任何路由**的那些请求。如果放在路由匹配之后，扫描器挨个端口
// 扫过来时压根不会命中任何路由，也就永远走不到这份名单 —— 而那正是最需要
// 拦下的流量。放在这里还有附带好处：被全局封禁的地址连 ACME 挑战和
// HTTP→HTTPS 跳转都不会触发，是最彻底的拒绝。
func (a *App) checkGlobalDeny(rec *statusRecorder, tbl *RouteTable, ip string, blocked *string) bool {
	gdec := decideIP(tbl.globalDeny, nil, ip, false)
	if gdec.Allowed {
		return false
	}
	*blocked = gdec.Reason
	// 路由标签留空：全局封禁不属于任何一条路由，硬填一个 ID 是假信息。
	// 404 分支也是这么处理的。
	a.metrics.IncRejected("", gdec.Reason)
	a.metrics.IncRequest("", http.StatusForbidden)
	// 响应体刻意不带命中的具体规则：那等于告诉扫描器「你踩到哪条线了」。
	// 具体规则进访问日志（blocked 标签 + 命中测试工具），运维看得到，对面学不到。
	writeJSON(rec, http.StatusForbidden, map[string]any{
		"error":  "forbidden",
		"reason": gdec.Reason,
	})
	return true
}

// handlePlaintext 处理明文端口上的两件事，顺序不能乱：
//  1. ACME 的 HTTP-01 挑战 —— 它必须能到达，绝不能跳转，一跳转
//     Let's Encrypt 的验证就失败（而且是静默失败，很难查）。
//  2. HTTP→HTTPS 重定向（该路由开了 TLS 且要求跳转）。
//
// 返回 true 表示这一关已经写好了响应（挑战已响应 / 已跳转）。
func (a *App) handlePlaintext(rec *statusRecorder, r *http.Request, tbl *RouteTable, port int, blocked *string) bool {
	if requestIsTLS(r) {
		return false
	}
	if m := a.tlsmgr.Load(); m != nil && m.acme != nil {
		// autocert 的 HTTPHandler 认识 /.well-known/acme-challenge/ 前缀
		// 并直接响应，其余请求交给 fallback。传 nil fallback 之前先判前缀，
		// 避免它为每个普通请求都掺一脚。
		if strings.HasPrefix(r.URL.Path, acmeChallengePrefix) {
			m.acme.HTTPHandler(nil).ServeHTTP(rec, r)
			return true
		}
	}

	// 该路由开了 TLS 且要求跳转 → 301 到 HTTPS
	if rt := tbl.Match(port, r.Host, r.URL.Path); rt != nil && rt.wantsHTTPSRedirect() {
		target := a.httpsRedirectURL(r)
		rec.Header().Set("Location", target)
		// 301 是永久重定向，浏览器会缓存。这里用 301 是因为「明文→HTTPS」
		// 的策略确实不会来回变，让客户端把跳转记下来能省掉一次明文往返。
		rec.WriteHeader(http.StatusMovedPermanently)
		*blocked = "redirected_to_https"
		a.metrics.IncRequest(rt.ID, http.StatusMovedPermanently)
		return true
	}
	return false
}

// checkRouteACL 是第 1 关：路由级 IP 名单（白名单 + 黑名单）。
// 全局黑名单已经在 checkGlobalDeny 判过，这里传 nil 跳过它，避免同一次请求算两遍。
func (a *App) checkRouteACL(rec *statusRecorder, rt *Route, ip string, blocked *string) bool {
	adec := decideIP(nil, rt.acl, ip, false)
	if adec.Allowed {
		return false
	}
	*blocked = adec.Reason
	a.metrics.IncRejected(rt.ID, adec.Reason)
	a.metrics.IncRequest(rt.ID, http.StatusForbidden)
	writeJSON(rec, http.StatusForbidden, map[string]any{
		"error":  "forbidden",
		"route":  rt.ID,
		"reason": adec.Reason,
		"layer":  adec.Layer,
	})
	return true
}

// checkRateLimit 是第 2 关：限流。
func (a *App) checkRateLimit(rec *statusRecorder, rt *Route, ip string, blocked *string) bool {
	if rt.limiter == nil || rt.limiter.Allow(ip) {
		return false
	}
	*blocked = "rate_limited"
	a.metrics.IncRateLimited(rt.ID)
	a.metrics.IncRequest(rt.ID, http.StatusTooManyRequests)
	rec.Header().Set("Retry-After", "1")
	writeJSON(rec, http.StatusTooManyRequests, map[string]any{
		"error": "rate_limited",
		"route": rt.ID,
	})
	return true
}

// checkCircuit 是第 3 关：熔断。后端已经不行了就别再打了，直接快速失败。
func (a *App) checkCircuit(rec *statusRecorder, rt *Route, blocked *string) bool {
	if rt.cb == nil || rt.cb.Allow() {
		return false
	}
	*blocked = "circuit_open"
	a.metrics.IncRejected(rt.ID, "circuit_open")
	a.metrics.IncRequest(rt.ID, http.StatusServiceUnavailable)
	retryAfter := rt.cb.cfg.OpenSecs
	if retryAfter < 1 {
		retryAfter = 1
	}
	rec.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeJSON(rec, http.StatusServiceUnavailable, map[string]any{
		"error":       "circuit_open",
		"route":       rt.ID,
		"retry_after": retryAfter,
	})
	return true
}

// checkAuth 是第 4 关：认证。
func (a *App) checkAuth(rec *statusRecorder, r *http.Request, rt *Route, blocked *string) bool {
	if rt.auth == nil {
		return false
	}
	claims, ok, reason := rt.auth.Authenticate(r)
	if !ok {
		*blocked = "auth_" + reason
		rt.auth.WriteChallenge(rec)
		a.metrics.IncRejected(rt.ID, "auth_"+reason)
		a.metrics.IncRequest(rt.ID, http.StatusUnauthorized)
		writeJSON(rec, http.StatusUnauthorized, map[string]any{
			"error":  "unauthorized",
			"route":  rt.ID,
			"reason": reason,
		})
		return true
	}
	rt.auth.OnSuccess(r, claims)
	return false
}

// logAccess 把一条访问记录同时送进内存环形缓冲和结构化日志。
//
// 两者的开关是分开的，这是有意的：
//   - 环形缓冲始终记录（定长 500 条、只占内存、不落盘），管理台的实时日志靠它，
//     关掉的话界面直接空掉；
//   - access_log 控制的是标准输出那条日志，量大了或者要接日志系统时由它决定。
func (a *App) logAccess(r *http.Request, port int, rt *Route, blocked, ip string, status int, start time.Time) {
	e := LogEntry{
		Time:     formatLogTime(start),
		Port:     port,
		Host:     r.Host,
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Status:   status,
		DurMs:    float64(time.Since(start).Microseconds()) / 1000,
		ClientIP: ip,
		UA:       r.UserAgent(),
		Blocked:  blocked,
	}
	if rt != nil {
		e.Route = rt.ID
		e.RouteName = rt.Name
	}
	a.logs.Add(e)

	if !a.accessLog.Load() {
		return
	}
	slog.Info("access",
		"route", e.Route,
		"port", port,
		"host", r.Host,
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"dur_ms", int(e.DurMs),
		"client_ip", ip,
		"blocked", blocked,
		"ua", r.UserAgent(),
	)
}

// adminHandler 管理端口的总入口。
//
// 分成三层是有意为之：
//
//	/_goproxy/ui/  控制台静态资源，不鉴权（理由见 webui.go 的 uiHandler）
//	接口路径        健康检查、指标、管理接口，一律走 adminGuard
//	其余路径        按「人还是机器」分流 —— 人送控制台，机器给纯文本清单
//
// 第三层不能省。早期版本只把精确的 "/" 重定向到控制台，其余全交给管理接口
// 那个兜底的 "/"，结果是：用户在浏览器里手写 /_goproxy/（最容易猜的地址）
// 看到的是纯文本接口清单，而 / 才进控制台 —— 表现得像「控制台没生效」。
// adminIPGuard 把全局黑名单套到管理端口上。
//
// 为什么要在业务侧之外再套一遍：管理端口是独立监听的，走的是完全另一套
// handler，业务请求那条管线覆盖不到它。「全局」的意思是对**所有入口**生效，
// 所以这里必须单独判一次。
//
// 关于客户端 IP 的取值，有一个容易误判的地方：如果控制台是通过自己的路由
// 发布出去的（比如把管理端口挂到公网 32000 上），那么到达管理端口的这一跳
// 来自本机反向代理，RemoteAddr 是 127.0.0.1。这看起来像是「判定用错了 IP」，
// 其实不然 —— 那个请求在**外层业务端口**上已经用真实客户端 IP 判过全局黑名单了，
// 走到这里的是已经放行的流量。两层都在判，各自覆盖自己看得到的那个来源。
func (a *App) adminIPGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tbl := a.table.Load()
		if tbl == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r, tbl.trusted)
		dec := decideIP(tbl.globalDeny, nil, ip, false)
		if !dec.Allowed {
			a.metrics.IncRejected("", dec.Reason)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":  "forbidden",
				"reason": dec.Reason,
			})
			return
		}
		// 自动封禁同样覆盖管理端口。
		//
		// 「全局」的意思是对所有入口生效，自动封禁和全局黑名单在这一点上
		// 没有区别：被封的来源是扫描器，它没有任何理由访问控制台。
		// 不会把自己关在门外 —— 正在用控制台的人命中豁免（见 banExempt）。
		if entry, banned := a.bans.lookup(ip); banned {
			a.metrics.IncRejected("", "auto_ban")
			refuseAutoBanned(w, r, ip, entry)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) adminHandler() http.Handler {
	guarded := a.adminGuard(a.adminMux())

	// 登录/会话这两条路径**必须在 adminGuard 之外**。
	//
	// 这不是随手放行，而是登录本身的语义决定的：登录接口的职责就是
	// 「在还没有凭据的时候拿到凭据」，把它放在 Guard 之内等于把钥匙锁在屋里 ——
	// 未登录的浏览器只会拿到 401，永远走不到登录页。
	// （这个坑真实踩过：/login 曾经注册在 adminMux 上，结果所有登录测试全 401。）
	//
	// 放行不等于不设防，两条路径各自带完整防护：
	//   - /login  ：来源同源校验 + 按 IP/全局失败计数封禁 + 恒定耗时 + 常量时间比对
	//   - /session：GET 只读且不泄漏信息（自己报告当前凭据来源）；写方法要同源校验
	// 其余所有管理接口仍然一律经过 adminGuard，没有任何豁免。
	auth := http.NewServeMux()
	auth.HandleFunc("/_goproxy/login", a.handleLogin)
	auth.HandleFunc("/_goproxy/session", a.handleSession)

	root := http.NewServeMux()
	root.Handle(uiPrefix, a.uiHandler())
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isAuthPath(r.URL.Path) {
			auth.ServeHTTP(w, r)
			return
		}

		if isAdminAPIPath(r.URL.Path) {
			guarded.ServeHTTP(w, r)
			return
		}

		// 到这里的都不是接口路径：根路径、只写了前缀的 /_goproxy、以及写错的地址。
		// 浏览器（Accept 含 text/html）一律送控制台，不管它敲的是哪一个 ——
		// 人在地址栏里试地址时不该被一本纯文本清单接住。
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && wantsHTML(r) {
			if _, ok := uiFS(); ok {
				http.Redirect(w, r, uiPrefix, http.StatusFound)
				return
			}
		}

		if isAdminLandingPath(r.URL.Path) {
			serveAdminIndex(w)
			return
		}

		// 写错的地址老实报 404。以前所有未知路径都回 200 + 接口清单，
		// 于是 `curl -f /_goproxy/statss` 这种拼写错误看着像成功。
		http.NotFound(w, r)
	})
	// 安全头包在最外层：无论落到静态资源、接口还是纯文本清单都会带上。
	// 全局黑名单放在安全头**之内**，这样被它拦下的 403 也带着安全头。
	return securityHeaders(a.adminIPGuard(root))
}

// isAuthPath 判断路径是不是「登录/会话」这两条需要在认证前就能访问的接口。
//
// 单独列出来而不是复用 isAdminAPIPath，是为了让「哪些路径绕过了 adminGuard」
// 这件事在代码里一眼可见 —— 安全评审时只需要看这一个函数。
func isAuthPath(p string) bool {
	return p == "/_goproxy/login" || p == "/_goproxy/session"
}

// isAdminAPIPath 判断路径是不是管理端接口。
//
// 必须在交给 adminGuard 之前判断，不能指望「先转发、mux 兜底了再说」：
// 浏览器直接打开 /_goproxy/routes 也要拿到 JSON，不能因为带了
// Accept: text/html 就被重定向到控制台。
func isAdminAPIPath(p string) bool {
	switch p {
	case "/healthz", "/readyz", "/metrics":
		return true
	}
	// /_goproxy/ui/ 开头的属于控制台自己的资源；
	// 光秃秃的 /_goproxy 和 /_goproxy/ 是「人在找控制台」，都不算接口。
	return strings.HasPrefix(p, "/_goproxy/") &&
		p != "/_goproxy/" &&
		!strings.HasPrefix(p, uiPrefix)
}

// isAdminLandingPath 保留几个「人在找管理端」的地址给纯文本清单，
// 让 curl 用户仍然能一眼看到接口列表和真正的控制台地址。
func isAdminLandingPath(p string) bool {
	return p == "/" || p == "/_goproxy" || p == "/_goproxy/"
}

// serveAdminIndex 输出纯文本接口清单。给不带 Accept: text/html 的调用方
// （curl、监控探针、脚本）看，所以刻意不做成网页。
func serveAdminIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "goproxy admin\n"+
		"  管理控制台（浏览器打开）  "+uiPrefix+"\n"+
		"  登录用配置里 admin_users 的用户名 / 密码（或 admin_token）\n"+
		"  以下接口全部需要凭据（会话 Cookie 或 Bearer 令牌），本机访问也不例外：\n"+
		"  /healthz  /readyz  /metrics\n"+
		"  /_goproxy/login           POST {username,password} 或 {token} 换取会话 Cookie\n"+
		"  /_goproxy/session         GET 当前登录态  DELETE 登出\n"+
		"  /_goproxy/routes          GET 列出路由  POST 新建\n"+
		"  /_goproxy/routes/{id}     GET / PUT / PATCH(局部改) / DELETE\n"+
		"  /_goproxy/config          GET / PATCH 全局配置（含 global_ip_deny 全局黑名单）\n"+
		"  /_goproxy/acl/test        GET ?ip=&route_id= 或 POST {ip,route_id} 名单命中测试\n"+
		"  /_goproxy/ports           当前监听端口\n"+
		"  /_goproxy/certs           证书状态（域名/签发者/到期/来源）\n"+
		"  /_goproxy/stats           聚合状态（指标 + 采样曲线 + 熔断计数）\n"+
		"  /_goproxy/logs            最近访问记录  ?limit=N\n"+
		"  /_goproxy/events          实时访问日志（SSE）\n"+
		"  /_goproxy/reload          POST 手动重载配置\n"+
		"  /_goproxy/bans            GET 自动封禁列表 + 蜜罐状态  POST {ip,reason,secs} 手动封禁\n"+
		"  /_goproxy/bans/unban      POST {ip:\"1.2.3.4\"} 或 {ip:\"all\"} 解封\n"+
		"  /_goproxy/honeypot        PUT 蜜罐端口 / 开关 / 模式（observe|enforce）\n"+
		"  /_goproxy/upgrade         GET 当前版本 / 升级能力 / 备份与暂存状态\n"+
		"  /_goproxy/upgrade/upload  POST 上传二进制（multipart 的 file 字段，或直接把文件当请求体）\n"+
		"  /_goproxy/upgrade/install POST {\"sha256\":\"可选\"} 安装已暂存的文件\n"+
		"  /_goproxy/upgrade/rollback POST 回退到 <exe>.old（上一次升级前的版本）\n")
}

// handleCerts 返回所有证书的状态。
//
// 未启用 TLS 时返回空列表而不是 404：「没配 TLS」和「配了但没证书」
// 是两件不同的事，前者前端展示为「TLS 未启用」的空态，
// 用 404 会让它看起来像接口挂了。
func (a *App) handleCerts(w http.ResponseWriter, r *http.Request) {
	m := a.tlsmgr.Load()
	certs := []CertStatus{}
	if m != nil {
		certs = m.Status()
	}

	enabled := false
	acme := ""
	if cfg := a.tlsCfg.Load(); cfg != nil {
		enabled = cfg.TLS.Enabled
		if cfg.TLS.ACME != nil {
			acme = cfg.TLS.ACME.effectiveDirectoryURL()
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tls_enabled": enabled,
		"acme_dir":    acme,
		"certs":       certs,
	})
}

// adminMux 是真正的管理接口集合，整体由 adminGuard 保护。
func (a *App) adminMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.table.Load() == nil {
			http.Error(w, "route table not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		io.WriteString(w, a.metrics.Render())
	})
	// 路由与全局配置的读写接口（实现见 admin_api.go）
	mux.HandleFunc("GET /_goproxy/routes", a.handleListRoutes)
	mux.HandleFunc("POST /_goproxy/routes", a.handleCreateRoute)
	mux.HandleFunc("GET /_goproxy/routes/{id}", a.handleGetRoute)
	mux.HandleFunc("PUT /_goproxy/routes/{id}", a.handleReplaceRoute)
	mux.HandleFunc("PATCH /_goproxy/routes/{id}", a.handlePatchRoute)
	mux.HandleFunc("DELETE /_goproxy/routes/{id}", a.handleDeleteRoute)
	mux.HandleFunc("GET /_goproxy/config", a.handleGetConfig)
	mux.HandleFunc("PATCH /_goproxy/config", a.handlePatchConfig)
	// IP 名单的命中测试：GET ?ip=&route_id= 或 POST {ip, route_id}。
	// 不填 ip 就是「测我自己」，控制台的一键自检靠它。
	mux.HandleFunc("/_goproxy/acl/test", a.handleACLTest)
	// 管理台的数据源（实现见 stats.go）
	mux.HandleFunc("GET /_goproxy/stats", a.handleStats)
	mux.HandleFunc("GET /_goproxy/logs", a.handleLogs)
	mux.HandleFunc("GET /_goproxy/events", a.handleEvents)
	mux.HandleFunc("/_goproxy/ports", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.listeners.PortInfos())
	})
	// 登录 / 会话不在这里注册 —— 它们由 adminHandler 在外层单独分派，
	// 因为登录接口必须能在「尚未认证」时被访问到。见 adminHandler 里的注释。
	// 证书状态：域名、签发者、到期时间、来源。控制台的证书页读它。
	mux.HandleFunc("GET /_goproxy/certs", a.handleCerts)
	mux.HandleFunc("/_goproxy/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		if err := a.reload(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ports": a.listeners.Ports()})
	})
	// ---------- 升级（实现见 upgrade.go / upgradefetch.go）----------
	// 这是整套管理接口里唯一会改动**二进制文件本身**的一组，所以：
	// 所有动作串行（upgradeManager.busy），每次动作写审计日志（谁触发的），
	// 并且安装 / 回退在换文件之前一律先跑一次新二进制的 -version。
	mux.HandleFunc("GET /_goproxy/upgrade", a.handleUpgradeState)
	mux.HandleFunc("POST /_goproxy/upgrade/upload", a.handleUpgradeUpload)
	mux.HandleFunc("POST /_goproxy/upgrade/install", a.handleUpgradeInstall)
	mux.HandleFunc("POST /_goproxy/upgrade/rollback", a.handleUpgradeRollback)

	// ---------- 自动封禁与蜜罐（实现见 banlist.go / honeypot.go / banapi.go）----------
	//
	// 这一组管的是**运行态**而不是配置：封禁条目故意不进 Config，
	// 所以它有自己的读写接口，也不进 revision（否则每次自动封禁都会让
	// 正在编辑控制台的人撞一次 409）。
	mux.HandleFunc("GET /_goproxy/bans", a.handleBansState)
	mux.HandleFunc("POST /_goproxy/bans", a.handleBanCreate)
	mux.HandleFunc("POST /_goproxy/bans/unban", a.handleBanRemove)
	mux.HandleFunc("PUT /_goproxy/honeypot", a.handleHoneypotUpdate)

	// 这里刻意**不注册** "/" 兜底。兜底一旦放在 mux 里，它就会替所有拼错的
	// 接口地址回 200，把 404 变成「看起来成功」。未知路径由 adminHandler 统一处置。
	return mux
}

// 这里曾经有一个 watchLoop：每秒 stat 一次 config.json 的 mtime / size，
// 变了就热重载，用来支持「手工编辑配置文件」。
//
// v0.9.0 换到 SQLite 之后它被**去掉**了，而不是换成「轮询数据库文件」。
// 配置现在只经管理接口修改，而写接口保存成功后自己就会调 reload()，
// 本来就不需要外部的变化检测。留一个轮询只会带来两个坏处：
// 每次保存都要等下一次 tick 才发现变化（平白慢一秒），
// 以及暗示「直接拿 sqlite3 改库」是支持的 —— 那条路会绕过校验、自锁检查和
// 引用完整性，而这些检查恰恰是配置安全的地方。
//
// 需要批量或离线改配置时走命令行：
//
//	goproxy -config-export config.json   # 导出成人可读的 JSON，改完再导入
//	goproxy -config-import config.json   # 导入（走完整校验，失败不动原配置）

// statsLoop 定期把熔断器状态同步到指标。
// 熔断状态是「当前值」而不是累加值，只能采样，不能靠请求触发。
func (a *App) statsLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tbl := a.table.Load()
			if tbl == nil {
				continue
			}
			states := make(map[string]int, len(tbl.routes))
			for _, r := range tbl.routes {
				if r.cb == nil {
					continue
				}
				states[r.ID] = int(r.cb.State())
				a.metrics.SetCBStats(r.ID, r.cb.openedTotal.Load(), r.cb.rejectedTotal.Load())
			}
			a.metrics.SetCircuitStates(states)
		}
	}
}

// sampleLoop 每秒采一个点，保留最近 5 分钟的 QPS / 错误率曲线。
//
// 采样放在服务端而不是让前端攒：界面一打开就该有历史曲线，
// 否则刷新一次页面曲线就从头开始长，没法判断「刚才那波错误还在不在」。
func (a *App) sampleLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.metrics.Sample(now)
		}
	}
}

// sessionSweepLoop 定期清掉过期会话与陈旧的登录失败记录。
//
// 会话是内存里的 map，如果不主动清理，过期条目会一直留着 ——
// 单管理员的场景下量很小，但「过期即失效」如果只靠 lookup 时判断，
// 内存占用就只增不减，长期跑着不放心。
func (a *App) sessionSweepLoop(ctx context.Context) {
	t := time.NewTicker(sessionSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sessions.sweep()
		}
	}
}

func (a *App) Run(ctx context.Context) error {
	// 启动第一行就报版本：线上排查「到底跑的是哪一版」时，
	// journalctl 的头几行就能回答，不用去翻二进制。
	slog.Info("goproxy 启动", "version", version, "commit", commit)

	if err := a.reload(); err != nil {
		return err
	}

	// 放在 reload 之后：配置文件本身读不到会先在这里上面就退出，
	// 能走到这说明「读」没问题，接下来要确认「写」也没问题。
	a.warnIfConfigUnwritable()
	// 同理，「管理凭据没配」也要等 reload 之后才能判断（reload 才把
	// 配置里的账号表建起来）。
	a.warnIfNoAdminCredentials()

	a.mu.Lock()
	adminAddr := a.adminAddr
	a.mu.Unlock()

	var adminSrv *http.Server
	if adminAddr != "" {
		adminSrv = &http.Server{
			Addr:              adminAddr,
			Handler:           a.adminHandler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln, err := net.Listen("tcp", adminAddr)
		if err != nil {
			return err
		}
		go func() {
			slog.Info("管理端口已启动", "addr", adminAddr)
			if err := adminSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				slog.Error("管理端口异常退出", "err", err)
			}
		}()
	}

	go a.statsLoop(ctx)
	go a.sampleLoop(ctx)
	go a.sessionSweepLoop(ctx)
	// 封禁集合自己起两个循环：攒批落盘 + 周期清扫与外部同步。
	// 它们由 bans.Close() 收尾，所以这里不挂 ctx。
	a.bans.Start()

	<-ctx.Done()
	slog.Info("收到退出信号，开始优雅停机")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a.listeners.ShutdownAll(shutdownCtx)
	// 蜜罐端口也要关：它监听的是业务之外的端口，listeners 管不到它。
	a.trap.Close()
	// 封禁落盘：bans.Close 会先把攒着的写下去再退出。
	// 否则「刚封完就重启」会丢一批 —— 而重启恰好可能是运维为了别的
	// 事情做的，不该顺手把封禁清掉。
	a.bans.Close()
	if adminSrv != nil {
		_ = adminSrv.Shutdown(shutdownCtx)
	}
	slog.Info("已停机")
	return nil
}

// runConfigIO 处理 -config-import / -config-export。
//
// 导入和导出共用这一次「打开数据库」：两个子命令都要先有库。
func runConfigIO(configDB, importPath, exportPath string) error {
	st, err := storeFor(configDB)
	if err != nil {
		return err
	}

	if exportPath != "" {
		raw, err := st.exportJSON()
		if err != nil {
			return err
		}
		// 0600：导出的 JSON 里有 admin_token 与密码哈希，不该让同机其它用户读到。
		if err := os.WriteFile(exportPath, raw, 0o600); err != nil {
			return fmt.Errorf("写出 %s 失败: %w", exportPath, err)
		}
		slog.Info("配置已导出", "file", exportPath, "bytes", len(raw))
		return nil
	}

	raw, err := os.ReadFile(importPath)
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", importPath, err)
	}
	rev, err := st.importJSON(raw)
	if err != nil {
		return err
	}
	slog.Info("配置已导入", "file", importPath, "revision", rev[:12])
	slog.Info("若服务正在运行，需重启或调一次 POST /_goproxy/reload 才会生效" +
		"（导入只写库，不碰进程里已经加载的路由表）")
	return nil
}

// 编译时通过 -ldflags "-X main.version=... -X main.commit=..." 注入
var (
	version = "dev"
	commit  = "none"
)

func main() {
	configDB := flag.String("c", "goproxy.db", "配置数据库（SQLite）路径")
	logLevel := flag.String("log-level", "info", "日志级别: debug|info|warn|error")
	textLog := flag.Bool("text-log", false, "输出人类可读日志（默认 JSON）")
	showVer := flag.Bool("version", false, "打印版本信息并退出")
	hashPw := flag.String("hash-password", "",
		"把给定密码算成 bcrypt 哈希并退出（用于填进控制台的 admin_users[].password_hash）")
	importCfg := flag.String("config-import", "",
		"把一份 JSON 配置导入数据库后退出，例如 -c goproxy.db -config-import config.json")
	exportCfg := flag.String("config-export", "",
		"把数据库里的配置导出成 JSON 后退出，例如 -c goproxy.db -config-export config.json")
	applyUpgrade := flag.Bool("upgrade-apply", false,
		"以 root 应用控制台「升级」页暂存好的新版本（服务账号写不进二进制目录时用它）")
	rollbackUpgrade := flag.Bool("upgrade-rollback", false,
		"以 root 回退到 <exe>.old（升级模块留下的上一版）")
	listBans := flag.Bool("bans", false,
		"列出当前的自动封禁并退出（服务在不在跑都能用）")
	unban := flag.String("unban", "",
		"解封一个地址或全部：-unban 1.2.3.4 / -unban all")
	honeypotSet := flag.String("honeypot-set", "",
		"设置蜜罐端口列表，例如 -honeypot-set \"23,3389,5900/udp\"（逗号或空格分隔）")
	honeypotMode := flag.String("honeypot-mode", "",
		"蜜罐模式：observe（只记录，默认）| enforce（命中即封禁）| off（关闭）")
	flag.Parse()

	if *showVer {
		fmt.Printf("goproxy %s (commit %s)\n", version, commit)
		return
	}

	if *hashPw != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(*hashPw), bcrypt.DefaultCost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "生成失败: %v\n", err)
			os.Exit(1)
		}
		// 只往 stdout 打哈希本身，方便直接 $(...) 取用。
		// 提示语走 stderr，免得被一起捕获进去。
		fmt.Println(string(h))
		fmt.Fprintln(os.Stderr, "把上面这行填进控制台的 admin_users[].password_hash（账号在控制台的「配置」页维护）")
		return
	}

	var lvl slog.Level
	switch *logLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if *textLog {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))

	// 导入 / 导出：干完就退出，不起服务。
	//
	// 这两个子命令替代的是以前「直接编辑 config.json，进程靠 mtime 轮询热重载」
	// 那条路。导入走完整校验（含旧写法拦截与默认值补齐），失败时数据库一个字节不动。
	if *importCfg != "" || *exportCfg != "" {
		if err := runConfigIO(*configDB, *importCfg, *exportCfg); err != nil {
			slog.Error("配置导入/导出失败", "err", err)
			os.Exit(1)
		}
		return
	}

	// 托管升级的第二半：以 root 应用 / 回退。
	//
	// install.sh 装出来的实例里服务以 goproxy 跑、/usr/local/bin 属 root，进程自己
	// 写不进去，于是控制台只负责下载、校验、验证并暂存，最后这一步交给 root 执行：
	//
	// goproxy -c <库> -upgrade-apply      应用暂存的新版本
	// goproxy -c <库> -upgrade-rollback   回退到 <exe>.old
	//
	// 必须在 NewApp 之前处理：它只需要 -c 来推导暂存目录，不该顺手把配置库建出来。
	if *applyUpgrade || *rollbackUpgrade {
		if err := runUpgradeApply(*configDB, *rollbackUpgrade); err != nil {
			slog.Error("应用升级失败", "err", err)
			os.Exit(1)
		}
		return
	}

	// 封禁与蜜罐的命令行入口：干完就退出，不起服务。
	//
	// 这一组存在的理由是「控制台进不去的时候还有路可走」：
	// 自动封禁有可能把正在操作的人封在外面（判据完全来自网络行为），
	// 所以必须有一条不依赖控制台、也不依赖网络的解封通道。
	// 与 -upgrade-apply 同一个思路。
	if *listBans {
		if err := runBanList(*configDB); err != nil {
			slog.Error("读取封禁列表失败", "err", err)
			os.Exit(1)
		}
		return
	}
	if *unban != "" {
		if err := runUnban(*configDB, *unban); err != nil {
			slog.Error("解封失败", "err", err)
			os.Exit(1)
		}
		return
	}
	if *honeypotSet != "" || *honeypotMode != "" {
		var (
			mode    string
			enabled *bool
		)
		set := func(b bool) *bool { return &b }
		switch *honeypotMode {
		case "":
			// 只改端口，不动开关
		case honeypotModeObserve, "observe-only":
			mode, enabled = honeypotModeObserve, set(true)
		case honeypotModeEnforce, "on":
			mode, enabled = honeypotModeEnforce, set(true)
		case "off", "disable", "false":
			enabled = set(false)
		default:
			slog.Error("honeypot-mode 取值不合法",
				"got", *honeypotMode, "want", "observe|enforce|off")
			os.Exit(1)
		}
		if err := runHoneypotSet(*configDB, *honeypotSet, mode, enabled); err != nil {
			slog.Error("设置蜜罐失败", "err", err)
			os.Exit(1)
		}
		return
	}
	app, err := NewApp(*configDB)
	if err != nil {
		slog.Error("初始化失败", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil {
		slog.Error("运行失败", "err", err)
		os.Exit(1)
	}
}
