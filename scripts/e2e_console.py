#!/usr/bin/env python3
"""管理控制台端到端自检。

用真实的后端 + 真实的反代二进制跑（不是 httptest），覆盖控制台依赖的全部接口：

  1. 控制台静态资源能加载，路径与缓存头都对
  2. 浏览器访问根路径被导向控制台，curl 拿到的是纯文本接口清单
  3. 真实流量能进到 stats / logs
  4. SSE 能收到 hello 握手和后续 access 事件
  5. 路由 CRUD 写接口 + ETag 乐观并发
  6. 全局配置读改、健康检查、Prometheus 指标
  7. 认证与会话（用户名 + 密码登录、Cookie、CSRF 同源校验）
  8. 三层 IP 名单（全局黑名单 / 路由白名单 / 路由黑名单）与命中测试接口

用法（在仓库根目录或任意位置都行）：

    python scripts/e2e_console.py

脚本会自己 go build 出两个临时二进制，把仓库里的 config.json 复制到临时目录
导入一份临时配置库再跑，所以不会污染工作区。需要 PATH 里有 go。

自检需要**独占** config.json 里涉及的全部端口（含管理端口 9080）。若本机已经跑着
一份实例，脚本会直接报错退出 —— 而不是连上那个实例、把它的响应当成自己的来断言。
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# scripts/ 的上一级就是仓库根目录
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if os.name == "nt" else ""
ADMIN = "http://127.0.0.1:9080"

# 认证用例专用的账号。密码写成常量是因为它只存在于这个临时配置里，
# 进程退出即连同临时目录一起被清掉，不是真实凭据。
E2E_ADMIN_USER = "e2e-admin"
E2E_ADMIN_PASSWORD = "e2e-password-9f3a"

# 自检实例的管理凭据。必须有值 —— v0.6.0 起回环不再免认证，
# 所有管理接口都要凭据，包括 /healthz 和 /metrics。
E2E_ADMIN_TOKEN = "e2e-s3cret-token"

# 本机有 http_proxy 时会把 127.0.0.1 也截走（表现为 502），
# 所以自检一律显式关掉代理。
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

passed = []
failed = []


def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print("  [OK]   %s" % name)
    else:
        failed.append("%s :: %s" % (name, detail))
        print("  [FAIL] %s  %s" % (name, detail))


# 管理接口的认证头。在 main() 里根据临时配置填上。
# 用一个模块级 dict 而不是给每个函数加参数：这个脚本里几十处调用都要带它，
# 加参数会把每个调用点都改一遍，噪声远大于收益。
AUTH_HEADERS = {}

# 瞬时连接重置的重试次数。
#
# 实测（Windows / Winsock）偶发：客户端刚发完请求、服务端还在处理，
# 连接就被本机协议栈重置，urllib 抛 ConnectionResetError。
# 有意思的是**同一条请求单独重放一定成功**，服务端日志里连痕迹都没有 ——
# 所以这是测试机上的时序/协议栈现象，不是被测代码的问题。
#
# 但它会以两种方式毁掉整轮自检：
#   1. 未捕获异常直接崩掉脚本，**后面的用例一条都不跑**，
#      表现成「改动把 e2e 弄挂了」，其实只是第 7 节某条 DELETE 撞上了；
#   2. 把它当成失败断言，会让人去查一个不存在的服务端 bug。
# 重试一次能把这两种噪声都消掉，同时**不掩盖真正的连接问题** ——
# 连不通的话重试也会连不通，照样报错。
_TRANSIENT = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


def _open_with_retry(op, req, timeout, attempts=2):
    """执行一次 opener.open，遇到瞬时连接重置就重放。

    只对连接层异常重试：HTTPError（4xx/5xx）是**有效响应**，必须原样返回，
    重试它会把「过期 If-Match -> 409」这类断言变成不确定。
    """
    last = None
    for i in range(attempts):
        try:
            return op(req, timeout=timeout)
        except _TRANSIENT as e:
            last = e
            if i + 1 < attempts:
                print("     （连接被重置，重试一次：%s）" % e)
                time.sleep(0.3)
    raise last


def get(path, accept=None, timeout=8):
    req = urllib.request.Request(ADMIN + path)
    if accept:
        req.add_header("Accept", accept)
    for k, v in AUTH_HEADERS.items():
        req.add_header(k, v)
    try:
        with _open_with_retry(opener.open, req, timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


class _StopRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随跳转，只看跳转本身。

    urllib 默认会自动跟随 302，那样断言到的就是最终页面的 200，
    把「根路径到底有没有重定向」这件事测没了。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


no_redirect = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _StopRedirect()
)


def get_noredirect(path, accept=None, timeout=8):
    req = urllib.request.Request(ADMIN + path)
    if accept:
        req.add_header("Accept", accept)
    for k, v in AUTH_HEADERS.items():
        req.add_header(k, v)
    try:
        with _open_with_retry(no_redirect.open, req, timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def hdr(h, name):
    """HTTP 头大小写不敏感。

    Go 会把 ETag 按 MIME 规范写成 Etag 发出去，直接 h.get('ETag') 拿不到。
    """
    return h.get(name) or h.get(name.lower()) or h.get(name.capitalize())


def post(path, body, method="POST", headers=None):
    data = json.dumps(body).encode()
    req = urllib.request.Request(ADMIN + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    # 认证头先挂，再挂调用方给的 —— 让调用方能显式覆盖（比如测「不带凭据」）
    for k, v in AUTH_HEADERS.items():
        req.add_header(k, v)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _open_with_retry(opener.open, req, 8) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def wait_port(port, timeout=20, proc=None):
    end = time.time() + timeout
    while time.time() < end:
        # 自己起的进程都退出了就别白等 —— 否则会一直等到超时，
        # 然后「端口通」这件事被别人占着的端口满足了，测的是别人的进程。
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.4):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def port_in_use(port):
    try:
        with socket.create_connection(("127.0.0.1", port), 0.3):
            return True
    except OSError:
        return False


def config_listen_ports(cfg):
    """配置里要求监听的端口：default_ports 加上每条路由自己指定的 listen_port。"""
    ports = {int(p) for p in (cfg.get("default_ports") or [])}
    for r in cfg.get("routes") or []:
        lp = int(r.get("listen_port") or 0)
        if lp:
            ports.add(lp)
    return sorted(ports)


def required_ports(cfg, admin_port):
    """自检要独占的端口：测试后端 + 管理端口 + 配置里所有监听端口 + CRUD 用的 8099。

    从临时配置里算出来，而不是写死一份清单 —— 配置改了清单就跟着改，不会漏。
    """
    return sorted({9001, 9002, 9003, 9004, 8099, admin_port} | set(config_listen_ports(cfg)))


def build_binaries(outdir):
    """把反代和测试后端编译到临时目录，用完即弃。"""
    built = {}
    for name, pkg in (("goproxy-test", "."), ("backend-test", "./backend")):
        out = os.path.join(outdir, name + EXE)
        print("  go build -o %s %s" % (out, pkg))
        r = subprocess.run(["go", "build", "-o", out, pkg], cwd=ROOT)
        if r.returncode != 0:
            raise SystemExit("go build %s 失败" % pkg)
        built[name] = out
    return built


def run_auth_section(tmp, bins):
    """认证与会话的端到端验证。

    v0.6.0 起回环不再免认证，所以这里**不再需要**用内部标记头把请求降级成
    「外部请求」—— 本机直连同样要走鉴权。标记头保留着是因为它仍有意义：
    它验证「经代理转发进来的请求」也不会被额外优待。

    为什么仍然单独起一个实例：这个用例要自己控制凭据（知道密码明文才能验证
    「密码错会怎样」），而演示配置里不该有明文密码。单独起一个能精确布置
    各种凭据状态，也不受演示数据影响。

    凭据形态：admin_users（用户名 + bcrypt 哈希，给人登录用）
            + admin_token（Bearer，给脚本用）。两条都验。
    """
    import http.cookiejar

    port_admin = 9081
    port_console = 9084  # 控制台经代理发布出来的端口，见下面 cfg["routes"]
    port_biz = 9082
    # 第二个实例要**独立的库**：它和主实例不是同一份配置，也不该共享
    # （同库双进程是 SQLite 单写者模型下最容易出问题的地方）。
    auth_cfg_path = os.path.join(tmp, "auth-config.json")
    auth_db_path = os.path.join(tmp, "auth-config.db")

    # 用二进制自己算哈希，而不是在这里实现一遍 bcrypt ——
    # 那样测的就不是「服务端能不能校验它自己生成的哈希」了。
    pw_hash = subprocess.run(
        [bins["goproxy-test"], "-hash-password", E2E_ADMIN_PASSWORD],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if not pw_hash:
        check("生成 bcrypt 哈希", False, "goproxy -hash-password 没输出")
        return

    cfg = {
        "admin_addr": "127.0.0.1:%d" % port_admin,
        "admin_token": E2E_ADMIN_TOKEN,
        "admin_users": [{"username": E2E_ADMIN_USER, "password_hash": pw_hash}],
        "access_log": False,
        "default_ports": [],
        # ---- 10.7 用的「把控制台自己发布出去」的路由 ----
        #
        # 直接挂在**这个实例**上，而不是另起一个进程：另起一个就必须再占一个
        # 管理端口，而 wait_port 会因为第二个进程 bind 失败而报「端口没起来」——
        # 第一次就是这么踩的（第二个实例抢 9081 报 EADDRINUSE，整个 10.7 全废）。
        # 同一个进程里发布自己的管理端口，既省事又更贴近用户的实际部署。
        #
        # 为什么这条路由必须在**主实例**里：它把管理端口发布到 port_console，
        # 于是浏览器访问 http://<host>:port_console/_goproxy/ui/ 时，请求由
        # goproxy 自己转发给内部管理端口 —— 这正是那个 bug 的触发条件
        # （Director 改写 Host，Origin 仍是浏览器的公网地址）。
        "routes": [
            {
                "id": "console-via-proxy",
                "name": "把控制台发布出去",
                "listen_port": port_console,
                "path_prefix": "/",
                "target": "http://127.0.0.1:%d" % port_admin,
            }
        ],
    }
    with open(auth_cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    del port_biz

    # 这份 JSON 只是种子，跑起来的是独立那个库（见上面 auth_db_path 的说明）。
    # 导入失败要当场报到，别让后面所有断言撞在 401 上还看不出原因。
    imp = subprocess.run(
        [bins["goproxy-test"], "-c", auth_db_path, "-config-import", auth_cfg_path],
        cwd=ROOT, capture_output=True, text=True,
    )
    if imp.returncode != 0:
        check("认证实例的配置导入", False, (imp.stdout + imp.stderr)[:300])
        return

    if port_in_use(port_admin):
        check("认证实例端口空闲", False, "%d 已被占用" % port_admin)
        return
    if port_in_use(port_console):
        check("控制台发布端口空闲", False, "%d 已被占用" % port_console)
        return

    proc = subprocess.Popen(
        [bins["goproxy-test"], "-c", auth_db_path, "-text-log"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_port(port_admin, 15, proc=proc):
            check("认证实例启动", False, "端口 %d 没起来" % port_admin)
            return

        base_url = "http://127.0.0.1:%d" % port_admin
        # 每个请求都带内部标记头：把「本机回环」降级成「外部请求」，
        # 否则回环免认证会让所有鉴权断言失去意义。
        external = {"X-Goproxy-Internal-Via": "1"}

        # 不带 Cookies 的裸 opener，用来观察「没有凭据」的行为
        bare = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def req(path, method="GET", body=None, headers=None, opener=None):
            data = json.dumps(body).encode() if body is not None else None
            r = urllib.request.Request(base_url + path, data=data, method=method)
            for k, v in external.items():
                r.add_header(k, v)
            if data is not None:
                r.add_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                r.add_header(k, v)
            o = opener or bare
            try:
                with o.open(r, timeout=10) as resp:
                    return resp.status, dict(resp.headers), resp.read()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read()

        # ---- 10.0 回环不再免认证（v0.6.0 的行为变更）----
        # 这里是本机 127.0.0.1 直连、不带任何凭据。旧版本会全部 200。
        # 探针/指标也要凭据 —— 这条是刻意的：它们同样能泄露运行状态。
        for path in ("/_goproxy/routes", "/_goproxy/stats", "/healthz", "/readyz", "/metrics"):
            st, h, b = req(path)
            check("回环无凭据 %s -> 401" % path, st == 401,
                  "实际 %s :: %s" % (st, b[:150]))

        # ---- 10.1 三种凭据路径 ----
        st, h, b = req("/_goproxy/routes", headers={"Authorization": "Bearer wrong"})
        check("错误 Bearer -> 401", st == 401, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = req(
            "/_goproxy/routes",
            headers={"Authorization": "Bearer " + E2E_ADMIN_TOKEN},
        )
        check("正确 Bearer -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        # ---- 10.2 用户名 + 密码登录换取会话 Cookie ----
        # 用带 CookieJar 的 opener，模拟浏览器
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar)
        )

        st, h, b = req(
            "/_goproxy/login",
            method="POST",
            body={"username": E2E_ADMIN_USER, "password": "wrong-password"},
            headers={"Origin": base_url},
            opener=browser,
        )
        check("密码错 -> 401", st == 401, "实际 %s :: %s" % (st, b[:150]))

        # 用户名不存在必须和密码错**完全一样** —— 否则可以拿来枚举账号
        st2, h2, b2 = req(
            "/_goproxy/login",
            method="POST",
            body={"username": "no-such-user", "password": "whatever"},
            headers={"Origin": base_url},
            opener=browser,
        )
        check("用户不存在 -> 401", st2 == 401, "实际 %s :: %s" % (st2, b2[:150]))
        check("  用户不存在与密码错的响应无法区分",
              st == st2 and b == b2,
              "密码错 %s/%s vs 用户不存在 %s/%s" % (st, b[:80], st2, b2[:80]))

        st, h, b = req(
            "/_goproxy/login",
            method="POST",
            body={"username": E2E_ADMIN_USER, "password": E2E_ADMIN_PASSWORD},
            headers={"Origin": base_url},
            opener=browser,
        )
        check("用户名+密码正确 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))
        if st != 200:
            return

        # 登录响应要报出是谁登录了 —— 控制台顶部靠它显示用户名
        try:
            lbody = json.loads(b)
            check("  登录响应带 username", lbody.get("username") == E2E_ADMIN_USER, str(lbody))
            check("  登录响应 via=session", lbody.get("via") == "session", str(lbody))
        except Exception as e:
            check("  登录响应可解析", False, str(e))

        sess_cookies = [c for c in jar if c.name == "goproxy_admin_session"]
        check("登录下发了会话 Cookie", len(sess_cookies) == 1, "实际 %d 个" % len(sess_cookies))
        if sess_cookies:
            c = sess_cookies[0]
            # 浏览器直接读不到 HttpOnly 之外的属性时，属性名会落在 _rest 里
            rest = getattr(c, "_rest", {}) or {}
            check("  会话 Cookie 是 HttpOnly",
                  c.has_nonstandard_attr("HttpOnly") or "HttpOnly" in rest,
                  "属性 %s" % rest)
            check("  会话 Cookie Path 是 /_goproxy/", c.path == "/_goproxy/", "实际 %r" % c.path)

        # ---- 10.3 会话能免令牌访问 ----
        st, h, b = req("/_goproxy/routes", opener=browser)
        check("带会话 Cookie 免令牌 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = req("/_goproxy/session", opener=browser)
        check("GET /session -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))
        if st == 200:
            info = json.loads(b)
            check("  via 报告为 session", info.get("via") == "session", str(info))
            check("  has_session 为真", info.get("has_session") is True, str(info))
            check("  报告登录用户名", info.get("username") == E2E_ADMIN_USER, str(info))

        # 未登录时 /session 必须给 401 + credentials_configured，
        # 前端靠这两个信息决定「显示登录表单」还是「引导去配账号」
        st, h, b = req("/_goproxy/session", opener=bare)
        check("未登录 /session -> 401", st == 401, "实际 %s :: %s" % (st, b[:150]))
        if st == 401:
            try:
                ubody = json.loads(b)
                check("  401 体里带 credentials_configured",
                      ubody.get("credentials_configured") is True, str(ubody))
                check("  401 的 message 不暴露「用户名是否存在」",
                      "用户名" not in ubody.get("message", "") or "或密码" in ubody.get("message", ""),
                      str(ubody.get("message")))
            except Exception as e:
                check("  401 体可解析", False, str(e))

        # ---- 10.4 CSRF：带会话的跨源写请求必须被拒 ----
        st, h, b = req(
            "/_goproxy/config",
            method="PATCH",
            body={"access_log": True},
            headers={"Origin": "http://evil.example"},
            opener=browser,
        )
        check("会话 + 跨源 Origin 写 -> 403", st == 403, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = req(
            "/_goproxy/config",
            method="PATCH",
            body={"access_log": False},
            headers={"Origin": base_url},
            opener=browser,
        )
        check("会话 + 同源 Origin 写 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        # 登录接口也不能被跨站调用（登录 CSRF）
        st, h, b = req(
            "/_goproxy/login",
            method="POST",
            body={"username": E2E_ADMIN_USER, "password": E2E_ADMIN_PASSWORD},
            headers={"Origin": "http://evil.example"},
            opener=bare,
        )
        check("跨源登录 -> 403", st == 403, "实际 %s :: %s" % (st, b[:150]))

        # 但不带 Origin 的脚本请求要能登录（fail-open 的那一半）
        st, h, b = req(
            "/_goproxy/login",
            method="POST",
            body={"username": E2E_ADMIN_USER, "password": E2E_ADMIN_PASSWORD},
        )
        check("无 Origin 的脚本登录 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        # ---- 10.5 登出后会话立即失效 ----
        st, h, b = req("/_goproxy/session", method="DELETE",
                       headers={"Origin": base_url}, opener=browser)
        check("登出 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = req("/_goproxy/routes", opener=browser)
        check("登出后旧会话失效 -> 401", st == 401, "实际 %s :: %s" % (st, b[:150]))

        # ---- 10.6 安全响应头 ----
        st, h, b = req("/_goproxy/routes", headers={"Authorization": "Bearer " + E2E_ADMIN_TOKEN})
        low = {k.lower(): v for k, v in h.items()}
        check("带 X-Content-Type-Options: nosniff",
              low.get("x-content-type-options") == "nosniff", str(low.get("x-content-type-options")))
        check("带 X-Frame-Options: DENY",
              low.get("x-frame-options") == "DENY", str(low.get("x-frame-options")))
        csp = low.get("content-security-policy", "")
        check("接口带 CSP 且不含 unsafe-inline", "unsafe-inline" not in csp, csp[:160])

        st, h, b = req("/_goproxy/ui/")
        low = {k.lower(): v for k, v in h.items()}
        csp = low.get("content-security-policy", "")
        check("控制台带 CSP", bool(csp), str(low))
        check("  控制台 CSP 限制 script-src 为 self",
              "script-src 'self'" in csp, csp[:200])
        # style-src 允许 unsafe-inline 是刻意取舍：React 的 style={{}} 需要它
        check("  控制台仍允许 style 内联（已知取舍）",
              "style-src 'self' 'unsafe-inline'" in csp, csp[:220])

        # ---- 10.7 经代理访问控制台（回归：v0.6.0 的「卡在正在检查管理接口…」） ----
        #
        # 这一段守的 bug：把管理端口用一条路由发布出去（用户实际就是这么部署的，
        # http://<公网IP>:32000/_goproxy/ui/），经代理进来的请求 Host 会被
        # Director 改写成内部地址，而浏览器发的 Origin 是公网地址 —— 如果同源
        # 校验拿 r.Host 去比，登录必然 403 cross_origin_rejected，前端又没处理
        # 非 401 错误，于是永远停在「正在检查管理接口…」。
        #
        # 用的是同一个实例（它的 config 里已经挂了 console-via-proxy 那条路由），
        # 所以这里走的是**真实代理链路**，不是伪造头 —— 伪造的话就测不出
        # 「Director 到底写了什么」，而那个值恰恰是判定的依据。
        if not wait_port(port_console, 10):
            check("控制台发布端口监听", False, "%d 没起来" % port_console)
        else:
            via_url = "http://127.0.0.1:%d" % port_console
            pbare = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def vreq(path, method="GET", body=None, headers=None, opener=None):
                data = json.dumps(body).encode() if body is not None else None
                r = urllib.request.Request(via_url + path, data=data, method=method)
                if data is not None:
                    r.add_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    r.add_header(k, v)
                o = opener or pbare
                try:
                    with o.open(r, timeout=10) as resp:
                        return resp.status, dict(resp.headers), resp.read()
                except urllib.error.HTTPError as e:
                    return e.code, dict(e.headers), e.read()

            # 静态页面经代理要能打开（这是「页面能显示但数据拿不到」的前提）
            st, h, b = vreq("/_goproxy/ui/")
            check("经代理 GET /_goproxy/ui/ -> 200", st == 200, "实际 %s" % st)

            # 未登录时接口应当 401（能看到 credentials_configured）
            st, h, b = vreq("/_goproxy/stats", headers={"Origin": via_url})
            check("经代理未登录 /stats -> 401", st == 401, "实际 %s :: %s" % (st, b[:120]))
            st, h, b = vreq("/_goproxy/session", headers={"Origin": via_url})
            check("经代理未登录 /session -> 401", st == 401, "实际 %s :: %s" % (st, b[:120]))
            try:
                cc = json.loads(b.decode("utf-8")).get("credentials_configured")
            except Exception:  # noqa: BLE001
                cc = None
            check("  经代理 /session 报告 credentials_configured=true", cc is True, str(cc))

            # 核心断言：经代理登录必须成功
            vjar = http.cookiejar.CookieJar()
            vbrowser = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(vjar),
            )
            st, h, b = vreq(
                "/_goproxy/login",
                method="POST",
                body={"username": E2E_ADMIN_USER, "password": E2E_ADMIN_PASSWORD},
                headers={"Origin": via_url, "Sec-Fetch-Site": "same-origin"},
                opener=vbrowser,
            )
            check("经代理登录 -> 200（不再 403 cross_origin_rejected）",
                  st == 200, "实际 %s :: %s" % (st, b[:150]))
            check("  经代理登录下发了会话 Cookie",
                  any("goproxy" in c.name for c in vjar), str([c.name for c in vjar]))

            # 带着会话经代理读 + 写
            st, h, b = vreq("/_goproxy/stats", headers={"Origin": via_url}, opener=vbrowser)
            check("经代理带会话读 /stats -> 200", st == 200, "实际 %s :: %s" % (st, b[:120]))

            st, h, b = vreq(
                "/_goproxy/config",
                method="PATCH",
                body={"access_log": False},
                headers={"Origin": via_url, "Sec-Fetch-Site": "same-origin"},
                opener=vbrowser,
            )
            check("经代理带会话写 /config -> 200（CSRF 校验已正确放宽）",
                  st == 200, "实际 %s :: %s" % (st, b[:150]))

            # 安全边界：放宽必须只对「浏览器真正用的那个源」生效
            for label, origin in (
                ("第三方", "http://evil.example"),
                ("内部管理地址", base_url),
                ("同主机不同端口", "http://127.0.0.1:%d" % (port_console + 1)),
            ):
                st, h, b = vreq(
                    "/_goproxy/config",
                    method="PATCH",
                    body={"access_log": False},
                    headers={"Origin": origin},
                    opener=vbrowser,
                )
                check("经代理 Origin=%s 写 -> 403" % label,
                      st == 403, "实际 %s :: %s" % (st, b[:150]))
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        time.sleep(0.4)
        try:
            proc.kill()
        except Exception:
            pass


def cli_config_io(bins, db_path, export_to=None, import_from=None):
    """调命令行导出一份 / 导入一份配置，返回 CompletedProcess。

    这是**不经过管理接口**改配置的唯一途径，也正是 SelfLockout 护栏给出的
    退路（见 admin_api.go 的 escapeHint）。所以它值得被自检真的跑一遍：
    那条提示要是失效了，用户就只能登机器改数据库了。
    """
    args = [bins["goproxy-test"], "-c", db_path]
    if export_to:
        args += ["-config-export", export_to]
    else:
        args += ["-config-import", import_from]
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)


def run_acl_section(db_path, bins, restart_proxy):
    """三层 IP 名单、命名地址列表库与命中测试的端到端验证。

    v0.7.0 把原来「mode 二选一」的路由级 ACL 换成了三份可以并存的名单：
    全局黑名单（对所有入口生效，含管理端口）→ 路由白名单 → 路由黑名单。
    光看配置列表推不出结果，所以配套做了个只读的命中测试接口。

    v0.8.0 又把「每条路由各写一份名单」换成了「顶层 ip_lists 集中定义、
    路由按名字引用」。引用关系带来了三件必须有断言兜住的新事：
      · 改名必须连带改写所有引用，否则引用会悬空（悬空引用是硬错误）；
      · 还被引用着的名单不许删，要报 409 list_in_use 并点名是哪条路由；
      · 解除引用之后可以删。
    判定结果现在还多带一个「命中的是哪份名单」（decision.list）——
    多份名单并存时，只说规则（10.0.0.0/8）回答不了「我该去哪份名单里删掉它」。

    断言分两类，缺一不可：
      · 判定类 —— 走 /_goproxy/acl/test，能精确到「被哪一层、哪份名单、哪条规则拦下」，
        以及层级顺序（全局优先、白名单优先于黑名单）；
      · 落地类 —— 把名单配到真实配置里再从真实端口打过去，确认 403 真的发生。
    只做前者会漏掉「判定对了但请求管线没接上」；
    只做后者则只能看到 403，看不出是哪一层拦的。

    最后一小节的「全局黑名单把管理端口也封掉」会在收尾时报两个额外的结论：
    命令行导入这条路能用，以及「被自己关在门外」之后靠**重启**能恢复回来。
    """

    # 响应体是 bytes，而错误信息里是中文 —— Python 的 bytes 字面量只允许 ASCII，
    # 所以想断言中文文案时得自己 encode 一次。
    def inbody(text):
        return text.encode("utf-8") in b

    print("\n== 11. 三层 IP 名单与命中测试 ==")

    # 命中测试要求填单个 IP（不是 CIDR）：它要回答「这个具体的来源会怎样」，
    # 收 CIDR 反而会让人以为在配规则。
    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1", "route_id": "svc-acl"})
    check("POST /_goproxy/acl/test -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))
    dec = json.loads(b)["decision"]
    check("命中路由黑名单 -> 拒绝", dec["allowed"] is False, str(dec))
    check("  原因细分为 acl_route_deny", dec.get("reason") == "acl_route_deny", str(dec.get("reason")))
    check("  层名是「黑名单」", dec.get("layer") == "黑名单", str(dec.get("layer")))
    check("  带出命中的是哪份名单", dec.get("list") == "本机演示黑名单", str(dec.get("list")))
    check("  带出命中的规则", dec.get("rule") == "127.0.0.1", str(dec.get("rule")))
    check("  带出条目备注（回答「当初为什么封它」）",
          bool(dec.get("note")), str(dec.get("note")))
    # 给人看的那句话要同时说清「哪份名单」和「哪条规则」——
    # 只说规则的话，多份名单并存时用户不知道该去改哪一份。
    check("  文案里点明名单名与规则",
          "本机演示黑名单" in dec.get("message", "") and "127.0.0.1" in dec.get("message", ""),
          str(dec.get("message")))

    steps = dec.get("steps") or []
    check("  回放全部三层判定", len(steps) == 3, str(steps))
    check("  顺序固定：全局黑名单 → 白名单 → 黑名单",
          [s.get("layer") for s in steps] == ["全局黑名单", "白名单", "黑名单"],
          str([s.get("layer") for s in steps]))
    check("  全局黑名单未配置时不参与拦截",
          steps and steps[0].get("configured") is False, str(steps[:1]))
    check("  命中的那一层带出名单名（供界面直接定位）",
          steps and steps[2].get("list") == "本机演示黑名单", str(steps[-1:]))

    # 没配任何名单的路由必须放行 —— 「没配」和「配了空白名单」是两件事，
    # 后者是配置错误（validate 会拒），前者是完全不限制。
    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1", "route_id": "svc-a"})
    dec = json.loads(b)["decision"]
    check("没配名单的路由 -> 放行", dec["allowed"] is True, str(dec))

    # 不指定路由：只判全局那一层。
    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1"})
    dec = json.loads(b)["decision"]
    check("不指定路由时只判全局层 -> 放行", dec["allowed"] is True, str(dec))
    check("  路由级两层标注为未配置",
          [s.get("configured") for s in dec.get("steps") or []] == [False, False, False],
          str(dec.get("steps")))

    # GET 查询串形式：给 curl 和运维脚本用，和 POST 必须解析到同一套逻辑。
    st, h, b = get("/_goproxy/acl/test?ip=127.0.0.1&route_id=svc-acl")
    check("GET 查询串形式同样可用",
          st == 200 and json.loads(b)["decision"]["allowed"] is False, "实际 %s :: %s" % (st, b[:200]))

    st, h, b = post("/_goproxy/acl/test", {"ip": "no-such-ip"})
    check("非法 IP -> 400 invalid_ip", st == 400 and b"invalid_ip" in b, "实际 %s :: %s" % (st, b[:150]))

    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1", "route_id": "no-such-route"})
    check("未知 route_id -> 404", st == 404, "实际 %s :: %s" % (st, b[:150]))

    # ---- 自锁护栏 ----
    # 全局黑名单同样作用于管理端口，所以「覆盖自己来源」的一次保存会把控制台关在门外。
    # 后端必须在写路径上拦住它，而且**库里的配置不能被动过** ——
    # 否则用户以为没保存成功，实际已经写进去了，下一个请求就进不来。
    st, h, b = post("/_goproxy/config", {"global_ip_deny": ["127.0.0.1"]}, method="PATCH")
    check("全局黑名单覆盖自己来源 -> 409 拒绝保存", st == 409, "实际 %s :: %s" % (st, b[:220]))
    check("  错误码是 self_lockout", b"self_lockout" in b, b[:220])
    st, _h, b = get("/_goproxy/config")
    check("  被拒后库里的配置未被改动",
          (json.loads(b).get("global_ip_deny") or []) == [],
          str(json.loads(b).get("global_ip_deny")))

    # ---- 正常写入：两种条目形态都要能存能读 ----
    st, h, b = post(
        "/_goproxy/config",
        {
            "global_ip_deny": [
                {"cidr": "203.0.113.66", "note": "e2e 全局封禁"},
                "203.0.113.99",
                {"cidr": "198.51.100.0/24", "note": "e2e 封整段"},
            ]
        },
        method="PATCH",
    )
    check("写入全局黑名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))

    st, _h, b = get("/_goproxy/config")
    gd = json.loads(b).get("global_ip_deny")
    check("回显三条", isinstance(gd, list) and len(gd) == 3, str(gd))
    check("  带备注的条目回写成对象", isinstance(gd[0], dict) and gd[0].get("note") == "e2e 全局封禁", str(gd[:1]))
    # 这条是刻意的取舍：没有备注就走字符串简写，否则一次控制台保存会把
    # 每条规则都撑成 {"cidr": …}，导出来的配置就不再是给人读的。
    check("  没备注的条目回写成字符串简写", gd[1] == "203.0.113.99", str(gd[1:2]))

    # ---- 命名地址列表库：新建 / 校验 / 改名 / 删除 ----
    #
    # v0.8.0 起名单不再内联写在路由里，而是集中定义在顶层 ip_lists、路由按名字引用。
    # 引用关系带来三件必须验的事：改名要连带改写引用、被引用的名单不许删、
    # 解除引用之后可以删。这一节就是围着这三件事建的。
    st, _h, b = get("/_goproxy/config")
    base_lists = json.loads(b).get("ip_lists") or []
    check("配置里能读到 ip_lists 名单库",
          isinstance(base_lists, list) and len(base_lists) >= 1, str(base_lists))

    built = base_lists + [
        {"name": "e2e 白名单A", "kind": "allow",
         "rules": [{"cidr": "203.0.113.66", "note": "e2e 白名单"}]},
        {"name": "e2e 内网段", "kind": "allow", "rules": ["10.0.0.0/8"]},
        {"name": "e2e 内部例外", "kind": "deny",
         "rules": [{"cidr": "10.0.0.5", "note": "e2e 内部例外"}]},
    ]
    st, _h, b = post("/_goproxy/config", {"ip_lists": built}, method="PATCH")
    check("新建三份名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:300]))

    st, _h, b = get("/_goproxy/config")
    got = {d["name"]: d for d in (json.loads(b).get("ip_lists") or [])}
    check("  三份都存进去了",
          all(n in got for n in ("e2e 白名单A", "e2e 内网段", "e2e 内部例外")),
          str(sorted(got)))
    # 角色（白/黑）记在名单自己身上，路由那边只管引用。
    # 若把角色写在引用点上，同一份名单被两条路由引用就可能一处当白、一处当黑，
    # 「这份名单到底什么意思」就没有唯一答案了。
    check("  角色（allow/deny）记在名单上，不在引用点上",
          got.get("e2e 白名单A", {}).get("kind") == "allow"
          and got.get("e2e 内部例外", {}).get("kind") == "deny",
          str(sorted((n, d.get("kind")) for n, d in got.items())))

    # 空的黑名单只是什么都不禁，放行。
    st, _h, b = post("/_goproxy/config",
                     {"ip_lists": built + [{"name": "e2e 空黑名单", "kind": "deny", "rules": []}]},
                     method="PATCH")
    check("空的黑名单 -> 允许保存（它只是什么都不禁）",
          st == 200, "实际 %s :: %s" % (st, b[:250]))

    # 空的白名单不行：它一旦被引用就只剩「只允许名单内的地址」一个含义，
    # 结果是把引用它的路由整个封死。这是配置事故，不是意图，必须在写盘前拦下。
    st, _h, b = post("/_goproxy/config",
                     {"ip_lists": built + [{"name": "e2e 空白名单", "kind": "allow", "rules": []}]},
                     method="PATCH")
    check("空的白名单 -> 400 拒绝", st == 400 and b"invalid_config" in b,
          "实际 %s :: %s" % (st, b[:250]))
    st, _h, b = get("/_goproxy/config")
    check("  被拒后名单库里没有它（没落库）",
          "e2e 空白名单" not in {d["name"] for d in (json.loads(b).get("ip_lists") or [])},
          str(json.loads(b).get("ip_lists")))

    # 把上面那份临时空黑名单收掉，后面改名/删除用到的名单集合才是确定的。
    st, _h, b = post("/_goproxy/config", {"ip_lists": built}, method="PATCH")
    check("  撤回临时名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:250]))

    # 让 svc-a 引用「e2e 白名单A」，于是 203.0.113.66 同时落在
    # 「引用的白名单内」和「全局黑名单里」—— 正好验层级顺序。
    st, h, b = get("/_goproxy/routes")
    etag = hdr(h, "ETag")
    st, h, b = post("/_goproxy/routes/svc-a", {"acl": {"lists": ["e2e 白名单A"]}},
                    method="PATCH", headers={"If-Match": etag})
    check("路由按名字引用一份名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:250]))

    # 引用不存在的名单必须被拦下 —— 把它当成「不限制来源」就是一次无声的放行。
    st, h, b = get("/_goproxy/routes")
    etag = hdr(h, "ETag")
    st, h, b = post("/_goproxy/routes/svc-a", {"acl": {"lists": ["e2e 查无此单"]}},
                    method="PATCH", headers={"If-Match": etag})
    check("引用不存在的名单 -> 400 拒绝",
          st == 400 and inbody("查无此单") and inbody("e2e"),
          "实际 %s :: %s" % (st, b[:300]))

    st, h, b = post("/_goproxy/acl/test", {"ip": "203.0.113.66", "route_id": "svc-a"})
    dec = json.loads(b)["decision"]
    check("全局黑名单命中 -> 拒绝（先于白名单）", dec["allowed"] is False, str(dec))
    check("  原因是 acl_global_deny，不是白名单没命中",
          dec.get("reason") == "acl_global_deny", str(dec.get("reason")))
    check("  层名是「全局黑名单」", dec.get("layer") == "全局黑名单", str(dec.get("layer")))
    # 全局黑名单是独立的一份、没有名字，所以这一层命中时不该报出名单名。
    # 若这里冒出一个名字，说明判定把全局层和路由层的数据混在一起了。
    check("  全局层不报「哪份名单」（它没有名字）",
          not dec.get("list"), str(dec.get("list")))

    # 反证：把同一个地址从全局黑名单里摘掉，它在同一条路由上就放行了。
    # 没有这一步，上一条可能只是「白名单没生效」造成的假象。
    st, h, b = post(
        "/_goproxy/config",
        {"global_ip_deny": ["203.0.113.99", {"cidr": "198.51.100.0/24", "note": "e2e 封整段"}]},
        method="PATCH",
    )
    check("从全局黑名单移除该地址 -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))
    st, h, b = post("/_goproxy/acl/test", {"ip": "203.0.113.66", "route_id": "svc-a"})
    check("不在全局黑名单、但在白名单内 -> 放行",
          json.loads(b)["decision"]["allowed"] is True, b[:200])

    # 白名单一旦被引用，名单外的地址就该被拒 —— 这是「收紧范围」而不是「额外放行」。
    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1", "route_id": "svc-a"})
    dec = json.loads(b)["decision"]
    check("白名单里的地址之外 -> 拒绝", dec["allowed"] is False, str(dec))
    check("  原因是 acl_route_allow_miss", dec.get("reason") == "acl_route_allow_miss", str(dec.get("reason")))
    check("  层名是「白名单」", dec.get("layer") == "白名单", str(dec.get("layer")))
    # 「整层没命中」不该说成是某一份名单拦的 —— 那一层可能有好几份名单，
    # 点其中一份的名会冤枉它。
    check("  整层未命中时不报具体名单", not dec.get("list"), str(dec.get("list")))
    # 但 steps 里要说清这一层有哪些名单、共几条规则，否则用户只看到「未命中」，
    # 不知道该往哪份名单里加地址。
    allow_step = [s for s in dec.get("steps") or [] if s.get("layer") == "白名单"]
    check("  steps 里白名单层列明引用了哪几份名单",
          allow_step and "「e2e 白名单A」" in allow_step[0].get("detail", ""),
          str(allow_step))

    # ---- 改名：必须连带改写引用，而且是一次原子写 ----
    #
    # 若拆成「先删旧名、再加新名」两步，中间态里所有引用都悬空，
    # 而悬空引用是硬错误 —— 保存根本提交不下去，用户会碰到一个无法完成的操作。
    renamed_to = "e2e 白名单A（改名后）"
    renamed = [dict(d, name=renamed_to) if d["name"] == "e2e 白名单A" else d for d in built]
    st, _h, b = post("/_goproxy/config",
                     {"ip_lists": renamed, "ip_list_renames": {"e2e 白名单A": renamed_to}},
                     method="PATCH")
    check("改名（一次请求里连带改写引用）-> 200", st == 200, "实际 %s :: %s" % (st, b[:300]))

    st, _h, b = get("/_goproxy/routes")
    refs = None
    for r in json.loads(b) or []:
        if r.get("id") == "svc-a":
            refs = (r.get("acl") or {}).get("lists")
    check("  路由里的引用被一起改写成了新名字", refs == [renamed_to], str(refs))

    # 引用改了名，判定行为必须一模一样 —— 否则「改名成功但生效的名单换了」
    # 是一类只能靠行为对比才发现的错误。
    st, h, b = post("/_goproxy/acl/test", {"ip": "203.0.113.66", "route_id": "svc-a"})
    check("  改名后白名单仍在起作用（名单内 -> 放行）",
          json.loads(b)["decision"]["allowed"] is True, b[:200])
    st, h, b = post("/_goproxy/acl/test", {"ip": "127.0.0.1", "route_id": "svc-a"})
    check("  改名后白名单仍然生效（名单外 -> 拒绝）",
          json.loads(b)["decision"].get("reason") == "acl_route_allow_miss", b[:200])

    # ---- 删除：还被引用着的名单不许删 ----
    #
    # 不拦的话，删除会一路走到 validate 才报「某条路由引用了不存在的名单」，
    # 用户看到的是「引用写错了」，而真正发生的是一次删除动作 ——
    # 两者的下一步操作完全不同（一个去改引用，一个去解除引用）。
    st, _h, b = post("/_goproxy/config",
                     {"ip_lists": [d for d in renamed if d["name"] != renamed_to]},
                     method="PATCH")
    check("删掉还被引用的名单 -> 409 list_in_use",
          st == 409 and b"list_in_use" in b, "实际 %s :: %s" % (st, b[:300]))
    check("  报错点名了在用的路由（告诉用户去哪解除引用）", b"svc-a" in b, b[:300])
    st, _h, b = get("/_goproxy/config")
    check("  被拒后名单还在（没被写坏）",
          renamed_to in {d["name"] for d in (json.loads(b).get("ip_lists") or [])},
          str(json.loads(b).get("ip_lists")))

    # 两份名单并存：白名单 10.0.0.0/8 里单独剔掉 10.0.0.5。
    # 这正是旧版 mode 二选一表达不出来的配置 —— 现在就是引用两份名单，
    # 各自独立维护，一条路由同时用。
    st, h, b = get("/_goproxy/routes")
    etag = hdr(h, "ETag")
    st, h, b = post("/_goproxy/routes/svc-a",
                    {"acl": {"lists": ["e2e 内网段", "e2e 内部例外"]}},
                    method="PATCH", headers={"If-Match": etag})
    check("路由同时引用白名单 + 黑名单两份 -> 200", st == 200, "实际 %s :: %s" % (st, b[:250]))

    st, h, b = post("/_goproxy/acl/test", {"ip": "10.0.0.5", "route_id": "svc-a"})
    dec = json.loads(b)["decision"]
    check("白名单内的地址仍可被黑名单剔掉",
          dec["allowed"] is False and dec.get("reason") == "acl_route_deny", str(dec))
    check("  报出的是内容里的那份黑名单（多份名单时这一点必须准确）",
          dec.get("list") == "e2e 内部例外", str(dec.get("list")))
    check("  备注来自黑名单那条", dec.get("note") == "e2e 内部例外", str(dec.get("note")))
    check("  文案里点明了是哪份名单拦的",
          "e2e 内部例外" in dec.get("message", ""), str(dec.get("message")))

    st, h, b = post("/_goproxy/acl/test", {"ip": "10.0.0.9", "route_id": "svc-a"})
    check("白名单内且未被黑名单命中 -> 放行",
          json.loads(b)["decision"]["allowed"] is True, b[:200])

    # 解除引用之后就能删了。这是上面那条 409 的反证：没有这一步，
    # 409 有可能只是「删除功能整个坏掉了」的另一种表现。
    st, _h, b = post("/_goproxy/config",
                     {"ip_lists": [d for d in renamed if d["name"] != renamed_to]},
                     method="PATCH")
    check("解除引用后删除同一份名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:250]))
    st, _h, b = get("/_goproxy/config")
    check("  名单库里已经没有它",
          renamed_to not in {d["name"] for d in (json.loads(b).get("ip_lists") or [])},
          str(sorted(d["name"] for d in (json.loads(b).get("ip_lists") or []))))

    # ---- 落地验证：判定对了，真实请求也要真的被拦 ----
    #
    # 注意这里不能「PATCH 完立刻请求、一次定胜负」：写配置到新名单生效之间
    # 隔着一次 mtime 轮询，中间那一小段请求打的还是旧路由表（200），
    # 看起来就像断言写错了。所以统一用轮询等它生效。
    def wait_port_status(url, want, timeout=8, marker=None):
        """等某个地址真的返回 want；给了 marker 还要响应体里出现它。

        两个都必须等，理由不同：
          · 写配置到新名单生效之间隔着一次 1 秒的 mtime 轮询，中间那段请求
            打的还是旧路由表 —— 一次定胜负会拿到旧结果，看着像断言写错了。
          · 只看状态码会「假通过」：8081 本来就可能因为别的原因返回 403，
            于是断言在名单还没生效时就绿了。marker 把「因为正确的原因 403」
            也一起钉住。
        """
        end = time.time() + timeout
        last, body = None, b""
        while time.time() < end:
            try:
                with opener.open(url, timeout=3) as r:
                    body = r.read()
                    last = r.status
            except urllib.error.HTTPError as e:
                last, body = e.code, e.read()
            except Exception:
                last = None
            if last == want and (marker is None or marker in body):
                return last, body
            time.sleep(0.3)
        return last, body

    # (a) 8081 上的 svc-a 引用着「e2e 内网段」（只允许 10.0.0.0/8），
    #     而请求来自 127.0.0.1 —— 白名单没命中。
    st, body = wait_port_status("http://127.0.0.1:8081/whitelist-miss", 403,
                                marker=b"acl_route_allow_miss")
    check("业务端口白名单未命中 -> 403", st == 403, "实际 %s" % st)
    check("  响应体带 reason=acl_route_allow_miss", b"acl_route_allow_miss" in body, body[:150])

    # (b) 8088 挂的是 svc-acl，它引用着「本机演示黑名单」（deny 127.0.0.1），
    #     同一个来源应当 403。这一条同时证明「引用式名单真的接到了请求管线上」——
    #     上一条只说明白名单层生效了，管不了黑名单这一层。
    st, body = wait_port_status("http://127.0.0.1:8088/real-deny", 403,
                                marker=b"acl_route_deny")
    check("业务端口命中引用式黑名单 -> 403", st == 403, "实际 %s" % st)
    check("  响应体带 reason=acl_route_deny", b"acl_route_deny" in body, body[:150])
    # 响应体只到「哪一层」，不带规则和名单名。
    # 这是刻意的：告诉对方「你踩到哪条线了」等于送它一份探测地图。
    # 具体规则与名单名只进访问日志和命中测试（运维看得到，对面学不到）。
    check("  带层名",
          "黑名单".encode("utf-8") in body, body[:250])
    check("  但不泄漏命中的规则与名单名",
          "本机演示黑名单".encode("utf-8") not in body and b"127.0.0.1" not in body,
          body[:250])

    # (c) 对照组：8000 只命中兜底路由，那条路由没配任何名单，必须照常 200。
    #     少了这一条，上面的 403 有可能只是「端口整个不通」造成的。
    st, body = wait_port_status("http://127.0.0.1:8000/no-acl-here", 200)
    check("没配名单的端口照常 200（不是全盘拒绝）", st == 200, "实际 %s" % st)

    time.sleep(1.2)
    st, h, b = get("/_goproxy/logs?limit=200")
    reasons = {e["blocked"] for e in (json.loads(b).get("entries") or []) if e.get("blocked")}
    check("访问日志里出现 acl_route_deny", "acl_route_deny" in reasons, str(sorted(reasons)))

    # ---- 全局黑名单真的作用于所有入口（含管理端口）----
    #
    # 这件事**没法通过 PATCH 验证** —— 上面刚确认过自锁护栏会拦下它。
    # 唯一的途径是命令行导入（护栏刻意留的退路）。
    #
    # v0.9.0 之前这里是「直接写盘，等 1 秒的 mtime 轮询捡起来」。配置源换成 SQLite
    # 之后那条路不存在了：配置只认库，磁盘上那份 JSON 早已不再被读取。退路变成
    #   -config-export 导出 → 改 → -config-import 导回 → 生效
    # 这段就按这条退路完整走一遍，包括最后那一步**重启**。
    #
    # 顺序上有个关键细节：导入只写库，不碰进程里已经加载的路由表，所以紧接着那次
    # reload 还进得来（此刻生效的还是**旧**配置，它允许 127.0.0.1）。一旦新配置
    # 生效，管理端口也被封了 —— 再想靠 HTTP 恢复就没路了，只能重启进程。
    # 这也正是恢复那一段必须用 restart_proxy 而不是再调一次 reload 的原因。
    backup = os.path.join(os.path.dirname(db_path), "global-deny-backup.json")
    hot = os.path.join(os.path.dirname(db_path), "global-deny-hot.json")

    r = cli_config_io(bins, db_path, export_to=backup)
    check("命令行导出配置 -> 成功", r.returncode == 0, (r.stdout + r.stderr)[:200])
    before_gd = json.load(open(backup, encoding="utf-8")).get("global_ip_deny") or []

    try:
        live = json.load(open(backup, encoding="utf-8"))
        live["global_ip_deny"] = ["127.0.0.1/32"]
        with open(hot, "w", encoding="utf-8") as f:
            json.dump(live, f, ensure_ascii=False, indent=2)

        r = cli_config_io(bins, db_path, import_from=hot)
        check("命令行导入「封掉本机」的配置 -> 成功", r.returncode == 0, (r.stdout + r.stderr)[:200])

        # 导入只写库。让它生效要么重启，要么调一次 reload —— 这里走 reload，
        # 顺带验证「导入之后不重启也能生效」这条（README 里就是这么写的）。
        st, h, b = post("/_goproxy/reload", None)
        check("导入后调 reload -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        # 等**管理端口**自己被封。它同时是两个信号：
        #   · 导入 + reload 这条路真的把新配置吃进去了
        #   · 全局黑名单确实作用于管理端口，而不只是业务端口
        admin_body, st = None, None
        deadline = time.time() + 15
        while time.time() < deadline:
            st, _h, b = get("/_goproxy/config")
            if st == 403:
                admin_body = b
                break
            time.sleep(0.3)
        check("全局黑名单生效：管理端口 403", admin_body is not None,
              "等了 15s 管理端口仍是 %s" % st)
        if admin_body is not None:
            check("  管理端口的 403 带 acl_global_deny",
                  b"acl_global_deny" in admin_body, admin_body[:150])

        # 业务端口同一份名单同样生效。故意打 8081：它此刻配着
        # 「只允许 10.0.0.0/8」的白名单，而返回的原因必须是 acl_global_deny ——
        # 这一条顺带证明了「全局黑名单排在路由匹配之前」，连路由级名单都不看一眼。
        st, body = wait_port_status("http://127.0.0.1:8081/global-deny", 403,
                                    marker=b"acl_global_deny", timeout=10)
        check("业务端口同样 403，且原因来自全局层",
              b"acl_global_deny" in body, body[:180])
    finally:
        # 恢复。**不能只 reload** —— 此刻生效的配置把 127.0.0.1 一起封了，
        # 连 POST /_goproxy/reload 都进不来（下面第一次 get 就会是 403）。
        # 先把备份导回库，再重启进程；重启读的正是刚导回去的那份。
        #
        # 这一整段就是「被自己关在门外」之后的操作手册，所以它必须真的能跑通 ——
        # 不然我们给用户的那句提示只是一句没有验证过的话。
        r = cli_config_io(bins, db_path, import_from=backup)
        check("恢复：把备份配置导回库", r.returncode == 0, (r.stdout + r.stderr)[:200])
        check("恢复：重启进程", restart_proxy(), "重启后管理端口没起来")

    # 重启之后管理端口要能正常应答 —— 「被自己封住 → 导回 + 重启」这条退路的
    # 可验证形式。
    st, b = None, b""
    end = time.time() + 15
    while time.time() < end:
        st, _h, b = get("/_goproxy/config")
        if st == 200:
            break
        time.sleep(0.4)
    check("重启后管理端口恢复 200", st == 200, "等了 15s 仍是 %s" % st)
    gd = (json.loads(b).get("global_ip_deny") or []) if st == 200 else None
    check("  恢复后的名单回到导入前那一份（没被临时规则污染）",
          gd == before_gd, "%s != %s" % (gd, before_gd))

    # 清干净：把全局黑名单显式清空，验证「传空数组 = 清空」这条语义。
    # （这一步在重启之后做，走的是普通管理接口 —— 进程已经恢复成允许本机了。）
    st, h, b = post("/_goproxy/config", {"global_ip_deny": []}, method="PATCH")
    check("清空全局黑名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))
    st, _h, b = get("/_goproxy/config")
    check("  global_ip_deny 已清空",
          (json.loads(b).get("global_ip_deny") or []) == [],
          str(json.loads(b).get("global_ip_deny")))

    # 收尾：把 svc-a 的名单清掉，别把临时配置改得和原样差太远。
    st, h, b = get("/_goproxy/routes")
    etag = hdr(h, "ETag")
    st, h, b = post("/_goproxy/routes/svc-a", {"acl": None}, method="PATCH",
                    headers={"If-Match": etag})
    check("清掉临时路由的名单 -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))


def main():
    if shutil.which("go") is None:
        print("PATH 里找不到 go，无法编译测试二进制")
        return 1

    tmp = tempfile.mkdtemp(prefix="goproxy-e2e-")
    procs = []

    def spawn(args):
        p = subprocess.Popen(
            args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(p)
        return p

    try:
        print("== 编译测试二进制 ==")
        bins = build_binaries(tmp)

        # v0.9.0 起配置的真源是 SQLite 数据库，config.json 只是**种子**：
        # 库为空时导入一次，之后它就不再被读取。
        #
        # 所以这里不再把 config.json 当配置跑，而是复制一份到临时目录、
        # 显式导入到临时库里。自检里的 CRUD 改的是那个库，仓库里的
        # 演示配置照样不会被改脏 —— 和以前的目标一样，换了个落点。
        #
        # 走显式的 -config-import 而不是靠启动时的自动导入：导入失败时
        # 要能在这里把报错打出来，而不是等到「管理端口没起来」再回头猜。
        seed_path = os.path.join(tmp, "config.json")
        shutil.copyfile(os.path.join(ROOT, "config.json"), seed_path)
        db_path = os.path.join(tmp, "goproxy.db")

        # 管理地址以种子配置为准，别写死 9080。
        global ADMIN, AUTH_HEADERS
        cfg_data = json.load(open(seed_path, encoding="utf-8"))
        admin_addr = cfg_data.get("admin_addr") or "127.0.0.1:9080"
        ADMIN = "http://" + admin_addr
        admin_port = int(admin_addr.rsplit(":", 1)[1])

        # v0.6.0 起管理接口一律要凭据（回环也不例外），所以种子配置里必须带一个
        # admin_token，否则后面的每个断言都会撞在 401 上。
        #
        # 为什么用 admin_token 而不是 admin_users：这些用例是「脚本访问」，
        # 走 Bearer 最直接，不用维持一个 CookieJar。登录本身由第 10 节专门测。
        #
        # 注意这一步必须在**导入之前**做：导入之后磁盘上那份 JSON 就再也
        # 不被读取了，改它只是改了个没人看的文件。
        cfg_data["admin_token"] = E2E_ADMIN_TOKEN
        with open(seed_path, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f, ensure_ascii=False, indent=2)

        seed = subprocess.run(
            [bins["goproxy-test"], "-c", db_path, "-config-import", seed_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        if seed.returncode != 0:
            print("导入种子配置失败：\n%s\n%s" % (seed.stdout[-2000:], seed.stderr[-2000:]))
            return 1
        AUTH_HEADERS = {"Authorization": "Bearer " + E2E_ADMIN_TOKEN}

        # 端口预检。这一步不能省：如果 9080 上已经跑着一个实例（本机开发时很常见），
        # 自检自己起的那份会因端口被占而退出，而 wait_port 却立刻成功，
        # 于是所有断言都打在**别人那个进程**上 —— 全绿，但什么也没验证到。
        # （以前这一条还会把仓库里的 config.json 改脏；现在配置落在临时库里，
        #   但「测的必须是自己的进程」这个理由没有任何变化。）
        busy = [p for p in required_ports(cfg_data, admin_port) if port_in_use(p)]
        if busy:
            print("以下端口已被占用: %s" % ", ".join(str(p) for p in busy))
            print("端到端自检需要独占这些端口，先把占用它们的进程停掉：")
            print("  Windows:  taskkill /F /IM goproxy-demo.exe /IM backend-demo.exe")
            print("            taskkill /F /IM goproxy.exe /IM goproxy-test.exe")
            print("  Linux:    pkill -f goproxy")
            return 1

        print("== 启动测试后端 ==")
        for port, name in ((9001, "svcA"), (9002, "svcB"), (9003, "svcC"), (9004, "svcD")):
            spawn([bins["backend-test"], "-port", str(port), "-name", name])
        for port in (9001, 9002, 9003, 9004):
            if not wait_port(port):
                print("后端 %d 没起来" % port)
                return 1

        print("== 启动 goproxy ==")
        proxy = spawn([bins["goproxy-test"], "-c", db_path, "-text-log"])
        if not wait_port(admin_port, proc=proxy):
            print(
                "管理端口 %d 没起来（进程存活=%s，退出码=%s）"
                % (admin_port, proxy.poll() is None, proxy.returncode)
            )
            return 1

        def restart_proxy():
            """重启反代进程，返回 True 表示新进程的管理端口起来了。

            只有一处需要它：第 11 节刻意把管理端口自己也封掉，而那时进程里
            生效的配置会拒绝**所有**来源 —— 连 POST /_goproxy/reload 都进不去。
            「改库 + 重启」正是给那个护栏留的退路，所以这里得能真的走一遍，
            否则第 11 节的结论就只停在纸面上。
            """
            nonlocal proxy
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if proxy in procs:
                procs.remove(proxy)
            proxy = spawn([bins["goproxy-test"], "-c", db_path, "-text-log"])
            return wait_port(admin_port, 20, proc=proxy)

        # 配置里写着要监听的端口必须真的起来，少了就是监听失败。
        for port in config_listen_ports(cfg_data):
            if not wait_port(port, 10):
                print("业务端口 %d 没起来" % port)

        print("\n== 1. 控制台静态资源 ==")
        st, h, body = get("/_goproxy/ui/")
        check("GET /_goproxy/ui/ -> 200", st == 200, "实际 %s" % st)
        check("Content-Type 是 html", "text/html" in h.get("Content-Type", ""), h.get("Content-Type"))
        check("返回的是控制台入口页", b'id="root"' in body, body[:120])
        check("资源引用带 base 前缀", b"/_goproxy/ui/assets/" in body)

        import re

        assets = re.findall(rb"/_goproxy/ui/(assets/[A-Za-z0-9._-]+)", body)
        check("index.html 引用了 assets", len(assets) > 0, str(assets))

        for a in assets:
            st, h, b = get("/_goproxy/ui/" + a.decode())
            check("静态资源 %s -> 200" % a.decode(), st == 200, "实际 %s" % st)
            check("  assets 长缓存", "immutable" in h.get("Cache-Control", ""), h.get("Cache-Control"))

        st, h, b = get("/_goproxy/ui/index.html")
        check("index.html 不长缓存", "immutable" not in h.get("Cache-Control", ""), h.get("Cache-Control"))

        st, h, b = get("/_goproxy/ui/favicon.svg")
        check("favicon -> 200", st == 200, "实际 %s" % st)

        st, h, b = get("/_goproxy/ui/routes/deep/link")
        check("SPA 深链接回落 -> 200", st == 200 and b'id="root"' in b, "实际 %s" % st)

        print("\n== 2. 根路径与「找控制台」的地址分流 ==")

        # 这些都是人在地址栏里会敲的地址：根路径、只写了 /_goproxy 前缀的、
        # 顺手敲成 /index.html 的。浏览器来一律进控制台 —— 以前只有精确的 /
        # 会重定向，其余全落进纯文本接口清单，看着像「控制台没生效」。
        for p in ("/", "/_goproxy", "/_goproxy/", "/index.html", "/dashboard"):
            st, h, b = get_noredirect(p, accept="text/html,application/xhtml+xml")
            check(
                "浏览器访问 %s 跳转到控制台" % p,
                st in (301, 302, 307) and h.get("Location") == "/_goproxy/ui/",
                "实际 %s -> %s" % (st, h.get("Location")),
            )

        # 同一批地址换成 curl（不带 text/html）：落地页给纯文本清单，
        # 其余老实 404，不把拼错的地址伪装成成功。
        for p in ("/", "/_goproxy", "/_goproxy/"):
            st, h, b = get(p)
            check("curl 访问 %s 拿到 200" % p, st == 200, "实际 %s" % st)
            check("  是纯文本清单", "text/plain" in h.get("Content-Type", ""), h.get("Content-Type"))
            check("  清单里提示了控制台地址", b"/_goproxy/ui/" in b)
        for p in ("/index.html", "/dashboard"):
            st, h, b = get(p)
            check("curl 访问 %s -> 404" % p, st == 404, "实际 %s" % st)

        # 反向约束：接口不能因为带了 text/html 就被重定向，
        # 否则浏览器里直接打开 /_goproxy/routes 会拿不到 JSON。
        st, h, b = get_noredirect("/_goproxy/routes", accept="text/html,application/xhtml+xml")
        check("接口对浏览器请求不重定向", st == 200, "实际 %s" % st)
        check("  仍返回 JSON", "application/json" in h.get("Content-Type", ""), h.get("Content-Type"))

        # 拼错的接口地址要响亮地 404
        st, h, b = get("/_goproxy/statss")
        check("拼错的接口路径 -> 404", st == 404, "实际 %s" % st)

        print("\n== 3. 制造真实流量 ==")
        traffic = [
            (8000, "/"), (8081, "/hello"), (8081, "/x"),
            (8083, "/api/orders"), (8083, "/other"),
            (8088, "/blocked-by-acl"),
            (8089, "/will-fail"), (8089, "/will-fail"),
            (8089, "/will-fail"), (8089, "/will-fail"),
        ]
        for port, path in traffic:
            try:
                with opener.open("http://127.0.0.1:%d%s" % (port, path), timeout=4) as r:
                    r.read()
            except urllib.error.HTTPError:
                pass
            except Exception as e:
                print("    端口 %d 请求异常：%s" % (port, e))

        # 8082 配的是 rps=10 burst=20，必须一次性打满桶才会出 429。
        # 只发 5 个请求是测不出限流的 —— 桶都没见底。
        rl_codes = []
        for _ in range(80):
            try:
                with opener.open("http://127.0.0.1:8082/burst", timeout=3) as r:
                    rl_codes.append(r.status)
            except urllib.error.HTTPError as e:
                rl_codes.append(e.code)
            except Exception:
                pass
        check("限流：突发流量出现 429", 429 in rl_codes, "状态码分布 %s" % sorted(set(rl_codes)))
        check("限流：正常请求也能通过", 200 in rl_codes, "状态码分布 %s" % sorted(set(rl_codes)))

        # Basic 认证：先拿 401，再带凭据拿 200
        try:
            with opener.open("http://127.0.0.1:8086/", timeout=4) as r:
                r.read()
            print("    8086 未认证却通过了（异常）")
        except urllib.error.HTTPError as e:
            check("Basic 认证：无凭据 401", e.code == 401, "实际 %s" % e.code)

        import base64

        tok = base64.b64encode(b"admin:s3cret").decode()
        req = urllib.request.Request("http://127.0.0.1:8086/")
        req.add_header("Authorization", "Basic " + tok)
        with opener.open(req, timeout=4) as r:
            check("Basic 认证：正确凭据 200", r.status == 200, "实际 %s" % r.status)

        time.sleep(1.5)

        print("\n== 4. 状态接口 ==")
        st, h, b = get("/_goproxy/stats")
        check("GET /_goproxy/stats -> 200", st == 200, "实际 %s" % st)
        stats = json.loads(b)
        check("总请求数 > 0", stats["summary"]["requests_total"] > 0, str(stats["summary"]["requests_total"]))
        check("有 5xx 记录（熔断路由）", any(c.startswith("5") for c in stats["summary"]["by_status"]), str(stats["summary"]["by_status"]))
        check("限流计数 > 0", stats["summary"]["rate_limited_total"] > 0, str(stats["summary"]["rate_limited_total"]))
        check("拒绝计数 > 0（ACL）", stats["summary"]["rejected_total"] > 0, str(stats["summary"]["rejected_total"]))
        check("采样曲线有点", len(stats["series"] or []) > 0, str(len(stats["series"] or [])))
        check("端口列表完整", set(stats["ports"]) >= {8000, 8081, 8082, 8083, 8086, 8087, 8088, 8089}, str(stats["ports"]))
        check("有路由启用了熔断", stats["circuit"]["closed"] + stats["circuit"]["open"] + stats["circuit"]["half_open"] > 0, str(stats["circuit"]))
        check("日志缓冲有内容", stats["logs"]["buffered"] > 0, str(stats["logs"]))

        print("\n== 5. 日志接口 ==")
        st, h, b = get("/_goproxy/logs?limit=100")
        check("GET /_goproxy/logs -> 200", st == 200, "实际 %s" % st)
        logs = json.loads(b)
        ents = logs["entries"] or []
        check("有日志条目", len(ents) > 0, str(len(ents)))
        check("日志有 blocked 标记", any(e.get("blocked") for e in ents), "")
        reasons = {e["blocked"] for e in ents if e.get("blocked")}
        print("    拦截原因：%s" % reasons)
        check("出现 rate_limited", "rate_limited" in reasons, str(reasons))
        # v0.7.0 把笼统的 acl 拆成了三个标签，路由级黑名单现在是 acl_route_deny。
        # 断言用精确值而不是 "acl" —— 后者在拆分之后永远不成立，
        # 而且就算成立也说明不了是哪一层拦的。
        check("出现 acl_route_deny", "acl_route_deny" in reasons, str(reasons))
        check("出现 auth_missing_credentials", "auth_missing_credentials" in reasons, str(reasons))
        check("seq 单调递增", all(ents[i]["seq"] < ents[i + 1]["seq"] for i in range(len(ents) - 1)))

        print("\n== 6. SSE 实时日志 ==")
        hello_seen = []
        access_seen = []

        def listen():
            req = urllib.request.Request(ADMIN + "/_goproxy/events")
            req.add_header("Accept", "text/event-stream")
            # v0.6.0 起 /events 也在 adminGuard 后面，必须带凭据。
            # 漏了这句的症状很隐蔽：401 被下面的 except 吞掉，
            # 表现为「hello 没收到、事件数 0」，看着像 SSE 本身坏了。
            for k, v in AUTH_HEADERS.items():
                req.add_header(k, v)
            try:
                with opener.open(req, timeout=12) as r:
                    ev = ""
                    data = ""
                    for raw in r:
                        line = raw.decode("utf-8", "replace").rstrip("\n")
                        if line == "":
                            if data:
                                if ev == "hello":
                                    hello_seen.append(json.loads(data))
                                elif ev == "access":
                                    access_seen.append(json.loads(data))
                            ev, data = "", ""
                            continue
                        if line.startswith(":"):
                            continue
                        k, _, v = line.partition(":")
                        v = v.lstrip(" ")
                        if k == "event":
                            ev = v
                        elif k == "data":
                            data += v
            except urllib.error.HTTPError as e:
                # 把状态码打出来，别静默吞掉 —— 否则鉴权失败会伪装成「SSE 没数据」
                print("    （SSE 连接被拒：HTTP %d %s）" % (e.code, e.read()[:120]))
            except Exception as e:
                print("    （SSE 连接异常：%s）" % e)

        t = threading.Thread(target=listen, daemon=True)
        t.start()
        time.sleep(1.0)
        check("SSE 收到 hello 握手", len(hello_seen) > 0, str(hello_seen))

        for _ in range(3):
            try:
                with opener.open("http://127.0.0.1:8081/sse-trigger", timeout=4) as r:
                    r.read()
            except Exception:
                pass
            time.sleep(0.25)

        time.sleep(1.2)
        check("SSE 收到 access 事件", len(access_seen) > 0, str(len(access_seen)))
        if access_seen:
            e = access_seen[-1]
            check("access 事件字段完整", {"seq", "path", "status", "dur_ms"} <= set(e), str(list(e)[:8]))

        # 断开后订阅者要回收
        time.sleep(1.0)
        st, h, b = get("/_goproxy/stats")
        subs = json.loads(b)["logs"]["subscribers"]
        print("    （当前订阅者 %d，监听线程仍在跑所以 >=1 属正常）" % subs)

        print("\n== 7. 路由 CRUD ==")
        st, h, b = get("/_goproxy/routes")
        check("GET /routes -> 200", st == 200, "实际 %s" % st)
        etag = hdr(h, "ETag")
        check("返回了 ETag", bool(etag), "实际响应头 %s" % dict(h))
        # 拿到的是带引号的 sha256，前端要原样塞回 If-Match
        check("ETag 是带引号的 sha256", etag is not None and etag.startswith('"') and len(etag) == 66, str(etag))

        new_route = {
            "name": "e2e 临时路由",
            "listen_port": 8099,
            "path_prefix": "/e2e",
            "target": "http://127.0.0.1:9001",
        }
        st, h, b = post("/_goproxy/routes", new_route)
        check("POST /routes -> 201", st == 201, "实际 %s :: %s" % (st, b[:200]))
        created = json.loads(b)
        rid = created["route"]["id"]
        check("新路由拿到了 id", bool(rid), str(created))
        check("新端口 8099 已监听", 8099 in (created.get("ports") or []), str(created.get("ports")))
        check("listen_port 被保留", created["route"]["listen_port"] == 8099, str(created["route"]))

        if not wait_port(8099, 5):
            check("8099 真的在监听", False, "端口没起来")
        else:
            check("8099 真的在监听", True)

        # 用过期 ETag 提交，必须 409
        st, h, b = post(
            "/_goproxy/routes/" + rid,
            {"enabled": False},
            method="PATCH",
            headers={"If-Match": '"deadbeef"'},
        )
        check("过期 If-Match -> 409", st == 409, "实际 %s :: %s" % (st, b[:150]))

        # 用正确 ETag 停用
        st, h, b = post(
            "/_goproxy/routes/" + rid,
            {"enabled": False},
            method="PATCH",
            headers={"If-Match": created["revision"]},
        )
        check("PATCH 停用 -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))
        check("停用后启用状态为 false", json.loads(b)["route"]["enabled"] is False, b[:200])
        time.sleep(0.6)
        check("停用后 8099 关闭", not wait_port(8099, 2), "端口还开着")

        st, h, b = post("/_goproxy/routes/" + rid, None, method="DELETE")
        check("DELETE -> 200", st == 200, "实际 %s :: %s" % (st, b[:200]))
        check("删除后回到 9 条路由", json.loads(b)["routes"] == 9, b[:200])

        # 配置里的原始路由不能被我们改坏
        st, h, b = get("/_goproxy/routes")
        routes = json.loads(b)
        ids = {r["id"] for r in routes}
        check("原有 9 条路由都在", len(ids) == 9, str(sorted(ids)))
        check("fallback 路由仍在", "fallback" in ids)

        print("\n== 8. 全局配置 ==")
        st, h, b = get("/_goproxy/config")
        check("GET /config -> 200", st == 200, "实际 %s" % st)
        cfg = json.loads(b)
        check("不回传 admin_token 明文", "admin_token" not in cfg, str(list(cfg)))
        check("返回 admin_token_set 布尔位", "admin_token_set" in cfg)
        # admin_users 只暴露用户名，密码哈希绝不出现 ——
        # 这个接口能读到配置，把哈希顺带带出去等于一次认证读取就泄漏全部凭据
        check("返回 admin_users 列表", isinstance(cfg.get("admin_users"), list), str(cfg.get("admin_users")))
        for u in cfg.get("admin_users") or []:
            check("  admin_users 里不含密码材料",
                  "password" not in u and "password_hash" not in u, str(u))
        check("返回 credentials_configured 布尔位",
              isinstance(cfg.get("credentials_configured"), bool), str(cfg.get("credentials_configured")))
        check("管理地址正确", cfg["admin_addr"] == "127.0.0.1:9080", str(cfg["admin_addr"]))

        st, h, b = post("/_goproxy/config", {"admin_addr": "0.0.0.0:9080"}, method="PATCH")
        check("改 admin_addr 被拒（启动期配置）", st == 400, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = post("/_goproxy/config", {"routes": []}, method="PATCH")
        check("走 config 改 routes 被拒", st == 400, "实际 %s :: %s" % (st, b[:150]))

        st, h, b = post("/_goproxy/reload", None)
        check("手动重载 -> 200", st == 200, "实际 %s :: %s" % (st, b[:150]))

        print("\n== 9. 健康检查与指标 ==")
        for p, want in (("/healthz", 200), ("/readyz", 200), ("/metrics", 200)):
            st, h, b = get(p)
            check("GET %s -> %d" % (p, want), st == want, "实际 %s" % st)
        st, h, b = get("/metrics")
        check("metrics 含 goproxy_requests_total", b"goproxy_requests_total" in b)
        check("metrics 含熔断状态", b"goproxy_circuit_state" in b)
        check("metrics 含 p95 直方图", b"goproxy_request_duration_seconds_bucket" in b)

        print("\n== 10. 认证与会话 ==")
        run_auth_section(tmp, bins)

        # 放在最后：这一节会（刻意地）把管理端口也一起封掉，再靠「导回配置 +
        # 重启进程」恢复。后面若还有用例，就会撞在「刚被自己封掉的管理接口」上。
        run_acl_section(db_path, bins, restart_proxy)

    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    print("通过 %d 项，失败 %d 项" % (len(passed), len(failed)))
    for f in failed:
        print("  FAIL " + f)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
