#!/usr/bin/env python3
"""管理控制台端到端自检。

用真实的后端 + 真实的反代二进制跑（不是 httptest），覆盖控制台依赖的全部接口：

  1. 控制台静态资源能加载，路径与缓存头都对
  2. 浏览器访问根路径被导向控制台，curl 拿到的是纯文本接口清单
  3. 真实流量能进到 stats / logs
  4. SSE 能收到 hello 握手和后续 access 事件
  5. 路由 CRUD 写接口 + ETag 乐观并发
  6. 全局配置读改、健康检查、Prometheus 指标

用法（在仓库根目录或任意位置都行）：

    python scripts/e2e_console.py

脚本会自己 go build 出两个临时二进制，并把 config.json 复制到临时目录再跑，
所以不会污染工作区。需要 PATH 里有 go。

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
    port_biz = 9082
    auth_cfg_path = os.path.join(tmp, "auth-config.json")

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
        "routes": [],
    }
    with open(auth_cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    del port_biz

    if port_in_use(port_admin):
        check("认证实例端口空闲", False, "%d 已被占用" % port_admin)
        return

    proc = subprocess.Popen(
        [bins["goproxy-test"], "-c", auth_cfg_path, "-text-log"],
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

        # config.json 会被 CRUD 测试改写（写接口落盘时会重新格式化），
        # 所以复制一份到临时目录里跑，别把仓库里的演示配置改脏。
        cfg = os.path.join(tmp, "config.json")
        shutil.copyfile(os.path.join(ROOT, "config.json"), cfg)

        # 管理地址以临时配置为准，别写死 9080。
        global ADMIN, AUTH_HEADERS
        cfg_data = json.load(open(cfg, encoding="utf-8"))
        admin_addr = cfg_data.get("admin_addr") or "127.0.0.1:9080"
        ADMIN = "http://" + admin_addr
        admin_port = int(admin_addr.rsplit(":", 1)[1])

        # v0.6.0 起管理接口一律要凭据（回环也不例外），所以必须往这份临时配置里
        # 塞一个 admin_token，否则后面的每个断言都会撞在 401 上。
        #
        # 为什么用 admin_token 而不是 admin_users：这些用例是「脚本访问」，
        # 走 Bearer 最直接，不用维持一个 CookieJar。登录本身由第 10 节专门测。
        cfg_data["admin_token"] = E2E_ADMIN_TOKEN
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f, ensure_ascii=False, indent=2)
        AUTH_HEADERS = {"Authorization": "Bearer " + E2E_ADMIN_TOKEN}

        # 端口预检。这一步不能省：如果 9080 上已经跑着一个实例（本机开发时很常见），
        # 自检自己起的那份会因端口被占而退出，而 wait_port 却立刻成功，
        # 于是所有断言都打在**别人那个进程**上 —— 全绿，但什么也没验证到，
        # 还会把仓库里的 config.json 改脏（CRUD 落盘的正是那个实例的配置）。
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
        proxy = spawn([bins["goproxy-test"], "-c", cfg, "-text-log"])
        if not wait_port(admin_port, proc=proxy):
            print(
                "管理端口 %d 没起来（进程存活=%s，退出码=%s）"
                % (admin_port, proxy.poll() is None, proxy.returncode)
            )
            return 1

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
        check("出现 acl", "acl" in reasons, str(reasons))
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
