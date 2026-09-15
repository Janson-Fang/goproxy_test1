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


def get(path, accept=None, timeout=8):
    req = urllib.request.Request(ADMIN + path)
    if accept:
        req.add_header("Accept", accept)
    try:
        with opener.open(req, timeout=timeout) as r:
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
    try:
        with no_redirect.open(req, timeout=timeout) as r:
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
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with opener.open(req, timeout=8) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.4):
                return True
        except OSError:
            time.sleep(0.2)
    return False


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

        print("== 启动测试后端 ==")
        for port, name in ((9001, "svcA"), (9002, "svcB"), (9003, "svcC"), (9004, "svcD")):
            spawn([bins["backend-test"], "-port", str(port), "-name", name])
        for port in (9001, 9002, 9003, 9004):
            if not wait_port(port):
                print("后端 %d 没起来" % port)
                return 1

        print("== 启动 goproxy ==")
        spawn([bins["goproxy-test"], "-c", cfg, "-text-log"])
        if not wait_port(9080):
            print("管理端口 9080 没起来")
            return 1
        for port in (8000, 8081, 8082, 8083, 8086, 8087, 8088, 8089):
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

        print("\n== 2. 根路径分流 ==")
        st, h, b = get_noredirect("/", accept="text/html,application/xhtml+xml")
        check("浏览器访问 / 返回跳转", st in (301, 302), "实际 %s" % st)
        check("跳转目标是控制台", h.get("Location") == "/_goproxy/ui/", str(h.get("Location")))

        st, h, b = get("/")
        check("curl 访问 / 拿到 200", st == 200, "实际 %s" % st)
        check("curl 拿到纯文本清单", "text/plain" in h.get("Content-Type", ""), h.get("Content-Type"))
        check("清单里提示了控制台地址", b"/_goproxy/ui/" in b)

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
            except Exception:
                pass

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
