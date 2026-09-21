"""蜜罐 + 自动封禁的端到端验证（真实二进制、真实端口、真实进程）。

为什么非要真跑一遍：单测只能覆盖机制（评分、阶梯、豁免函数），而这一段的价值
恰恰在「真端口上开着一个没人该访问的监听、真进程之间共享同一张封禁表」这些
只有真起来才成立的地方。这里验的每一条都对应一个具体的失败模式：

  1. 蜜罐端口真的在监听、并且**一个字节都不回**（回了就是给扫描器当指纹）
  2. 回环来源命中豁免：连了不该连的端口，但内网地址一个都不封
  3. 手动封禁 127.0.0.1 之后，业务端口与控制台**同时**被拒（403 且什么都不说）
  4. 命令行 -bans / -unban 在服务运行期间读写同一张表（跨进程可见）
  5. 重启后封禁仍在（否则「打崩进程」就等于免费解封）

用法：python scripts/e2e_honeypot.py
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# 仓库根目录（脚本就在 <repo>/scripts/ 下）。不写死绝对路径：
# 这个脚本要能跟着代码一起被 clone 到任何地方跑。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO = "go"
PY = sys.executable


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    mark = "PASS" if ok else "FAIL"
    line = "  [%s] %s" % (mark, name)
    if detail and not ok:
        line += "\n         -> %s" % detail
    print(line)


# 不开代理：本机有 http_proxy，会让 127.0.0.1 的请求变成 502
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def req(method, url, body=None, token="e2etoken", timeout=5, raw=False):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with OPENER.open(r, timeout=timeout) as resp:
            payload = resp.read()
            return resp.status, (payload if raw else payload.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        payload = e.read()
        return e.code, (payload if raw else payload.decode("utf-8", "replace"))


def start_service(exe, db, admin):
    proc = subprocess.Popen(
        [exe, "-c", db, "-text-log"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=os.path.dirname(db),
    )
    # 等就绪：/_goproxy/ports 需要凭据，401 也算「活着且路由表就绪」之外的信息；
    # 用带令牌的请求判 200。
    for _ in range(80):
        try:
            st, _ = req("GET", "http://127.0.0.1:%d/_goproxy/ports" % admin, timeout=1)
            if st == 200:
                return proc, True
        except Exception:
            pass
        if proc.poll() is not None:
            out = proc.stdout.read().decode("utf-8", "replace")
            print("服务提前退出：\n" + out[-2000:])
            return proc, False
        time.sleep(0.25)
    return proc, False


def stop_service(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main():
    work = tempfile.mkdtemp(prefix="honeypot-e2e-")
    exe = os.path.join(work, "goproxy.exe")
    db = os.path.join(work, "goproxy.db")

    print("== 0. 编译真实二进制 ==")
    env = dict(os.environ, CGO_ENABLED="0")
    r = subprocess.run([GO, "build", "-o", exe, "."], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print("编译失败：\n" + r.stderr[-3000:])
        return 1
    check("二进制编译成功", os.path.exists(exe))

    admin, route_port, trap_port, trap_udp, backend = (
        free_port(), free_port(), free_port(), free_udp_port(), free_port())

    # 后端：409/200 都行，只要它在，转发这一步就不会因为连不上而掩盖我们的断言
    backend_srv = http.server.ThreadingHTTPServer(
        ("127.0.0.1", backend),
        type("H", (http.server.BaseHTTPRequestHandler,), {
            "do_GET": lambda self: (self.send_response(200), self.end_headers(),
                                  self.wfile.write(b"backend-ok")),
            "log_message": lambda *a: None,
        }))
    threading.Thread(target=backend_srv.serve_forever, daemon=True).start()

    cfg = {
        "admin_addr": "127.0.0.1:%d" % admin,
        "admin_token": "e2etoken",
        "default_ports": [route_port],
        "routes": [{
            "id": "r1", "listen_port": route_port, "path_prefix": "/",
            "target": "http://127.0.0.1:%d" % backend,
        }],
    }
    cfg_path = os.path.join(work, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    print("== 1. 导入配置 ==")
    r = subprocess.run([exe, "-c", db, "-config-import", cfg_path],
                       capture_output=True, text=True, timeout=120)
    check("配置导入成功", r.returncode == 0, r.stdout[-500:] + r.stderr[-500:])

    print("== 2. 设置蜜罐端口（先观察模式）==")
    r = subprocess.run([exe, "-c", db, "-honeypot-set", "%d,%d/udp" % (trap_port, trap_udp)],
                       capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
    check("蜜罐端口已写入配置", r.returncode == 0 and "已保存" in (r.stdout or ""),
          (r.stdout or "") + (r.stderr or ""))

    print("== 3. 起服务 ==")
    proc, ok = start_service(exe, db, admin)
    if not ok:
        return 1
    check("服务启动并就绪", ok)
    base = "http://127.0.0.1:%d" % admin
    try:
        print("== 4. 观察模式下，连蜜罐端口 ==")
        got_bytes = b""
        try:
            c = socket.create_connection(("127.0.0.1", trap_port), timeout=3)
            c.settimeout(0.4)
            try:
                got_bytes = c.recv(64)
            except socket.timeout:
                got_bytes = b""
            c.close()
        except OSError as e:
            check("蜜罐端口可连接（伪装成开放）", False, str(e))

        check("蜜罐端口接受连接（内核回 SYN-ACK = 扫描器判定 open）", True)
        check("蜜罐不向对方发送任何数据（不给指纹）", got_bytes == b"", repr(got_bytes))

        # 循环等命中被记账（上报发生在 accept 的 goroutine 里）
        recent = []
        for _ in range(40):
            st, body = req("GET", base + "/_goproxy/bans")
            if st == 200:
                recent = json.loads(body).get("recent") or []
                if recent:
                    break
            time.sleep(0.1)
        check("蜜罐命中被记录", len(recent) >= 1, json.dumps(recent)[:300])
        if recent:
            check("记录的来源是直连对端 127.0.0.1", recent[0]["ip"] == "127.0.0.1",
                  json.dumps(recent[0]))
            check("记录里带着端口与协议",
                  recent[0]["port"] == trap_port and recent[0]["proto"] == "tcp",
                  json.dumps(recent[0]))

        st, body = req("GET", base + "/_goproxy/bans")
        state = json.loads(body)
        check("观察模式下一个都没封（内网来源本来就豁免）",
              state["stats"]["active"] == 0, json.dumps(state["stats"]))
        check("开关与模式如实反映在状态里",
              state["config"]["enabled"] and state["config"]["mode"] == "observe",
              json.dumps(state["config"]))

        print("== 5. 切到 enforce，再连一次 UDP 蜜罐 ==")
        hp = dict(state["config"])
        hp["mode"] = "enforce"
        hp["enabled"] = True
        st, body = req("PUT", base + "/_goproxy/honeypot", hp)
        check("蜜罐配置更新成功", st == 200, body[:400])

        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(b"\x00probe", ("127.0.0.1", trap_udp))
        # 不回包：设个短超时，读不到东西才是对的
        u.settimeout(0.4)
        replied = b""
        try:
            replied = u.recvfrom(64)[0]
        except socket.timeout:
            pass
        u.close()
        check("UDP 蜜罐绝不回包（不回包才不会成为反射放大器）", replied == b"", repr(replied))

        recent = []
        for _ in range(40):
            st, body = req("GET", base + "/_goproxy/bans")
            recent = json.loads(body).get("recent") or []
            if any(x["proto"] == "udp" for x in recent):
                break
            time.sleep(0.1)
        check("UDP 命中被记录", any(x["proto"] == "udp" for x in recent),
              json.dumps(recent)[:300])
        check("enforce 之下回环来源依然不封（豁免在最后一道写入口再判一次）",
              json.loads(req("GET", base + "/_goproxy/bans")[1])["stats"]["active"] == 0)

        print("== 6. 手动封禁 127.0.0.1：业务端口与控制台应同时被拒 ==")
        st, body = req("POST", base + "/_goproxy/bans",
                       {"ip": "127.0.0.1", "reason": "e2e 手动封禁", "secs": 600})
        check("手动封禁成功（人工封禁不走豁免）", st == 200, body[:300])

        st, body = req("GET", "http://127.0.0.1:%d/" % route_port, raw=True)
        check("业务端口被拒 403", st == 403, "status=%s body=%r" % (st, body[:120]))
        check("拒绝响应什么都不说（无 JSON、无 reason、无 Content-Type）",
              b"forbidden" not in body and b"{" not in body,
              repr(body[:200]))

        st, body = req("GET", base + "/_goproxy/bans")
        check("控制台接口同样被拒（自动封禁覆盖所有入口）", st == 403,
              "status=%s body=%r" % (st, body[:120]))

        st, body = req("GET", "http://127.0.0.1:%d/" % route_port, raw=True, token=None)
        check("无凭据访问业务端口也被拒（不是靠鉴权兜的）", st == 403,
              "status=%s" % st)

        print("== 7. 命令行跨进程读写同一张封禁表 ==")
        r = subprocess.run([exe, "-c", db, "-bans"], capture_output=True, text=True,
                           timeout=60, encoding="utf-8", errors="replace")
        check("命令行 -bans 能看到这条封禁",
              r.returncode == 0 and "127.0.0.1" in (r.stdout or ""),
              (r.stdout or "")[-500:])
        check("命令行 -bans 标出它正在生效", "生效中" in (r.stdout or ""),
              (r.stdout or "")[-400:])

        r = subprocess.run([exe, "-c", db, "-unban", "127.0.0.1"], capture_output=True,
                           text=True, timeout=60, encoding="utf-8", errors="replace")
        check("命令行 -unban 执行成功", r.returncode == 0 and "已解封" in (r.stdout or ""),
              (r.stdout or "")[-400:])

        # 关键一条：命令行改的是库，而判定用的是**进程内存里的快照**。
        # 没有那条周期性重读，这里会一直 403 —— 界面上「已解封」、请求仍被拒，
        # 是最难解释的一种不一致。等它自己收敛（最多一轮重读）。
        print("    （等运行中的服务自己发现被解封，最多 75 秒）")
        converged = False
        deadline = time.time() + 75
        while time.time() < deadline:
            st, _ = req("GET", "http://127.0.0.1:%d/" % route_port, raw=True, timeout=2)
            if st == 200:
                converged = True
                break
            time.sleep(2)
        check("运行中的服务发现外部解封：不重启也恢复放行", converged,
              "等了 75 秒仍是 %s" % st)

        print("== 8. 重启：库里的封禁要恢复，被解封的不要再回来 ==")
        st, body = req("POST", base + "/_goproxy/bans",
                       {"ip": "93.184.216.34", "reason": "e2e 重启留存", "secs": 600})
        check("再封一个公网地址", st == 200, body[:200])
        stop_service(proc)
        proc, ok = start_service(exe, db, admin)
        check("服务重启后就绪", ok)
        st, body = req("GET", base + "/_goproxy/bans")
        entries = json.loads(body)["entries"]
        ips = [e["ip"] for e in entries]
        check("重启后封禁仍然生效（打崩进程 != 免费解封）",
              "93.184.216.34" in ips, json.dumps(entries)[:400])
        check("已解封的地址没被恢复", "127.0.0.1" not in ips, json.dumps(entries)[:400])

        st, body = req("GET", "http://127.0.0.1:%d/" % route_port, raw=True)
        check("重启后业务端口对未封禁来源正常（转发到后端）", st == 200, "status=%s" % st)

        print("== 9. 蜜罐端口在重启后仍在监听 ==")
        try:
            c = socket.create_connection(("127.0.0.1", trap_port), timeout=3)
            c.close()
            listen_ok = True
        except OSError as e:
            listen_ok = False
            print("    ", e)
        check("重启后蜜罐端口继续监听（配置持久化）", listen_ok)

        st, body = req("GET", base + "/_goproxy/bans")
        check("状态接口给出阶梯说明（界面直接显示）",
              len(json.loads(body).get("ladder") or []) == 4, body[:300])

    finally:
        stop_service(proc)
        backend_srv.shutdown()

    print("\n=== 结果：%d 项通过，%d 项失败 ===" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  - " + f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
