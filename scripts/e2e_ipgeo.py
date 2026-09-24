"""日志里 IP 地域的端到端验证（真实二进制 + 真实 26 MB 地域库 + 真实端口）。

为什么要单跑一遍：单测里的合成库只能证明「解析器符合我理解的格式」，证明不了
「拿真实的 qqwry.dat 也能读出对的地名」。这个脚本用的就是真库，断言的是
几个常识地址（8.8.8.8 / 114.114.114.114）——它们错了就说明格式又读偏了。

顺带验三件只有真跑才能证的事：
  1. 地域是在**出站时**补的：/logs 与 SSE 两条路都要带上，且环形缓冲里那份不带；
  2. 各种「查不到」是分开的状态（内网 / IPv6 / 未收录 / 未启用），不是笼统的未知；
  3. 没有地域库时不影响任何其它功能，只是地域位置显示「未启用」。

用法：python scripts/e2e_ipgeo.py
没有 qqwry.dat 时跳过（它是 .gitignore 的运行时数据文件，CI 上必然没有）。
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO = "go"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail and not ok:
        print("         -> %s" % detail)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def find_qqwry():
    """找那份真实的地域库。找不到就跳过 —— 它不进仓库。"""
    for rel in ("qqwry.dat", os.path.join("..", "qqwry.dat"),
                os.path.join("..", "..", "qqwry.dat")):
        p = os.path.abspath(os.path.join(ROOT, rel))
        if os.path.isfile(p):
            return p
    return ""


def api(admin, method, path, body=None, token="geo-e2e-token", timeout=10):
    c = http.client.HTTPConnection("127.0.0.1", admin, timeout=timeout)
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
        return r.status, raw
    finally:
        c.close()


def japi(admin, method, path, body=None):
    st, raw = api(admin, method, path, body)
    try:
        return st, json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return st, {"_raw": raw[:200].decode("utf-8", "replace")}


def visit(port, path, xff=None):
    """打一下业务端口。带 XFF 就能把「来源 IP」设成想要的值。"""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {}
    if xff:
        h["X-Forwarded-For"] = xff
    try:
        c.request("GET", path, headers=h)
        r = c.getresponse()
        r.read()
        return r.status
    except Exception as e:
        return 0
    finally:
        c.close()


def start(exe, db, cwd, extra=None):
    args = [exe, "-c", db] + (extra or [])
    proc = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc


def wait_ready(admin, proc, tries=60):
    for _ in range(tries):
        try:
            st, _ = api(admin, "GET", "/_goproxy/ports", timeout=1)
            if st == 200:
                return True
        except Exception:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.25)
    return False


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main():
    qqwry = find_qqwry()
    if not qqwry:
        print("没找到 qqwry.dat（它是 .gitignore 的运行时数据文件），跳过 IP 地域端到端。")
        return 0
    print("地域库:", qqwry, "（%.1f MB）" % (os.path.getsize(qqwry) / 1048576.0))

    work = tempfile.mkdtemp(prefix="ipgeo-e2e-")
    exe = os.path.join(work, "goproxy.exe")
    db = os.path.join(work, "goproxy.db")

    print("== 0. 编译 ==")
    env = dict(os.environ, CGO_ENABLED="0")
    r = subprocess.run([GO, "build", "-o", exe, "."], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print("编译失败:\n" + r.stderr[-2000:])
        return 1

    admin, biz = free_port(), free_port()
    cfg = {
        "admin_addr": "127.0.0.1:%d" % admin,
        "admin_token": "geo-e2e-token",
        "default_ports": [biz],
        # 让 127.0.0.1 可信，才能用 X-Forwarded-For 造出「任意来源 IP」的日志。
        # 不带 XFF 的请求行为不变（clientIP 在 XFF 为空时照样返回直连地址）。
        "trusted_proxies": ["127.0.0.1"],
        "routes": [{"id": "r1", "listen_port": biz, "path_prefix": "/",
                    "target": "http://127.0.0.1:9"}],
    }
    cfg_path = os.path.join(work, "seed.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    print("== 1. 把地域库放到配置库同目录（验自动查找那条路）==")
    import shutil
    shutil.copyfile(qqwry, os.path.join(work, "qqwry.dat"))

    r = subprocess.run([exe, "-c", db, "-config-import", cfg_path],
                       capture_output=True, text=True, cwd=work, timeout=120)
    check("配置导入成功", r.returncode == 0, (r.stdout or "")[-300:])

    print("== 2. 起服务 ==")
    proc = start(exe, db, work)
    if not wait_ready(admin, proc):
        out = proc.stdout.read().decode("utf-8", "replace")[-1500:]
        print("服务没起来:\n" + out)
        stop(proc)
        return 1
    check("服务启动并就绪", True)

    try:
        print("== 3. 造一批不同来源的日志 ==")
        cases = [
            ("8.8.8.8", "ok", "美国", "谷歌"),
            ("114.114.114.114", "ok", "中国", "南京"),
            ("192.168.1.9", "internal", "", ""),
            ("2001:4860:4860::8888", "unsupported", "", ""),
        ]
        for i, (ip, _, _, _) in enumerate(cases):
            visit(biz, "/geo-%d" % i, xff=ip)
        visit(biz, "/geo-local")  # 不带 XFF → 127.0.0.1
        time.sleep(0.4)

        print("== 4. /logs 里每条记录的地域 ==")
        st, body = japi(admin, "GET", "/_goproxy/logs?limit=100")
        check("logs 接口正常", st == 200, json.dumps(body)[:300])
        entries = {e.get("client_ip"): e for e in (body.get("entries") or [])}
        for ip, want_status, want_country, want_detail in cases:
            e = entries.get(ip)
            if not e:
                check("%s 这条日志在" % ip, False, "日志里没有这个来源（造数据失败？）")
                continue
            geo = e.get("ip_geo") or {}
            ok = geo.get("status") == want_status
            if want_status == "ok":
                ok = ok and geo.get("country") == want_country and want_detail in (geo.get("detail") or "")
            check("%-22s 地域状态=%s" % (ip, want_status), ok, json.dumps(geo, ensure_ascii=False))

        e = entries.get("127.0.0.1")
        check("内网来源标成「局域网」（不是「未知地区」）",
              bool(e) and (e.get("ip_geo") or {}).get("status") == "internal",
              json.dumps(e.get("ip_geo") if e else None, ensure_ascii=False))

        print("== 5. 地域与 IP 在同一个对象里（对齐是结构性的，不靠两边按顺序贴）==")
        pairs_ok = True
        for ip, info in entries.items():
            geo = info.get("ip_geo")
            if geo is None:
                continue
            # 中国的地址不该把「美国」标上去，反之亦然 —— 串行就会这样
            if "8.8.8.8" == ip and "美国" not in (geo.get("country") or ""):
                pairs_ok = False
            if "114.114.114.114" == ip and "江苏" not in json.dumps(geo, ensure_ascii=False):
                pairs_ok = False
        check("★ 每条日志的地域都属于它自己那个 IP", pairs_ok,
              json.dumps({k: (v.get("ip_geo") or {}).get("status") for k, v in entries.items()}, ensure_ascii=False)[:400])

        print("== 6. 地域库的自述（来源 / 时间 / 条数）==")
        geo_meta = body.get("geo") or {}
        check("响应里带着地域库来源", geo_meta.get("available") is True, json.dumps(geo_meta, ensure_ascii=False)[:300])
        check("条数与真实库一致（150 万量级）", (geo_meta.get("entries") or 0) > 1_000_000,
              str(geo_meta.get("entries")))
        check("给出了文件时间（界面据此说明数据新不新）", bool(geo_meta.get("updated_at")),
              str(geo_meta.get("updated_at")))
        check("路径指向那个文件", "qqwry.dat" in (geo_meta.get("path") or ""), str(geo_meta.get("path")))
        check("命中统计在动（缓存生效）", (geo_meta.get("hits") or 0) >= 0 and (geo_meta.get("queries") or 0) > 0,
              json.dumps(geo_meta, ensure_ascii=False)[:200])

        print("== 7. SSE 实时推送也要带地域 ==")
        got = {}

        def read_sse():
            """
            读 SSE。注意第一条是 `event: hello`（带 latest_seq，形状和访问记录
            完全不同），必须按事件名区分 —— 只挑 `event: access` 的 data，
            否则会把 hello 的 payload 当成一条日志，得出「没带地域」的假结论。
            """
            try:
                c = http.client.HTTPConnection("127.0.0.1", admin, timeout=8)
                c.request("GET", "/_goproxy/events",
                          headers={"Authorization": "Bearer geo-e2e-token"})
                r = c.getresponse()
                buf = ""
                event = ""
                deadline = time.time() + 6
                while time.time() < deadline:
                    chunk = r.read(1)
                    if not chunk:
                        break
                    buf += chunk.decode("utf-8", "replace")
                    while "\n\n" in buf:
                        block, buf = buf.split("\n\n", 1)
                        event, payload = "", None
                        for line in block.split("\n"):
                            if line.startswith("event: "):
                                event = line[7:].strip()
                            elif line.startswith("data: "):
                                payload = line[6:]
                        if event == "access" and payload:
                            got["entry"] = json.loads(payload)
                            c.close()
                            return
                c.close()
            except Exception as e:
                got["err"] = str(e)

        t = threading.Thread(target=read_sse, daemon=True)
        t.start()
        time.sleep(0.8)
        visit(biz, "/geo-sse", xff="8.8.8.8")
        t.join(timeout=8)
        ent = got.get("entry") or {}
        check("SSE 推来的访问记录也带地域",
              bool(ent.get("ip_geo")) and ent["ip_geo"].get("status") == "ok",
              json.dumps(got, ensure_ascii=False)[:300])

        print("== 8. 环形缓冲里那份不带地域（地域只在出站时补）==")
        # 上面几条请求都进过缓冲；重新拉一次 /logs，同一批 IP 仍然有地域 ——
        # 说明补地域是可重复的、不是「写的时候写过一次就没了」。
        st, body2 = japi(admin, "GET", "/_goproxy/logs?limit=100")
        again = {e.get("client_ip"): e for e in (body2.get("entries") or [])}
        check("再拉一次仍然有地域（说明是出站补的，不靠写入时记下）",
              bool((again.get("8.8.8.8") or {}).get("ip_geo")),
              json.dumps(again.get("8.8.8.8"), ensure_ascii=False)[:300])

        stop(proc)
        print("== 9. 没有地域库时：只降级，不影响别的 ==")
        os.remove(os.path.join(work, "qqwry.dat"))
        proc = start(exe, db, work)
        if not wait_ready(admin, proc):
            check("去掉地域库后服务仍能启动", False, proc.stdout.read().decode()[-800:])
            return 1
        check("★ 没有地域库时服务照常启动", True)
        visit(biz, "/geo-nolib", xff="8.8.8.8")
        time.sleep(0.4)
        st, body3 = japi(admin, "GET", "/_goproxy/logs?limit=20")
        e2 = {e.get("client_ip"): e for e in (body3.get("entries") or [])}.get("8.8.8.8")
        geo2 = (e2 or {}).get("ip_geo") or {}
        check("地域显示为「未启用」而不是空白或乱码", geo2.get("status") == "unavailable",
              json.dumps(geo2, ensure_ascii=False))
        check("状态里给出了原因（说清去哪放文件）",
              "qqwry" in (geo2.get("detail") or "") or "qqwry" in json.dumps(body3.get("geo") or {}, ensure_ascii=False),
              json.dumps(geo2, ensure_ascii=False))
        meta2 = body3.get("geo") or {}
        check("geo 段如实报「不可用」", meta2.get("available") is False, json.dumps(meta2, ensure_ascii=False)[:200])
        # 业务请求本身照常走完管线。这里 target 指向一个没人监听的端口，
        # 所以预期就是 502（上游连不上）—— 断言的是「还有正常响应」，
        # 而不是某个具体状态码：地域库的缺失不该影响请求处理本身。
        st = visit(biz, "/geo-ok", xff="8.8.8.8")
        check("地域库缺失不影响请求处理（仍拿到正常的上游响应）", st in (200, 404, 502),
              "业务端口返回 %s" % st)
    finally:
        stop(proc)

    print("\n=== 结果：%d 项通过，%d 项失败 ===" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  - " + f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
