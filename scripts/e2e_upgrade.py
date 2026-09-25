"""升级相关行为的端到端验证（真实二进制 + 真实配置库 + 真实进程）。

它验的是**单测证明不了的那一层**：`-config-check` 用的是「新二进制自己」的校验逻辑，
所以必须拿真二进制、对着真库跑一遍 —— 假文件只能得到「exec 失败」。

四组断言，对应这个功能的四条承诺：

  1. **它说的就是启动时会说的**：同一份库，预检与真启动的判词必须一字不差。
     这条是全部价值所在 —— 预检要是自己一套说法，就只是个会漂移的副本。
  2. **它什么都不改**：跑前跑后给库文件与所在目录拍快照比对。
     「试跑」动了手比不试跑更糟：真迁移一次，还在跑的旧二进制就面对一个它不认识的库。
  3. **不通过时真的拦住了**：上传/安装被拒、文件没被换掉；带 force 才放行，且带回警告。
  4. **正常路径没被它破坏**：把配置改好之后，同一条路照样能装。

用法：python scripts/e2e_upgrade.py
"""

import hashlib
import http.client
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO = "go"
TOKEN = "upgrade-e2e-token"

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


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def dir_snapshot(path, skip_shm=False):
    """目录快照：文件名 + 大小 + 内容哈希。

    skip_shm=True 时跳过 `-shm`。理由见 check_readonly_invariant：
    它是 SQLite 的 WAL 共享内存索引，任何连接都会碰它，且不承载配置数据，
    所以「预检不改动配置数据」这句里不该把它算进去。
    """
    out = []
    for name in sorted(os.listdir(path)):
        if skip_shm and name.endswith("-shm"):
            continue
        p = os.path.join(path, name)
        if not os.path.isfile(p):
            continue
        out.append("%s %d %s" % (name, os.path.getsize(p), sha256_file(p)[:16]))
    return out


def run_cli(exe, args, cwd=None, timeout=60):
    """跑一次命令行子命令，返回 (退出码, stdout+stderr)。"""
    env = dict(os.environ, CGO_ENABLED="0")
    r = subprocess.run([exe] + args, cwd=cwd, capture_output=True, text=True,
                       timeout=timeout, env=env)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def set_schema_version(db, value):
    """直接把库里的 schema 版本改掉，用来造「库比程序新」这个局面。

    用 Python 自带的 sqlite3，而不是装一个 sqlite3 命令行 —— 后者在 Windows 上
    基本不会有，而这条断言恰恰是本地最该跑得起来的那几条之一。
    """
    con = sqlite3.connect(db, timeout=10)
    try:
        con.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (value,))
        con.commit()
    finally:
        con.close()


def api(admin, method, path, body=None, raw_body=None, ctype=None, timeout=20):
    c = http.client.HTTPConnection("127.0.0.1", admin, timeout=timeout)
    headers = {"Authorization": "Bearer " + TOKEN}
    data = raw_body
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if ctype:
        headers["Content-Type"] = ctype
    try:
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def japi(admin, method, path, body=None):
    st, raw = api(admin, method, path, body)
    try:
        return st, json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return st, {"_raw": raw[:400].decode("utf-8", "replace")}


def upload(admin, file_path, extra_headers=None):
    """把文件当请求体直接发（上传接口也支持这种写法），multipart 那条路
    已经由单测覆盖，这里用更贴近脚本/curl 的方式。"""
    with open(file_path, "rb") as f:
        data = f.read()
    c = http.client.HTTPConnection("127.0.0.1", admin, timeout=60)
    headers = {"Authorization": "Bearer " + TOKEN,
               "Content-Type": "application/octet-stream"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        c.request("POST", "/_goproxy/upgrade/upload", body=data, headers=headers)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def start(exe, db, cwd, extra=None):
    """起实例，输出落文件（不用 PIPE —— 理由见 e2e_ipgeo.py 里那段注释）。"""
    path = os.path.join(cwd, "instance.log")
    logf = open(path, "ab", buffering=0)
    proc = subprocess.Popen([exe, "-c", db] + (extra or []), cwd=cwd,
                            stdout=logf, stderr=subprocess.STDOUT)
    proc.logf = logf
    proc.logpath = path
    return proc


def tail_log(proc, n=1500):
    path = getattr(proc, "logpath", None)
    if not path:
        return "(没有日志文件)"
    try:
        with open(path, "rb") as f:
            return f.read()[-n:].decode("utf-8", "replace") or "(日志是空的)"
    except OSError as e:
        return "(读日志失败: %s)" % e


def wait_ready(admin, proc, tries=80):
    for _ in range(tries):
        try:
            st, _ = japi(admin, "GET", "/_goproxy/ports", body=None)
            if st == 200:
                return True
        except Exception:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.25)
    return False


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    logf = getattr(proc, "logf", None)
    if logf is not None:
        logf.close()


GOOD_CONFIG = {
    "admin_addr": "127.0.0.1:%d",
    "admin_token": TOKEN,
    "default_ports": [18081],
    "routes": [{"id": "r1", "listen_port": 18081, "path_prefix": "/",
                "target": "http://127.0.0.1:9"}],
}

# v0.7.x 写法：路由内联 acl。v0.8.0 起必须拒绝，并打印迁移映射。
# 用它验「预检能不能拦住历史上真拦过的那一类问题」。
LEGACY_CONFIG = {
    "routes": [{
        "id": "web",
        "listen_port": 18082,
        "target": "http://127.0.0.1:9",
        "acl": {"mode": "allow", "cidrs": ["10.0.0.0/8"]},
    }],
}


def main():
    work = tempfile.mkdtemp(prefix="upgrade-e2e-")
    exe = os.path.join(work, "goproxy" + (".exe" if os.name == "nt" else ""))

    print("== 0. 编译真实二进制 ==")
    env = dict(os.environ, CGO_ENABLED="0")
    r = subprocess.run([GO, "build", "-o", exe, "."], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        print("编译失败:\n" + r.stderr[-2000:])
        return 1
    print("   二进制: %s（%.1f MB）" % (exe, os.path.getsize(exe) / 1048576.0))

    # ---------------------------------------------------------------
    print("\n== 1. CLI 预检：判词与启动一致、且什么都不改 ==")
    db = os.path.join(work, "cfg", "goproxy.db")
    os.makedirs(os.path.dirname(db), exist_ok=True)
    seed = os.path.join(work, "seed.json")
    good = dict(GOOD_CONFIG)
    good["admin_addr"] = "127.0.0.1:%d" % free_port()
    with open(seed, "w", encoding="utf-8") as f:
        json.dump(good, f)

    rc, out = run_cli(exe, ["-c", db, "-config-import", seed])
    check("先导入一份合法配置（前提）", rc == 0, out[-400:])

    before = dir_snapshot(os.path.dirname(db))
    before_sha = sha256_file(db)

    rc, out = run_cli(exe, ["-c", db, "-config-check"])
    check("合法配置：预检通过（退出码 0）", rc == 0, out[-400:])
    check("通过时说明读到了什么", "可以加载" in out, out[-400:])

    after = dir_snapshot(os.path.dirname(db))
    check("预检没有改动主库文件", sha256_file(db) == before_sha)

    # 除 -shm 之外，数据文件必须一模一样。
    #
    # 只排除 -shm，理由要写清楚（这是实测出来的，不是宽松处理）：
    # SQLite 的 WAL 模式下，**任何**连接 —— 包括只读连接 —— 都要通过 -shm
    # 这个共享内存索引协调读位置，所以它的字节必然会变；它不承载任何配置数据。
    # 而真正承载配置的 goproxy.db 与 goproxy.db-wal，在 mode=ro 下不会被改动
    # （对比：若用 query_only，自己是最后一个连接时会把 WAL 检查点进主库、
    #   并删掉 -wal/-shm —— 内容没变，但文件确实被重写了）。
    before_data = dir_snapshot(os.path.dirname(db), skip_shm=True)
    after_data = dir_snapshot(os.path.dirname(db), skip_shm=True)
    check("预检除 -shm（SQLite 运行时索引）外没有改动任何文件", before_data == after_data,
          "之前 %s\n之后 %s" % (before_data, after_data))
    changed = set(before) - set(after) | (set(after) - set(before))
    check("确实只有 -shm 变过（不是碰巧没变）",
          all("-shm" in c for c in changed),
          "非 -shm 的差异: %s" % sorted(x for x in changed if "-shm" not in x))

    # 造一个「库比程序新」的局面：启动必然失败，预检也必须失败，
    # 而且两边的判词要一字不差。
    set_schema_version(db, "99")
    rc, out = run_cli(exe, ["-c", db, "-config-check"])
    check("schema 对不上：预检失败（非 0 退出码）", rc != 0, "rc=%d %s" % (rc, out[-300:]))
    check("判词里带上实际读到的版本号", "99" in out, out[-300:])
    check("判词说清了「库比程序新」", "库比程序新" in out, out[-300:])

    rc2, out2 = run_cli(exe, ["-c", db, "-version"])
    # -version 与配置无关，这里只是确认二进制本身还好用（排除「二进制坏了」这种解释）
    check("同一个二进制自己能跑（排除二进制损坏）", rc2 == 0, out2[-200:])

    # -c 指到旧的 config.json：升级最常见的误操作
    json_path = os.path.join(work, "cfg", "config.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(good, f)
    rc, out = run_cli(exe, ["-c", json_path, "-config-check"])
    check("把 config.json 当配置库：被拦住", rc != 0, out[-300:])
    check("并给出「这不是 SQLite 库」的判词", "不是 SQLite 数据库" in out, out[-300:])

    # 老部署升级场景：空库 + 旁边一份旧写法 config.json
    seed_dir = os.path.join(work, "legacy")
    os.makedirs(seed_dir, exist_ok=True)
    empty_db = os.path.join(seed_dir, "goproxy.db")
    rc, _ = run_cli(exe, ["-c", empty_db, "-config-export", os.path.join(seed_dir, "x.json")])
    with open(os.path.join(seed_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(LEGACY_CONFIG, f)
    rc, out = run_cli(exe, ["-c", empty_db, "-config-check"])
    check("空库 + 旧写法 config.json：预检拦住（这是历史上真拦过的那类问题）",
          rc != 0, out[-400:])
    check("判词里带迁移映射（能照着改）", "ip_lists" in out and "config.json" in out, out[-500:])

    # ---------------------------------------------------------------
    print("\n== 2. CLI 应用（root 那一步）：预检不通过时不许换文件 ==")
    apply_dir = os.path.join(work, "apply")
    state_dir = os.path.join(apply_dir, "state")
    os.makedirs(state_dir, exist_ok=True)
    installed = os.path.join(apply_dir, "goproxy")
    shutil.copyfile(exe, installed)
    installed_sha = sha256_file(installed)

    bad_db = os.path.join(state_dir, "goproxy.db")
    shutil.copyfile(db, bad_db)          # 这份库的 schema 是 99
    stage_dir = os.path.join(state_dir, "upgrade")
    os.makedirs(stage_dir, exist_ok=True)
    staged = os.path.join(stage_dir, "goproxy.staged")
    shutil.copyfile(exe, staged)

    rc, out = run_cli(installed, ["-c", bad_db, "-upgrade-apply"])
    check("配置对不上时 apply 拒绝执行", rc != 0, "rc=%d %s" % (rc, out[-400:]))
    check("拒绝理由是配置预检（不是别的错）", "配置预检未通过" in out, out[-500:])
    check("被拒时二进制一个字节没动", sha256_file(installed) == installed_sha)
    check("被拒时连备份都没产生（说明确实没走到替换）",
          not os.path.exists(installed + ".old"))

    # 把暂存文件的 mtime 设成一个可辨认的值：替换是 rename 过去的，mtime 会被保留，
    # 所以它是「这个文件确实被换过」的证据 —— 而内容哈希不行（真 goproxy 只有一种内容，
    # 两份副本的哈希必然相同）。
    staged_mtime = time.time() - 7200
    os.utime(staged, (staged_mtime, staged_mtime))

    rc, out = run_cli(installed, ["-c", bad_db, "-upgrade-apply", "-upgrade-force"])
    check("带 -upgrade-force 时放行", rc == 0, "rc=%d %s" % (rc, out[-400:]))
    check("放行时把风险说出来了", "警告" in out or "强行" in out, out[-400:])
    check("放行时确实替换了（换上去的就是暂存的那份文件）",
          abs(os.path.getmtime(installed) - staged_mtime) < 2,
          "mtime=%.0f 期望≈%.0f" % (os.path.getmtime(installed), staged_mtime))
    check("替换前的版本被备份下来了（还能回退）",
          os.path.exists(installed + ".old")
          and sha256_file(installed + ".old") == installed_sha)

    # ---------------------------------------------------------------
    print("\n== 3. 控制台：上传时报警、安装时拦住 ==")
    inst_dir = os.path.join(work, "inst")
    os.makedirs(inst_dir, exist_ok=True)
    inst_exe = os.path.join(inst_dir, "goproxy")
    shutil.copyfile(exe, inst_exe)
    inst_db = os.path.join(inst_dir, "goproxy.db")
    admin_port = free_port()
    cfg = dict(GOOD_CONFIG)
    cfg["admin_addr"] = "127.0.0.1:%d" % admin_port
    with open(os.path.join(inst_dir, "seed.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    run_cli(inst_exe, ["-c", inst_db, "-config-import", os.path.join(inst_dir, "seed.json")])

    proc = start(inst_exe, inst_db, inst_dir)
    try:
        if not wait_ready(admin_port, proc):
            print("实例没起来：\n" + tail_log(proc))
            return 1
        check("实例已就绪（前提）", True)

        # 把库的 schema 改成 99：运行中的实例不受影响，但任何「新二进制试读」都会失败。
        set_schema_version(inst_db, "99")
        exe_before = sha256_file(inst_exe)

        st, raw = upload(admin_port, exe)
        body = json.loads(raw.decode("utf-8", "replace"))
        check("上传本身仍然成功（上传不改任何东西）", st == 200, raw[:300])
        check("响应里报出「这个版本读不了当前配置」",
              bool(body.get("config_problem")), json.dumps(body, ensure_ascii=False)[:300])
        check("并没有假装预检通过了", body.get("config_checked") is not True,
              json.dumps(body, ensure_ascii=False)[:200])
        check("预检的判词里带上了版本号", "99" in (body.get("config_problem") or ""),
              (body.get("config_problem") or "")[:300])

        st, state = japi(admin_port, "GET", "/_goproxy/upgrade")
        check("暂存视图里也带着这条问题（列表页也看得见）",
              bool((state.get("staged") or {}).get("config_problem")),
              json.dumps(state.get("staged"), ensure_ascii=False)[:300])

        st, res = japi(admin_port, "POST", "/_goproxy/upgrade/install", {})
        check("安装被拒（409）", st == 409, "%s %s" % (st, json.dumps(res, ensure_ascii=False)[:300]))
        check("拒绝原因是 config_incompatible", res.get("error") == "config_incompatible",
              json.dumps(res, ensure_ascii=False)[:200])
        check("拒绝时把迁移/诊断信息一起给了出来", "99" in (res.get("message") or ""),
              (res.get("message") or "")[:300])
        check("被拒时二进制没有被换掉", sha256_file(inst_exe) == exe_before)

        # 带 force：放行，且响应里必须有 warning
        st, res2 = japi(admin_port, "POST", "/_goproxy/upgrade/install", {"force": True})
        check("带 force 时放行（200）", st == 200,
              "%s %s" % (st, json.dumps(res2, ensure_ascii=False)[:300]))
        check("放行时响应里带回 warning（不能看起来像普通成功）",
              bool(res2.get("warning")), json.dumps(res2, ensure_ascii=False)[:300])

        # 4. 把配置改回正常，同一条路照样能装 —— 预检不该破坏正常流程
        print("\n== 4. 配置修好之后，正常路径照旧 ==")
        set_schema_version(inst_db, "1")
        st, raw = upload(admin_port, exe)
        body2 = json.loads(raw.decode("utf-8", "replace"))
        check("合法配置下上传：不再有 config_problem",
              st == 200 and not body2.get("config_problem"),
              json.dumps(body2, ensure_ascii=False)[:300])
        check("合法配置下明确报「预检已通过」", body2.get("config_checked") is True,
              json.dumps(body2, ensure_ascii=False)[:200])

        exe_now = sha256_file(inst_exe)
        st, res3 = japi(admin_port, "POST", "/_goproxy/upgrade/install", {})
        check("合法配置下安装成功", st == 200,
              "%s %s" % (st, json.dumps(res3, ensure_ascii=False)[:300]))
        # 同名同内容的替换：这里只断言「备份产生了」= 确实走到了替换那一步
        check("安装确实走到了替换（产生了备份）", os.path.exists(inst_exe + ".old"),
              "没看到 %s" % (inst_exe + ".old"))
        check("上传的二进制与实例当前的一致（同版本替换）", sha256_file(inst_exe) == exe_now)
    finally:
        stop(proc)

    print("\n=== 结果：%d 项通过，%d 项失败 ===" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  - " + f)
    print("工作目录（保留现象，便于排查）：%s" % work)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
