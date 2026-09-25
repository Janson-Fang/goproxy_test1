"""一次性校验脚本：确认每个 Release 的正文来自 annotated tag 的说明，
而不是提交信息（v0.6.1 / v0.7.0 曾因 CI 读本地 refs/tags 而误取提交信息）。

不属于发布流程，仅用于人工复核。运行：

    python scripts/check_release_notes.py         # 核对全部 Release
    python scripts/check_release_notes.py v0.13.0 # 只核对某一个（发布后常用）

带参数这个模式是后加的：每次发布后只关心刚发的那个版本，而全量核对要按
「每个版本 3 次 API 调用」走一遍历史（十几个版本 ≈ 40 次）—— 在走代理的机器上
能跑两分钟，期间任何一次请求抖动都会让整次核对无果而终。

凭据：默认**匿名**读（公开仓库足够）。私有仓库用 `GITHUB_TOKEN=xxx` 显式给 ——
刻意不走 `git credential fill`，理由见 token() 的说明（它会弹确认窗口，无人值守时必卡）。
"""
import json
import os
import subprocess
import urllib.error
import urllib.request
import sys

REPO = ""
API = ""

# 凭据只取一次。
#
# 之前是在 api() 里现取，于是每个请求都 fork 一次 `git credential fill` ——
# 全量核对就是四十来次子进程。实测这在本机是有代价的：某次调用卡了 30 秒，
# 直接让整次核对以超时告终，而它本来只是去问一个一直没变的 token。
_TOKEN = ""


def token() -> str:
    """取凭据。**取不到不是错误** —— 本脚本读的全是公开只读信息。

    顺序：环境变量 → 匿名。

    刻意不走 `git credential fill`：它会**弹出「确认授权」的窗口**，
    而这脚本经常在没有交互终端的地方跑（子进程 / 沙箱 / 后台任务）——
    没人点那个窗口，它就一直等：实测卡满 120 秒，整次核对无果而终，
    而且报出来的是一段 subprocess 超时的 traceback，看不出卡在哪一步。
    （以前这里就是每请求调一次它，40 次调用里任何一次抽风都能让核对白跑。）
    需要鉴权时（私有仓库）用 GITHUB_TOKEN 环境变量显式给。
    """
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    for env in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(env, "").strip()
        if v:
            _TOKEN = v
            return _TOKEN
    _TOKEN = ANONYMOUS
    return _TOKEN


# 匿名标记：与「有 token」区分开，好让 api() 决定加不加 Authorization 头。
ANONYMOUS = "\x00anonymous"



def remote_repo() -> str:
    """从 origin 推出 owner/repo，避免把仓库名写死。"""
    url = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    slug = url.rsplit("github.com", 1)[-1].lstrip(":/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    if "/" not in slug:
        sys.exit("无法从 origin 解析 owner/repo：" + url)
    return slug


def api(path: str):
    req = urllib.request.Request(API + path)
    tok = token()
    if tok != ANONYMOUS:
        req.add_header("Authorization", "token " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "release-notes-check")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # 公开仓库匿名读就够了（每小时 60 次，本脚本约 40 次）。
        # 401/404 基本都是「这是个私有仓库」，得说明白怎么办。
        if e.code in (401, 404) and tok == ANONYMOUS:
            sys.exit(f"{path} 返回 {e.code}：匿名读不到这个仓库（私有仓库？）。\n"
                     "用 GITHUB_TOKEN=xxx python scripts/check_release_notes.py 重跑 ——\n"
                     "不要依赖 git credential fill：它会弹确认窗口，无人值守时必然卡住。")
        if e.code == 403 and tok == ANONYMOUS:
            sys.exit(f"{path} 返回 403：匿名额度用完（每小时 60 次）。\n"
                     "用 GITHUB_TOKEN=xxx 重跑，或等一小时后重试。")
        raise


def body_after_title(msg: str) -> str:
    """tag message 第一行是标题，正文从第二行起（与 CI 的 tail -n +2 一致）。"""
    return msg.split("\n", 1)[1].lstrip("\n").rstrip() if "\n" in msg else ""


def main() -> int:
    global REPO, API
    REPO = remote_repo()
    API = "https://api.github.com/repos/" + REPO
    print("仓库", REPO)

    # 可选参数：只核对一个 tag（发布后最常用）。
    # 不传就把历史全过一遍 —— 那是「想确认整段历史都没错」时才需要的。
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    if only:
        if not only.startswith("v"):
            only = "v" + only
        releases = [api("/releases/tags/" + only)]
        print("只核对", only)
    else:
        releases = api("/releases?per_page=50")

    print(f"{'tag':8} {'release':>8} {'tag正文':>8} {'commit':>7}  判定")
    bad = []
    for rel in sorted(releases, key=lambda r: tuple(int(x) for x in r["tag_name"].lstrip("v").split("."))):
        tag = rel["tag_name"]
        ref = api("/git/ref/tags/" + tag)
        if ref["object"]["type"] != "tag":
            print(f"{tag:8} {len(rel['body'] or ''):>8} {'-':>8} {'-':>7}  ? 轻量标签，本无说明")
            continue
        tobj = api("/git/tags/" + ref["object"]["sha"])
        notes = body_after_title(tobj["message"])
        # 注意走的是 Git Data API（/git/commits/{sha}），message 在**顶层**；
        # /repos/{o}/{r}/commits/{ref} 才把 message 嵌在 commit 里 —— 用错路径
        # 只会静默拿到空字符串，比对形同虚设。
        commit = api("/git/commits/" + tobj["object"]["sha"])
        cmsg = body_after_title(commit.get("message", ""))
        body = rel["body"] or ""

        has_notes = bool(notes) and notes[:60] in body
        has_commit = bool(cmsg) and cmsg[:60] in body
        if has_notes and not has_commit:
            verdict = "正确（tag 说明）"
        elif has_commit:
            verdict = "❌ 错误（取到了提交信息）"
            bad.append(tag)
        elif not notes:
            # tag 只有标题、没写正文，那 Release 只剩 auto changelog 是正常的。
            verdict = "— 该 tag 本就没写说明，仅 changelog"
        else:
            verdict = "⚠ 正文里找不到 tag 说明"
            bad.append(tag)
        print(f"{tag:8} {len(body):>8} {len(notes):>8} {len(cmsg):>7}  {verdict}")

    print()
    if bad:
        print("以下版本正文来源有问题：", ", ".join(bad))
        return 1
    print("全部版本正文均来自 annotated tag 说明 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
