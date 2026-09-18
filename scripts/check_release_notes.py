"""一次性校验脚本：确认每个 Release 的正文来自 annotated tag 的说明，
而不是提交信息（v0.6.1 / v0.7.0 曾因 CI 读本地 refs/tags 而误取提交信息）。

不属于发布流程，仅用于人工复核。运行：
    python scripts/_check_release_notes.py
"""
import json
import subprocess
import urllib.request
import sys

REPO = ""
API = ""


def token() -> str:
    out = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True, timeout=30,
    ).stdout
    for line in out.splitlines():
        if line.startswith("password="):
            return line[9:]
    sys.exit("拿不到 GitHub token（git credential fill 里没有 github.com 的凭据）")


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
    req.add_header("Authorization", "token " + token())
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "release-notes-check")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def body_after_title(msg: str) -> str:
    """tag message 第一行是标题，正文从第二行起（与 CI 的 tail -n +2 一致）。"""
    return msg.split("\n", 1)[1].lstrip("\n").rstrip() if "\n" in msg else ""


def main() -> int:
    global REPO, API
    REPO = remote_repo()
    API = "https://api.github.com/repos/" + REPO
    print("仓库", REPO)
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
