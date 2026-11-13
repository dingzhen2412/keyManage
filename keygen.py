#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥生成器 · 初级版（Python 命令行）

设计要点（与网页版规格一致）：
  · 专属随机种子只在首次运行时生成一次，永久固定保存在本机，用户不需要记住它
  · 生成密钥：站名 + 账号 + 长度 + 字符选项；重新生成会自动把版本号 +1，产生新密钥
  · 读取密钥：只需 站名 + 账号，当时的选项和版本号由软件保管的档案复现
  · 全程本地计算，不联网；密文确定性——同样输入永远得到同样密钥

用法：
  py keygen.py                 # 交互模式（普通人用这个）
  py keygen.py gen 站名 账号    # 命令行模式
  py keygen.py read 站名 账号
  py keygen.py rotate 站名 账号
  py keygen.py list
  py keygen.py export / import 备份.json / reset
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime

APP_ID = "keygen-python-experiment"
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keygen.json")
BACKUP_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keygen-backup.json")

SETS = {
    "lower":  "abcdefghijklmnopqrstuvwxyz",
    "upper":  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digit":  "0123456789",
    "symbol": "!@#$%^&*()-_=+[]{}?~",
}
CONFUSABLE = "0O1lI"
MIN_LEN, MAX_LEN, DEFAULT_LEN = 8, 64, 16


# ---------------- 存储：种子 + 各站档案 ----------------

def save_data(data: dict) -> None:
    with open(STORE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_data() -> dict:
    """读取本机档案；首次运行时生成 256 位随机种子并立即定死。"""
    if os.path.exists(STORE):
        try:
            with open(STORE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if (data.get("app") == APP_ID and isinstance(data.get("seed"), str)
                    and isinstance(data.get("entries"), dict)):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    # —— 首次启动：生成一次，永久固定 ——
    seed = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    data = {"app": APP_ID, "seed": seed, "entries": {}}
    save_data(data)
    return data


def seed_bytes(data: dict) -> bytes:
    s = data["seed"].replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def seed_fingerprint(data: dict) -> str:
    return "·".join(f"{b:02X}" for b in seed_bytes(data)[:4])


def entry_key(site: str, account: str) -> str:
    return site + "\t" + account


def norm(s: str) -> str:
    return " ".join(s.split())


def ts_str(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ---------------- 核心算法（纯函数） ----------------

def make_stream(seed: bytes, base: bytes):
    """由 HMAC 输出构造确定性字节流（要多少字节都够）"""
    counter = 0
    while True:
        block = hmac.new(seed, base + b"|" + str(counter).encode(), hashlib.sha256).digest()
        counter += 1
        for b in block:
            yield b


def alphabet_of(opts: dict):
    def filtr(s: str):
        return [c for c in s if not opts.get("no_confuse") or c not in CONFUSABLE]

    parts = []
    if opts.get("lower"):
        parts.append(filtr(SETS["lower"]))
    if opts.get("upper"):
        parts.append(filtr(SETS["upper"]))
    if opts.get("digit"):
        parts.append(filtr(SETS["digit"]))
    if opts.get("symbol"):
        parts.append(filtr(SETS["symbol"]))
    all_chars = list(dict.fromkeys(c for part in parts for c in part))  # 去重、保持顺序
    return parts, all_chars


def build_password(seed: bytes, site: str, account: str, version: int, opts: dict) -> str:
    """确定性生成密钥：
       1) 每个字符从"选项字符表"中按字节流选取
       2) 保证每个选中的字符集至少出现一次（位置也由同一字节流决定）"""
    parts, alphabet = alphabet_of(opts)
    stream = make_stream(seed, f"{site}|{account}|v{version}".encode("utf-8"))
    chars = [alphabet[next(stream) % len(alphabet)] for _ in range(opts["len"])]
    positions = list(range(len(chars)))
    for part in parts:
        p = positions.pop(next(stream) % len(positions))
        chars[p] = part[next(stream) % len(part)]
    return "".join(chars)


def entropy_bits(opts: dict) -> int:
    _, alphabet = alphabet_of(opts)
    return round(opts["len"] * math.log2(len(alphabet)))


def opt_summary(opts: dict) -> str:
    names = []
    if opts.get("lower"): names.append("小写")
    if opts.get("upper"): names.append("大写")
    if opts.get("digit"): names.append("数字")
    if opts.get("symbol"): names.append("符号")
    if opts.get("no_confuse"): names.append("已排除易混字符")
    return f"{opts['len']} 位 · {'/'.join(names)}"


# ---------------- 工具 ----------------

def copy_clipboard(text: str) -> bool:
    try:
        if sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=text.encode("utf-8"), check=True)
        return True
    except Exception:
        return False


def ask(prompt: str, default: str = "") -> str:
    try:
        s = input(prompt).strip()
    except EOFError:          # 无 stdin 的脚本环境，静默采用默认值
        return default
    return s or default


def ask_yes(prompt: str, default: bool = True) -> bool:
    s = ask(f"{prompt} [{'y/n' if default else 'n/y'}]: ").lower()
    if not s:
        return default
    return s in ("y", "yes", "是")


def read_opts() -> dict:
    """生成交互输入：长度 + 字符选项（每次生成时都由用户填，软件默默存档）"""
    while True:
        s = ask(f"密钥长度（{MIN_LEN}~{MAX_LEN}，回车=默认 {DEFAULT_LEN}）: ", str(DEFAULT_LEN))
        if s.isdigit() and MIN_LEN <= int(s) <= MAX_LEN:
            length = int(s)
            break
        print(f"  ✘ 请输入 {MIN_LEN}~{MAX_LEN} 之间的数字")
    while True:
        s = ask("字符集 [a]小写 [b]大写 [c]数字 [d]符号（回车=全部；也可输入组合如 acd）: ", "abcd").lower()
        picked = "".join(c for c in "abcd" if c in s)
        if picked:
            opts = {"lower": "a" in picked, "upper": "b" in picked,
                    "digit": "c" in picked, "symbol": "d" in picked}
            break
        print("  ✘ 至少选择一种字符集")
    opts["no_confuse"] = ask_yes("排除易混淆字符（0 O 1 l I）？", default=False)
    opts["len"] = length
    return opts


def show_entry(pw: str, entry: dict, prefix: str = "") -> None:
    print(f"{prefix}密钥：{pw}")
    print(f"{prefix}规格：{opt_summary(entry['opts'])} · 版本 v{entry['version']}"
          f" · 理论强度 {entropy_bits(entry['opts'])} bits"
          f" · 创建于 {ts_str(entry['created'])}")


# ---------------- 命令实现 ----------------

def do_gen(data: dict, site: str, account: str, opts: dict, yes: bool) -> dict:
    """生成（或重新生成）。重新生成时把版本号 +1，旧密钥作废。"""
    key = entry_key(site, account)
    existing = data["entries"].get(key)
    if existing and not yes:
        print(f"⚠️「{site}」已存在密码（当前 v{existing['version']}，"
              f"{opt_summary(existing['opts'])}）")
        if not ask_yes("重新生成将作废旧密码，继续？", default=False):
            print("已取消")
            return data
    version = existing["version"] + 1 if existing else 1
    entry = {"site": site, "account": account, "version": version, "opts": opts,
             "created": existing["created"] if existing else int(time.time()),
             "updated": int(time.time())}
    data["entries"][key] = entry
    save_data(data)
    pw = build_password(seed_bytes(data), site, account, version, opts)
    show_entry(pw, entry, prefix="\n")
    if copy_clipboard(pw):
        print("已复制到剪贴板 ✔")
    if existing:
        print("已作废旧密码并生成新密码 ✔")
    return data


def do_read(data: dict, site: str, account: str) -> None:
    entry = data["entries"].get(entry_key(site, account))
    if not entry:
        print(f"✘ 本机没有「{site}」{f'（账号 {account}）' if account else ''} 的生成记录。")
        print("  若你在其他设备生成过，请先用 import 导入备份。")
        return
    pw = build_password(seed_bytes(data), entry["site"], entry["account"],
                        entry["version"], entry["opts"])
    show_entry(pw, entry)
    if ask_yes("\n复制到剪贴板？"):
        if copy_clipboard(pw):
            print("已复制 ✔")


def do_rotate(data: dict, site: str, account: str, yes: bool) -> None:
    """轮换：沿用该站档案里保存的选项，版本号 +1 生成新密钥。"""
    entry = data["entries"].get(entry_key(site, account))
    if not entry:
        print(f"✘ 本机没有「{site}」的生成记录，请先用 gen 生成。")
        return
    do_gen(data, site, account, dict(entry["opts"]), yes)


def do_list(data: dict) -> None:
    entries = data["entries"]
    if not entries:
        print("（还没有生成过任何密钥）")
        return
    print(f"{'站点':<14} {'账号':<20} 版本  规格")
    print("-" * 70)
    for e in entries.values():
        site = e["site"] if len(e["site"]) <= 12 else e["site"][:11] + "…"
        acct = e["account"] if len(e["account"]) <= 18 else e["account"][:17] + "…"
        print(f"{site:<14} {acct:<20} v{e['version']:<4} {opt_summary(e['opts'])}")


def do_export(data: dict, out: str) -> None:
    payload = {"app": APP_ID, "exportedAt": datetime.now().isoformat(timespec="seconds"),
               "seed": data["seed"], "entries": data["entries"]}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"备份已导出：{out}")
    print("⚠️ 备份文件包含你的专属随机种子，请保存在安全的地方。")


def do_import(data: dict, path: str, yes: bool) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not (isinstance(obj, dict) and isinstance(obj.get("seed"), str)
            and isinstance(obj.get("entries"), dict)):
        print("✘ 备份文件格式无效，导入失败")
        return data
    if not yes:
        print(f"将导入：种子（指纹变化）+ {len(obj['entries'])} 条档案，"
              f"并覆盖本机现有 {len(data['entries'])} 条档案。")
        if not ask_yes("确认导入？", default=False):
            print("已取消")
            return data
    data = {"app": APP_ID, "seed": obj["seed"], "entries": obj["entries"]}
    save_data(data)
    print(f"导入成功，现在本机有 {len(data['entries'])} 条档案 ✔")
    return data


def do_reset(data: dict) -> None:
    if ask("确定重置？将删除种子和全部档案。输入「重置」确认：") != "重置":
        print("已取消")
        return
    os.remove(STORE)
    print("已重置，下次启动将生成全新种子。")


# ---------------- 交互模式 ----------------

def interactive() -> None:
    data = load_data()
    print("=" * 50)
    print("密钥生成器 · 初级版（Python 命令行）")
    print(f"✔ 专属随机种子已就绪（指纹 {seed_fingerprint(data)}，保存在本机，无需记忆）")
    print("=" * 50)
    while True:
        print("""
 1. 生成密钥      2. 读取密钥      3. 查看全部档案
 4. 导出备份      5. 导入备份      6. 重置软件      0. 退出""")
        choice = ask("选择> ")
        try:
            if choice == "1":
                site = ask("软件 / 网站名称: ")
                if not site:
                    print("✘ 请填写软件或网站名称")
                    continue
                account = ask("账号名（手机号 / 邮箱 / 用户名，可留空）: ")
                data = do_gen(data, site, account, read_opts(), yes=False)
            elif choice == "2":
                site = ask("软件 / 网站名称: ")
                if not site:
                    print("✘ 请填写软件或网站名称")
                    continue
                account = ask("账号名（可留空）: ")
                do_read(data, site, account)
            elif choice == "3":
                do_list(data)
            elif choice == "4":
                out = ask(f"备份保存到（回车=keygen-backup.json）: ", BACKUP_DEFAULT)
                do_export(data, out)
            elif choice == "5":
                path = ask("备份文件路径: ")
                if path:
                    data = do_import(data, path, yes=False)
            elif choice == "6":
                do_reset(data)
                data = load_data()
                print(f"✔ 新种子已就绪（指纹 {seed_fingerprint(data)}）")
            elif choice in ("0", "q", "exit"):
                break
            else:
                print("✘ 无效选择")
        except KeyboardInterrupt:
            print()
            continue
    print("再见 👋")


# ---------------- 命令行模式 ----------------

def len_type(s: str) -> int:
    try:
        v = int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"长度必须是 {MIN_LEN}~{MAX_LEN} 的数字")
    if not MIN_LEN <= v <= MAX_LEN:
        raise argparse.ArgumentTypeError(f"长度必须在 {MIN_LEN}~{MAX_LEN} 之间")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="密钥生成器 · 初级版")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="生成密钥（同站重复生成将作废旧密钥并升版本）")
    g.add_argument("site")
    g.add_argument("account", nargs="?", default="")
    g.add_argument("--len", dest="length", type=len_type, default=DEFAULT_LEN)
    g.add_argument("--no-lower", action="store_true")
    g.add_argument("--no-upper", action="store_true")
    g.add_argument("--no-digit", action="store_true")
    g.add_argument("--no-symbol", action="store_true")
    g.add_argument("--no-confuse", action="store_true")
    g.add_argument("--yes", action="store_true", help="跳过重新生成确认")

    r = sub.add_parser("read", help="读取密钥（只需站名+账号）")
    r.add_argument("site")
    r.add_argument("account", nargs="?", default="")

    t = sub.add_parser("rotate", help="沿用已有选项轮换密钥（版本号+1）")
    t.add_argument("site")
    t.add_argument("account", nargs="?", default="")
    t.add_argument("--yes", action="store_true")

    sub.add_parser("list", help="查看全部档案")
    e = sub.add_parser("export", help="导出备份")
    e.add_argument("--out", default=BACKUP_DEFAULT)
    i = sub.add_parser("import", help="导入备份（覆盖本机档案）")
    i.add_argument("path")
    i.add_argument("--yes", action="store_true")
    sub.add_parser("reset", help="重置：删除种子与全部档案")

    def opts_from(args):
        return {"lower": not args.no_lower, "upper": not args.no_upper,
                "digit": not args.no_digit, "symbol": not args.no_symbol,
                "no_confuse": args.no_confuse, "len": args.length}

    def run(args):
        data = load_data()
        if args.cmd in ("gen", "read", "rotate"):
            site, account = norm(args.site), norm(getattr(args, "account", ""))
        if args.cmd == "gen":
            do_gen(data, site, account, opts_from(args), args.yes)
        elif args.cmd == "read":
            do_read(data, site, account)
        elif args.cmd == "rotate":
            do_rotate(data, site, account, args.yes)
        elif args.cmd == "list":
            do_list(data)
        elif args.cmd == "export":
            do_export(data, args.out)
        elif args.cmd == "import":
            do_import(data, args.path, args.yes)
        elif args.cmd == "reset":
            do_reset(data)

    p.set_defaults(func=run)
    return p


def main() -> None:
    # Windows 管道/重定向时 stdout 默认是 GBK，统一改为 UTF-8，避免特殊符号崩溃
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if len(sys.argv) > 1:
        args = build_parser().parse_args()
        args.func(args)
    else:
        interactive()


if __name__ == "__main__":
    main()
