# -*- coding: utf-8 -*-
"""keygen.py 核心逻辑测试"""
import os
import secrets
import string
import sys

import keygen as kg

# Windows GBK 控制台下中文会乱码/崩溃，统一改为 UTF-8（与 keygen.py 的处理一致）
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print("PASS", name)
    else:
        failed += 1
        print("FAIL", name)

SEED = bytes(range(32))
SETS = kg.SETS
CONFUSABLE = kg.CONFUSABLE
SYMBOL_RE = SETS["symbol"]


def rand_opts():
    """随机组合：至少一种字符集、随机长度 8~64"""
    keys = secrets.SystemRandom().sample(
        ["lower", "upper", "digit", "symbol"], secrets.randbelow(3) + 1)
    opts = {k: k in keys for k in ("lower", "upper", "digit", "symbol")}
    opts["no_confuse"] = secrets.randbelow(2) == 1
    opts["len"] = secrets.randbelow(57) + 8
    return opts


# 1. 确定性：相同输入 → 相同输出
pw1 = kg.build_password(SEED, "微信", "1380000", 1,
                        {"lower": True, "upper": True, "digit": True,
                         "symbol": True, "no_confuse": False, "len": 16})
pw2 = kg.build_password(SEED, "微信", "1380000", 1,
                        {"lower": True, "upper": True, "digit": True,
                         "symbol": True, "no_confuse": False, "len": 16})
check("相同输入 → 输出一致", pw1 == pw2)
print("  示例密钥:", pw1)

# 2. 约束满足：长度、字符范围、每类至少一个
parts, alphabet = kg.alphabet_of({"lower": True, "upper": True, "digit": True,
                                  "symbol": True, "no_confuse": False, "len": 16})
check("长度 = 16", len(pw1) == 16)
check("字符全部在选项范围内", all(c in alphabet for c in pw1))
check("小写/大写/数字/符号各至少一个",
      all(any(c in part for c in pw1) for part in parts))

# 3. 版本号改变 → 密钥改变
pw3 = kg.build_password(SEED, "微信", "1380000", 2,
                        {"lower": True, "upper": True, "digit": True,
                         "symbol": True, "no_confuse": False, "len": 16})
check("版本号改变 → 新密钥", pw1 != pw3)

# 4. 站点不同 → 密钥不同
pw4 = kg.build_password(SEED, "淘宝", "1380000", 1,
                        {"lower": True, "upper": True, "digit": True,
                         "symbol": True, "no_confuse": False, "len": 16})
check("站点不同 → 密钥不同", pw1 != pw4)

# 5. 种子不同 → 密钥不同
pw5 = kg.build_password(bytes(range(1, 33)), "微信", "1380000", 1,
                        {"lower": True, "upper": True, "digit": True,
                         "symbol": True, "no_confuse": False, "len": 16})
check("种子不同 → 密钥不同", pw1 != pw5)

# 6. 长度边界 8 / 64
check("长度边界 8/64",
      len(kg.build_password(SEED, "t", "a", 1,
                            {"lower": True, "upper": True, "digit": True,
                             "symbol": True, "no_confuse": False, "len": 8})) == 8
      and len(kg.build_password(SEED, "t", "a", 9,
                                {"lower": True, "upper": True, "digit": True,
                                 "symbol": True, "no_confuse": False, "len": 64})) == 64)

# 7. 随机组合属性测试（200 组）：长度正确、范围正确、每个选中字符集至少出现一次
ok = True
for _ in range(200):
    opts = rand_opts()
    pw = kg.build_password(SEED, "随机", "测试", 1, opts)
    parts, alphabet = kg.alphabet_of(opts)
    if len(pw) != opts["len"] or any(c not in alphabet for c in pw):
        ok = False
        print("  ✘ 失败组合:", opts, "→", pw)
        break
    if not all(any(c in part for c in pw) for part in parts):
        ok = False
        print("  ✘ 字符集缺失:", opts, "→", pw)
        break
    if opts["no_confuse"] and any(c in CONFUSABLE for c in pw):
        ok = False
        print("  ✘ 混入易混字符:", opts, "→", pw)
        break
check("200 组随机组合属性全部满足", ok)

# 8. 纯数字模式（排除易混）
pw6 = kg.build_password(SEED, "银行卡", "x", 1,
                        {"lower": False, "upper": False, "digit": True,
                         "symbol": False, "no_confuse": True, "len": 12})
check("纯数字模式输出全为非易混数字", all(c in "23456789" for c in pw6) and len(pw6) == 12)

# 9. norm 归一化
check("空白归一化", kg.norm("  微信\t  app ") == "微信 app")

# 10. 熵估算
check("entropy_bits(16, 全字符集) ≈ 100~108",
      100 <= kg.entropy_bits({"lower": True, "upper": True, "digit": True,
                              "symbol": True, "no_confuse": False, "len": 16}) <= 108)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
