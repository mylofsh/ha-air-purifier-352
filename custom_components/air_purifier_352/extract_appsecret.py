#!/usr/bin/env python3
"""从 352 App 的 APK 中提取阿里云网关的 appSecret。

用法:
    /tmp/.venv_apk/bin/python extract_appsecret.py /path/to/352air.apk

原理:
    阿里云 API 网关的签名密钥 (appSecret) 通常以字符串常量形式硬编码在
    App 中，常与 appKey(27549861) 出现在同一个类/字符串池里。本脚本：
      1. 扫描 DEX 全部字符串常量，找 appKey 及其邻近字符串
      2. 找形似密钥的 32/64 位 hex、base64 字符串
      3. 对候选密钥，用真实抓包样本做 HmacSHA1 回归验证 —— 能对上的就是真密钥

输出:
    找到密钥时直接打印，并写入 appsecret_result.json
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path

APP_KEY = "27549861"

# 真实抓包样本（用于回归验证候选密钥）
SAMPLES = [
    {
        "label": "thing/properties/get",
        "method": "POST",
        "path": "/thing/properties/get",
        "body": '{"id":"F9C2621C-3796-45B5-AB9E-E3D5626D9F2B","params":{"iotId":"9JgBneytEkLCmbfkjh4O000000"},"request":{"language":"zh-CN","appKey":"27549861","iotToken":"d8a7ea5f5700054bee254c50073f014b","apiVer":"1.0.2"},"version":"1.0.0"}',
        "accept": "application/json; charset=UTF-8",
        "content_type": "application/json; charset=UTF-8",
        "date": "Wed, 07 Oct 2026 15:20:32 GMT+8",
        "nonce": "59ED2516-1431-41E6-B513-9AD42122CFE3",
        "timestamp": "1791357632447",
        "signature": "EotKRNdCnNdIzrtuf4aBmxjWwtQ=",
    },
    {
        "label": "living/thing/properties/set",
        "method": "POST",
        "path": "/living/thing/properties/set",
        "body": '{"id":"0FFF1672-30D4-4C25-A826-52F186D0996A","params":{"iotId":"9JgBneytEkLCmbfkjh4O000000","items":{"PowerSwitch":0}},"request":{"language":"zh-CN","appKey":"27549861","iotToken":"d8a7ea5f5700054bee254c50073f014b","apiVer":"1.0.0"},"version":"1.0.0"}',
        "accept": "application/json; charset=UTF-8",
        "content_type": "application/json; charset=UTF-8",
        "date": "Wed, 07 Oct 2026 15:26:32 GMT+8",
        "nonce": "51FC5449-EBA2-4FFE-A679-7540CF6D6E1F",
        "timestamp": "1791357632751",
        "signature": "MI3Bq0NJcdNMd+WXMjCyYyXEJbM=",
    },
]


def build_string_to_sign(s: dict) -> str:
    """复刻阿里云网关的 string_to_sign。"""
    body = s["body"].encode()
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    signed_lines = (
        "X-Ca-Version:1\n"
        f"X-Ca-Nonce:{s['nonce']}\n"
        f"X-Ca-Timestamp:{s['timestamp']}\n"
        "X-Ca-Stage:RELEASE\n"
        f"X-Ca-Key:{APP_KEY}"
    )
    return (
        s["method"] + "\n" +
        s["accept"] + "\n" +
        md5 + "\n" +
        s["content_type"] + "\n" +
        s["date"] + "\n" +
        signed_lines + "\n" +
        s["path"]
    )


def verify_secret(secret: str) -> bool:
    """用抓包样本验证候选密钥是否正确。"""
    for s in SAMPLES:
        sts = build_string_to_sign(s)
        sig = base64.b64encode(
            hmac.new(secret.encode(), sts.encode(), hashlib.sha1).digest()
        ).decode()
        if sig != s["signature"]:
            return False
    return True


# 密钥候选的形态
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
B64LIKE = re.compile(r"^[A-Za-z0-9+/=_-]{16,64}$")
ALNUM32 = re.compile(r"^[A-Za-z0-9]{32}$")


def looks_like_secret(s: str) -> bool:
    if not s or len(s) < 16 or len(s) > 64:
        return False
    if " " in s or "\n" in s:
        return False
    return bool(
        HEX32.match(s) or HEX64.match(s) or ALNUM32.match(s) or B64LIKE.match(s)
    )


def scan_apk(apk_path: str) -> dict:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    print(f"[*] 解析 APK: {apk_path}")
    apk = APK(apk_path)
    print(f"    包名: {apk.get_package()}")
    print(f"    版本: {apk.get_androidversion_name()} ({apk.get_androidversion_code()})")

    all_strings: set[str] = set()
    appkey_context: list[str] = []

    dex_files = [n for n in apk.get_files() if n.endswith(".dex")]
    print(f"[*] 发现 {len(dex_files)} 个 DEX 文件")

    for name in dex_files:
        print(f"    扫描 {name} ...")
        raw = apk.get_file(name)
        d = DEX(raw)
        strs = d.get_strings()
        for s in strs:
            try:
                v = s.get()
            except Exception:  # noqa: BLE001
                continue
            if not v:
                continue
            all_strings.add(v)

    print(f"[*] 收集到 {len(all_strings)} 个字符串常量")

    # 找 appKey 上下文：同 DEX 内相邻字符串
    for name in dex_files:
        raw = apk.get_file(name)
        d = DEX(raw)
        for s in d.get_strings():
            try:
                v = s.get()
            except Exception:  # noqa: BLE001
                continue
            if v and APP_KEY in v:
                appkey_context.append(v)

    return {
        "package": apk.get_package(),
        "version": apk.get_androidversion_name(),
        "strings": all_strings,
        "appkey_context": appkey_context,
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    apk_path = sys.argv[1]
    if not os.path.exists(apk_path):
        print(f"[!] 文件不存在: {apk_path}")
        return 1

    info = scan_apk(apk_path)
    strings = info["strings"]

    print()
    print("=" * 70)
    print("appKey 上下文")
    print("=" * 70)
    for v in info["appkey_context"][:20]:
        print(f"  {v[:160]}")

    # 候选收集
    candidates: list[str] = []

    # 1. 与 appKey 同处一个字符串的（形如 "27549861xxx" 或 url 里带 key）
    for v in info["appkey_context"]:
        for tok in re.findall(r"[A-Za-z0-9+/=_\-]{16,64}", v):
            if tok != APP_KEY and looks_like_secret(tok):
                candidates.append(tok)

    # 2. 所有形似密钥的字符串
    for v in strings:
        if looks_like_secret(v) and v != APP_KEY:
            candidates.append(v)

    # 去重保序
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    print()
    print("=" * 70)
    print(f"候选密钥 {len(uniq)} 个，开始用抓包样本验证")
    print("=" * 70)

    found = None
    for c in uniq:
        if verify_secret(c):
            found = c
            print(f"  *** 命中 *** {c}")
            break

    if not found:
        # 也试一下常见的变换
        print("  直接候选未命中，尝试常见变换（大小写/前后缀）...")
        for c in uniq[:400]:
            for variant in (c.upper(), c.lower(), c + "&", c.rstrip("=")):
                if variant != c and verify_secret(variant):
                    found = variant
                    print(f"  *** 命中（变换后）*** {variant}")
                    break
            if found:
                break

    result = {
        "apk": str(apk_path),
        "package": info["package"],
        "version": info["version"],
        "app_secret": found,
        "tried_candidates": len(uniq),
        "appkey_context": info["appkey_context"][:20],
    }

    out = Path("appsecret_result.json")
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    if found:
        print(f"✓ 找到 appSecret: {found}")
        print("  请填入 HA 集成配置 → 352 空气净化器 → appSecret")
    else:
        print("✗ 未在字符串常量中找到可验证的 appSecret")
        print("  可能原因：密钥做了混淆/加密，或通过 native 层计算")
        print("  建议改用 jadx 反编译后人工排查，或 frida hook HmacSHA1 调用")
    print(f"  结果已写入 {out}")
    return 0 if found else 2


if __name__ == "__main__":
    sys.exit(main())
