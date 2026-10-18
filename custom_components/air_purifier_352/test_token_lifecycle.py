"""离线自测：令牌生命周期逻辑（不依赖 HA / 网络）。

验证 ensure_tokens 的分支决策：
1. 令牌都新鲜 → 不做任何操作
2. access_token 过期 + 有账密 → 完整重登
3. iotToken 临近过期 → 先试 refresh，成功则不再重登
4. refresh 失败 + 有账密 → 回退到完整重登
5. 无账密且 refresh 失败 → 抛 AuthError
"""
from __future__ import annotations

import asyncio
import sys
import time

# 允许直接导入被测逻辑（避开 aiohttp/HA 依赖，复制关键判断）
IOT_TOKEN_REFRESH_MARGIN = 3600
ACCESS_TOKEN_REFRESH_MARGIN = 86400
IOT_EXPIRE_MS = 72000      # 20 小时
ACCESS_EXPIRE_MS = 5184000  # 60 天


class FakeClient:
    """复刻 AilinkApiClient 的令牌判断与 ensure_tokens 分支。"""

    def __init__(self, access_token="", iot_token="",
                 access_age=0.0, iot_age=0.0, refresh_ok=True):
        self.access_token = access_token
        self.iot_token = iot_token
        self._access_token_time = time.time() - access_age
        self._iot_token_time = time.time() - iot_age
        self._refresh_ok = refresh_ok
        self.calls: list[str] = []

    def iot_token_stale(self) -> bool:
        if not self.iot_token:
            return True
        return (time.time() - self._iot_token_time) > (IOT_EXPIRE_MS - IOT_TOKEN_REFRESH_MARGIN)

    def access_token_stale(self) -> bool:
        if not self.access_token:
            return True
        return (time.time() - self._access_token_time) > (ACCESS_EXPIRE_MS - ACCESS_TOKEN_REFRESH_MARGIN)

    async def refresh_iot_token(self) -> bool:
        self.calls.append("refresh_iot")
        if self._refresh_ok:
            self.iot_token = "NEW_IOT"
            self._iot_token_time = time.time()
        return self._refresh_ok

    async def full_login(self, account="", password=""):
        self.calls.append("full_login")
        self.access_token = "NEW_ACCESS"
        self.iot_token = "NEW_IOT"
        self._access_token_time = time.time()
        self._iot_token_time = time.time()

    async def ensure_tokens(self, account="", password=""):
        if not self.access_token_stale() and not self.iot_token_stale():
            return
        if self.access_token_stale() and account and password:
            await self.full_login(account, password)
            return
        if self.iot_token_stale() and await self.refresh_iot_token():
            return
        if account and password:
            await self.full_login(account, password)
        else:
            raise RuntimeError("令牌已过期且未提供账号密码")


results: list[bool] = []


def check(name: str, cond: bool) -> None:
    results.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


async def main() -> int:
    print("=" * 70)
    print("场景 1：令牌都新鲜（刚登录 1 小时）")
    c = FakeClient("A", "I", access_age=3600, iot_age=3600)
    await c.ensure_tokens("u", "p")
    check("不触发任何调用", c.calls == [])

    print()
    print("=" * 70)
    print("场景 2：access_token 过期 + 有账密 → 完整重登")
    c = FakeClient("A", "I", access_age=ACCESS_EXPIRE_MS, iot_age=100)
    await c.ensure_tokens("u", "p")
    check("调用 full_login", c.calls == ["full_login"])
    check("access_token 已更新", c.access_token == "NEW_ACCESS")

    print()
    print("=" * 70)
    print("场景 3：iotToken 临近过期 → 先 refresh，成功则不重登")
    # iot 已过 19.5 小时，超过阈值（19 小时）
    c = FakeClient("A", "I", access_age=3600, iot_age=19.5 * 3600)
    await c.ensure_tokens("u", "p")
    check("只调用 refresh_iot", c.calls == ["refresh_iot"])
    check("iot_token 已更新", c.iot_token == "NEW_IOT")

    print()
    print("=" * 70)
    print("场景 4：refresh 失败 + 有账密 → 回退完整重登")
    c = FakeClient("A", "I", access_age=3600, iot_age=19.5 * 3600, refresh_ok=False)
    await c.ensure_tokens("u", "p")
    check("先 refresh 后 full_login", c.calls == ["refresh_iot", "full_login"])
    check("最终拿到新 iot_token", c.iot_token == "NEW_IOT")

    print()
    print("=" * 70)
    print("场景 5：无账密且 refresh 失败 → 抛异常")
    c = FakeClient("A", "I", access_age=3600, iot_age=19.5 * 3600, refresh_ok=False)
    raised = False
    try:
        await c.ensure_tokens("", "")
    except RuntimeError:
        raised = True
    check("抛出异常", raised)

    print()
    print("=" * 70)
    print("场景 6：iotToken 边界（18.9h 不算过期，19.1h 算）")
    c1 = FakeClient("A", "I", access_age=0, iot_age=18.9 * 3600)
    check("18.9h 不 stale", not c1.iot_token_stale())
    c2 = FakeClient("A", "I", access_age=0, iot_age=19.1 * 3600)
    check("19.1h 算 stale", c2.iot_token_stale())

    print()
    print("=" * 70)
    print("场景 7：access_token 边界（有效期 60 天，提前 1 天刷新）")
    c1 = FakeClient("A", "I", access_age=58 * 86400, iot_age=0)
    check("58 天不 stale", not c1.access_token_stale())
    c2 = FakeClient("A", "I", access_age=59.5 * 86400, iot_age=0)
    check("59.5 天算 stale", c2.access_token_stale())

    print()
    print("=" * 70)
    passed = sum(1 for r in results if r)
    print(f"结果: {passed}/{len(results)} 通过")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
