"""API client for 352 Air Purifier.

认证链路（2026-10 抓包确认，App v1.9.0）：

  ① POST app.352air.com/api/v1/enduser/login
       {account, password(明文), area:"86", reason}
       → access_token(60天) / refresh_token / air_token

  ② POST api.link.aliyun.com/living/account/region/get
       authCode = 352 access_token, type = THIRD_AUTHCODE
       → regionId（cn-shanghai）

  ③ POST living-account.cn-shanghai.aliyuncs.com/api/prd/loginbyoauth.json
       form: loginByOauthRequest = {...JSON...}
       authCode = 352 access_token, oauthPlateform = 23
       → sid

  ④ POST api.link.aliyun.com/account/createSessionByAuthCode
       authCode = sid, accountType = "OA_SESSION"
       → iotToken(20h) / refreshToken(200h) / identityId

日常接口调用全部走阿里云网关，需 HmacSHA1 签名（见 aliyun_sign）。
"""
from __future__ import annotations

import json
import logging
import time
import urllib.parse
import uuid
from typing import Any

import aiohttp

from .aliyun_sign import build_headers
from .const import (
    ACCESS_TOKEN_REFRESH_MARGIN,
    ALIYUN_BASE,
    ALIYUN_OA_BASE,
    API_352_BASE,
    APP_BUILD_VERSION,
    APP_KEY,
    APP_PLATFORM,
    APP_VERSION,
    CONF_ACCESS_TOKEN,
    CONF_AIR_TOKEN,
    CONF_IDENTITY_ID,
    CONF_IOT_REFRESH_TOKEN,
    CONF_IOT_TOKEN,
    CONF_REFRESH_TOKEN_352,
    IOT_TOKEN_REFRESH_MARGIN,
)

_LOGGER = logging.getLogger(__name__)


class AuthError(Exception):
    """认证失败。"""


class ApiError(Exception):
    """接口调用失败。"""


class AilinkApiClient:
    """352 空气净化器异步客户端。"""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        app_secret: str = "",
        access_token: str = "",
        refresh_token_352: str = "",
        air_token: str = "",
        iot_token: str = "",
        iot_refresh_token: str = "",
        identity_id: str = "",
    ) -> None:
        self._session = session
        self._app_secret = app_secret

        self.access_token = access_token
        self.refresh_token_352 = refresh_token_352
        self.air_token = air_token
        self.iot_token = iot_token
        self.iot_refresh_token = iot_refresh_token
        self.identity_id = identity_id

        # 令牌获得/刷新的时刻（用于判断是否临近过期）
        self._access_token_time = time.time() if access_token else 0.0
        self._iot_token_time = time.time() if iot_token else 0.0

    # ================= 凭据输出（供保存到 config entry） =================

    def credentials(self) -> dict[str, str]:
        """返回当前凭据，供 config entry 持久化。"""
        return {
            CONF_ACCESS_TOKEN: self.access_token,
            CONF_REFRESH_TOKEN_352: self.refresh_token_352,
            CONF_AIR_TOKEN: self.air_token,
            CONF_IOT_TOKEN: self.iot_token,
            CONF_IOT_REFRESH_TOKEN: self.iot_refresh_token,
            CONF_IDENTITY_ID: self.identity_id,
        }

    # ================= ① 352 账号登录 =================

    async def login_352(self, account: str, password: str, area: str = "86") -> dict:
        """用 352 账号密码登录，获取 access_token。"""
        reason = json.dumps(
            {
                "version": APP_VERSION,
                "buildVersion": APP_BUILD_VERSION,
                "platform": APP_PLATFORM,
            },
            separators=(",", ":"),
        )
        body = {
            "password": password,
            "account": account,
            "area": area,
            "reason": reason,
        }
        url = f"{API_352_BASE}/api/v1/enduser/login"
        async with self._session.post(
            url,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise AuthError(f"352 登录 HTTP {resp.status}: {text[:200]}")
            try:
                data = await resp.json(content_type=None)
            except Exception as err:
                raise AuthError(f"352 登录返回非 JSON: {text[:200]}") from err

        if data.get("code") != 0:
            raise AuthError(
                f"352 登录失败: {data.get('message') or data.get('msg') or data}"
            )

        payload = data.get("data") or {}
        self.access_token = payload.get("access_token", "")
        self.refresh_token_352 = payload.get("refresh_token", "")
        self.air_token = payload.get("air_token", "")
        self._access_token_time = time.time()

        if not self.access_token:
            raise AuthError("352 登录成功但未返回 access_token")

        _LOGGER.debug(
            "352 登录成功，access_token 有效期至 %s", payload.get("expires_at")
        )
        return payload

    # ================= ② 查询区域 =================

    async def get_region(self) -> dict:
        """用 352 access_token 查询阿里云 IoT 区域。"""
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {
                "countryCode": "CN",
                "type": "THIRD_AUTHCODE",
                "authCode": self.access_token,
            },
            "request": {"apiVer": "1.0.2", "language": "zh-CN", "appKey": APP_KEY},
            "version": "1.0.0",
        }
        return await self._aliyun_post("/living/account/region/get", body)

    # ================= ③ OA 换 sid =================

    async def oauth_login(self) -> str:
        """用 352 access_token 换阿里云 OA sid。"""
        inner = {
            "riskControlInfo": {
                "createIfNotExist": "true",
                "sdkVersion": "3.4.0.27",
                "openaccountVersion": "3.4.0.27",
                "platformName": APP_PLATFORM,
                "netType": "",
                "brand": "Apple",
                "USE_H5_NC": "true",
                "deviceId": str(uuid.uuid4()),
                "locale": "zh-CN",
                "platformVersion": "26.6.2",
                "platform": "iPhone",
                "sessionid": uuid.uuid4().hex,
                "appKey": APP_KEY,
                "USE_OA_PWD_ENCRYPT": "true",
                "model": "iPhone18,2",
                "utdid": uuid.uuid4().hex[:24],
                "appVersion": APP_BUILD_VERSION,
            },
            "oauthPlateform": 23,
            "oauthAppKey": APP_KEY,
            "authCode": self.access_token,
        }
        form = {
            "loginByOauthRequest": json.dumps(inner, separators=(",", ":"), ensure_ascii=False)
        }
        url = f"{ALIYUN_OA_BASE}/api/prd/loginbyoauth.json"
        async with self._session.post(
            url,
            data=urllib.parse.urlencode(form),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=25),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise AuthError(f"OA 登录 HTTP {resp.status}: {text[:200]}")
            try:
                data = await resp.json(content_type=None)
            except Exception as err:
                raise AuthError(f"OA 登录返回非 JSON: {text[:300]}") from err

        result = (data.get("data") or {}).get("data") or {}
        success = result.get("loginSuccessResult") or {}
        sid = success.get("sid")
        if not sid:
            raise AuthError(f"OA 登录未取到 sid: {text[:300]}")
        return sid

    # ================= ④ 创建 IoT 会话 =================

    async def create_iot_session(self, sid: str) -> dict:
        """用 sid 换阿里云 IoT 令牌（iotToken 20h / refreshToken 200h）。"""
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {
                "request": {
                    "appKey": APP_KEY,
                    "authCode": sid,
                    "accountType": "OA_SESSION",
                }
            },
            "request": {"apiVer": "1.0.4", "language": "zh-CN", "appKey": APP_KEY},
            "version": "1.0.0",
        }
        data = await self._aliyun_post("/account/createSessionByAuthCode", body)
        inner = data.get("data") or {}
        self.iot_token = inner.get("iotToken", "")
        self.iot_refresh_token = inner.get("refreshToken", "") or self.iot_refresh_token
        self.identity_id = inner.get("identityId", "") or self.identity_id
        self._iot_token_time = time.time()
        if not self.iot_token:
            raise AuthError(f"创建 IoT 会话未返回 iotToken: {data}")
        return inner

    # ================= 完整登录流程 =================

    async def full_login(self, account: str, password: str, area: str = "86") -> None:
        """一次性跑完四步链路，拿到可用 iotToken。"""
        await self.login_352(account, password, area)
        await self.get_region()
        sid = await self.oauth_login()
        await self.create_iot_session(sid)
        _LOGGER.info("352 完整登录流程完成")

    # ================= 令牌刷新 =================

    async def refresh_iot_token(self) -> bool:
        """用 refreshToken 换新的 iotToken。失败返回 False。"""
        if not self.iot_refresh_token or not self.identity_id:
            return False
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {
                "request": {
                    "identityId": self.identity_id,
                    "refreshToken": self.iot_refresh_token,
                }
            },
            "request": {"apiVer": "1.0.4", "language": "zh-CN", "appKey": APP_KEY},
            "version": "1.0.0",
        }
        try:
            data = await self._aliyun_post("/account/checkOrRefreshSession", body)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("刷新 iotToken 失败: %s", err)
            return False

        inner = data.get("data") or {}
        new_token = inner.get("iotToken")
        if not new_token:
            return False
        self.iot_token = new_token
        self.iot_refresh_token = inner.get("refreshToken") or self.iot_refresh_token
        self.identity_id = inner.get("identityId") or self.identity_id
        self._iot_token_time = time.time()
        _LOGGER.debug("iotToken 已刷新")
        return True

    def iot_token_stale(self) -> bool:
        """iotToken 是否临近/已经过期（20h 有效期，提前 1h 视为过期）。"""
        if not self.iot_token:
            return True
        age = time.time() - self._iot_token_time
        return age > (72000 - IOT_TOKEN_REFRESH_MARGIN)

    def access_token_stale(self) -> bool:
        """352 access_token 是否临近过期（60 天，提前 1 天视为过期）。"""
        if not self.access_token:
            return True
        age = time.time() - self._access_token_time
        return age > (5184000 - ACCESS_TOKEN_REFRESH_MARGIN)

    async def ensure_tokens(self, account: str = "", password: str = "") -> None:
        """确保令牌可用：先试刷新，失败且已有账密则重新登录。"""
        if not self.access_token_stale() and not self.iot_token_stale():
            return

        if self.access_token_stale() and account and password:
            _LOGGER.info("352 access_token 过期，用账号密码重新登录")
            await self.full_login(account, password)
            return

        if self.iot_token_stale() and await self.refresh_iot_token():
            return

        if account and password:
            _LOGGER.info("刷新令牌失败，用账号密码重新登录")
            await self.full_login(account, password)
        else:
            raise AuthError("令牌已过期且未提供账号密码，无法自动恢复")

    # ================= 业务接口 =================

    async def list_devices(self) -> list[dict]:
        """列出账号下绑定的设备。"""
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {"pageSize": 50, "pageNo": 1},
            "request": {
                "language": "zh-CN",
                "appKey": APP_KEY,
                "iotToken": self.iot_token,
                "apiVer": "1.0.8",
            },
            "version": "1.0.0",
        }
        data = await self._aliyun_post("/uc/listBindingByAccount", body)
        return (data.get("data") or {}).get("data") or []

    async def get_properties(self, iot_id: str) -> dict:
        """读取设备全部属性，返回 {key: value}。"""
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {"iotId": iot_id},
            "request": {
                "language": "zh-CN",
                "appKey": APP_KEY,
                "iotToken": self.iot_token,
                "apiVer": "1.0.2",
            },
            "version": "1.0.0",
        }
        data = await self._aliyun_post("/thing/properties/get", body)
        raw = data.get("data") or {}
        return {
            key: (val.get("value") if isinstance(val, dict) else val)
            for key, val in raw.items()
        }

    async def set_properties(self, iot_id: str, items: dict[str, Any]) -> dict:
        """写入设备属性。items 形如 {"PowerSwitch": 1}。"""
        body = {
            "id": str(uuid.uuid4()).upper(),
            "params": {"iotId": iot_id, "items": items},
            "request": {
                "language": "zh-CN",
                "appKey": APP_KEY,
                "iotToken": self.iot_token,
                "apiVer": "1.0.0",
            },
            "version": "1.0.0",
        }
        return await self._aliyun_post("/living/thing/properties/set", body)

    async def get_device_info_352(self, iot_id: str) -> dict:
        """352 自有接口：设备详情。"""
        url = f"{API_352_BASE}/api/device/info/{iot_id}"
        async with self._session.get(
            url,
            headers={
                "Authorization": f"Token {self.access_token}",
                "Accept": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            data = await resp.json(content_type=None)
        if data.get("code") == 0:
            return data.get("data") or {}
        return {}

    # ================= 底层：带签名的阿里云请求 =================

    async def _aliyun_post(self, path: str, body: dict) -> dict:
        """向阿里云网关发带签名的 POST。"""
        if not self._app_secret:
            raise ApiError(
                "缺少 app_secret，无法对阿里云网关签名。"
                "请在集成配置中填入 352 App 的 appSecret（需反编译 App 获取）。"
            )

        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        headers = build_headers(
            app_key=APP_KEY,
            app_secret=self._app_secret,
            method="POST",
            path=path,
            body=payload,
        )

        url = f"{ALIYUN_BASE}{path}"
        async with self._session.post(
            url,
            data=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=25),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise ApiError(f"{path} HTTP {resp.status}: {text[:300]}")
            try:
                data = await resp.json(content_type=None)
            except Exception as err:
                raise ApiError(f"{path} 返回非 JSON: {text[:300]}") from err

        code = data.get("code")
        if code != 200:
            raise ApiError(f"{path} 返回 code={code}: {data}")
        return data
