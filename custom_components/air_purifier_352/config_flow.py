"""352 Air Purifier - Config Flow & Options Flow.

首次添加：输入 352 账号密码 + appSecret，自动完成四步登录链路。
之后可在「配置 → 选项」更新账号密码或 appSecret。
"""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AilinkApiClient, ApiError, AuthError

try:  # HA 2024.4+ 起 FlowResult 迁移到 config_entries
    from homeassistant.config_entries import ConfigFlowResult as FlowResult
except ImportError:  # 兼容旧版本
    from homeassistant.data_entry_flow import FlowResult  # type: ignore[no-redef]
from .const import (
    CONF_ACCOUNT,
    CONF_APP_SECRET,
    CONF_AREA,
    CONF_PASSWORD,
    DEFAULT_AREA,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ACCOUNT): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_AREA, default=DEFAULT_AREA): str,
        vol.Required(CONF_APP_SECRET): str,
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=600)
        ),
    }
)

STEP_OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_ACCOUNT): str,
        vol.Optional(CONF_PASSWORD): str,
        vol.Optional(CONF_APP_SECRET): str,
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=600)
        ),
    }
)


class Air352ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """352 空气净化器配置流程。"""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """首次添加。"""
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            api = AilinkApiClient(
                session=session,
                app_secret=user_input[CONF_APP_SECRET],
            )
            try:
                await api.full_login(
                    user_input[CONF_ACCOUNT],
                    user_input[CONF_PASSWORD],
                    user_input.get(CONF_AREA, DEFAULT_AREA),
                )
                devices = await api.list_devices()
                if not devices:
                    errors["base"] = "no_devices"
                else:
                    names = [
                        d.get("nickname") or d.get("productName", "")
                        for d in devices
                    ]
                    title = "352 " + ", ".join(n for n in names[:3] if n)
                    if len(devices) > 3:
                        title += f" +{len(devices) - 3}"

                    return self.async_create_entry(
                        title=title,
                        data={
                            CONF_ACCOUNT: user_input[CONF_ACCOUNT],
                            CONF_PASSWORD: user_input[CONF_PASSWORD],
                            CONF_AREA: user_input.get(CONF_AREA, DEFAULT_AREA),
                            CONF_APP_SECRET: user_input[CONF_APP_SECRET],
                            CONF_SCAN_INTERVAL: user_input.get(
                                CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                            ),
                            **api.credentials(),
                        },
                    )
            except AuthError:
                errors["base"] = "auth_failed"
            except ApiError as err:
                # 签名错误单独提示，便于用户定位 appSecret 问题
                errors["base"] = (
                    "sign_failed" if "签名" in str(err) or "sign" in str(err).lower()
                    else "api_error"
                )
            except Exception:  # noqa: BLE001
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "Air352OptionsFlow":
        """注册选项流程。"""
        return Air352OptionsFlow()


class Air352OptionsFlow(config_entries.OptionsFlow):
    """更新账号密码 / appSecret / 轮询间隔。

    进入路径：设置 → 设备与服务 → 352 空气净化器 → 配置 → 选项
    留空的字段保持原值。修改账密或密钥后会重新登录并重载集成。
    """

    def __init__(self) -> None:
        self._errors: dict[str, str] = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """显示并处理更新表单。"""
        current = {**self.config_entry.data, **self.config_entry.options}

        if user_input is not None:
            merged = dict(current)
            for key in (CONF_ACCOUNT, CONF_PASSWORD, CONF_APP_SECRET):
                val = (user_input.get(key) or "").strip()
                if val:
                    merged[key] = val
            if CONF_SCAN_INTERVAL in user_input:
                merged[CONF_SCAN_INTERVAL] = user_input[CONF_SCAN_INTERVAL]

            session = async_get_clientsession(self.hass)
            api = AilinkApiClient(
                session=session,
                app_secret=merged.get(CONF_APP_SECRET, ""),
            )
            try:
                # 用账户密码重新走完整链路，验证新配置可用
                await api.full_login(
                    merged[CONF_ACCOUNT],
                    merged[CONF_PASSWORD],
                    merged.get(CONF_AREA, DEFAULT_AREA),
                )
                await api.list_devices()

                new_data = {
                    CONF_ACCOUNT: merged[CONF_ACCOUNT],
                    CONF_PASSWORD: merged[CONF_PASSWORD],
                    CONF_AREA: merged.get(CONF_AREA, DEFAULT_AREA),
                    CONF_APP_SECRET: merged.get(CONF_APP_SECRET, ""),
                    CONF_SCAN_INTERVAL: merged.get(
                        CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                    ),
                    **api.credentials(),
                }
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=new_data, options={}
                )
                await self.hass.config_entries.async_reload(
                    self.config_entry.entry_id
                )
                return self.async_create_entry(title="", data={})
            except AuthError:
                self._errors["base"] = "auth_failed"
            except ApiError as err:
                self._errors["base"] = (
                    "sign_failed" if "签名" in str(err) or "sign" in str(err).lower()
                    else "api_error"
                )
            except Exception:  # noqa: BLE001
                self._errors["base"] = "unknown"

        schema = self.add_suggested_values_to_schema(
            STEP_OPTIONS_SCHEMA,
            {
                CONF_ACCOUNT: current.get(CONF_ACCOUNT, ""),
                CONF_PASSWORD: "",
                CONF_APP_SECRET: current.get(CONF_APP_SECRET, ""),
                CONF_SCAN_INTERVAL: current.get(
                    CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                ),
            },
        )

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=self._errors,
        )
