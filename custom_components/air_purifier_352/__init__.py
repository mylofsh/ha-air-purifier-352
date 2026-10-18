"""DataUpdateCoordinator and setup for 352 Air Purifier."""
from __future__ import annotations

import logging
from datetime import timedelta

import async_timeout

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AilinkApiClient, ApiError, AuthError
from .const import (
    CONF_ACCOUNT,
    CONF_APP_SECRET,
    CONF_PASSWORD,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["fan", "sensor", "switch", "select"]


class Air352DataUpdateCoordinator(DataUpdateCoordinator):
    """拉取 352 设备数据，并负责令牌自动续期。"""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AilinkApiClient,
        account: str,
        password: str,
        scan_interval: int,
        entry: ConfigEntry | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.api = api
        self._account = account
        self._password = password
        self._entry = entry

    async def _async_update_data(self) -> dict:
        """拉取设备与属性。"""
        try:
            async with async_timeout.timeout(30):
                # 令牌临近过期时自动续期（刷新或重新登录）
                try:
                    await self.api.ensure_tokens(self._account, self._password)
                    self._persist_credentials()
                except AuthError as err:
                    raise UpdateFailed(f"令牌续期失败: {err}") from err

                devices_raw = await self.api.list_devices()
                devices: list[dict] = []
                device_statuses: dict[str, dict] = {}

                for dev in devices_raw:
                    iot_id = dev.get("iotId")
                    if not iot_id:
                        continue
                    product_name = dev.get("productName", "") or ""
                    product_model = dev.get("productModel", "") or ""
                    # 只处理空气净化器
                    if "净化" not in product_name and "净化器" not in product_model:
                        continue

                    try:
                        props = await self.api.get_properties(iot_id)
                    except ApiError as err:
                        _LOGGER.warning("读取 %s 属性失败: %s", iot_id, err)
                        continue

                    if props:
                        device_statuses[iot_id] = props
                        devices.append(
                            {
                                "iotId": iot_id,
                                "name": dev.get("nickname")
                                or product_name
                                or "空气净化器",
                                "productName": product_name,
                                "productModel": product_model,
                            }
                        )

                return {
                    "devices": devices,
                    "device_statuses": device_statuses,
                }

        except UpdateFailed:
            raise
        except Exception as err:  # noqa: BLE001
            raise UpdateFailed(f"Error fetching data: {err}") from err

    def _persist_credentials(self) -> None:
        """把刷新后的令牌写回 config entry，避免重启后丢失。"""
        if self._entry is None:
            return
        creds = self.api.credentials()
        if all(self._entry.data.get(k) == v for k, v in creds.items()):
            return
        self.hass.config_entries.async_update_entry(
            self._entry, data={**self._entry.data, **creds}
        )
        _LOGGER.debug("已保存刷新后的令牌")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """从 config entry 建立 352 集成。"""
    session = async_get_clientsession(hass)

    cfg = {**entry.data, **entry.options}

    api = AilinkApiClient(
        session=session,
        app_secret=cfg.get(CONF_APP_SECRET, ""),
        access_token=cfg.get("access_token", ""),
        refresh_token_352=cfg.get("refresh_token_352", ""),
        air_token=cfg.get("air_token", ""),
        iot_token=cfg.get("iot_token", ""),
        iot_refresh_token=cfg.get("iot_refresh_token", ""),
        identity_id=cfg.get("identity_id", ""),
    )

    coordinator = Air352DataUpdateCoordinator(
        hass,
        api,
        account=cfg.get(CONF_ACCOUNT, ""),
        password=cfg.get(CONF_PASSWORD, ""),
        scan_interval=cfg.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        entry=entry,
    )
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """卸载集成。"""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
