import datetime
import hashlib
import json
import logging
from base64 import urlsafe_b64decode
from contextlib import contextmanager

from aiohttp import ClientSession

from hikconnect.exceptions import DeviceOffline, LoginError

log = logging.getLogger(__name__)


class _HikConnectClient(ClientSession):
    FEATURE_CODE = "deadbeef"  # any non-empty hex string works

    def __init__(self):
        headers = {
            "clientType": "55",
            "lang": "en-US",
            "featureCode": self.FEATURE_CODE,
        }
        super().__init__(raise_for_status=True, headers=headers)

    def set_session_id(self, session_id):
        self.headers.update({"sessionId": session_id})

    @contextmanager
    def without_session_id(self):
        if "sessionId" not in self.headers:
            yield self
            return

        session_id = self.headers.pop("sessionId")
        try:
            yield self
        finally:
            self.headers["sessionId"] = session_id


class HikConnect:
    # pylint: disable=too-many-public-methods

    BASE_URL = "https://api.hik-connect.com"

    CALL_STATUS_MAPPING = {
        1: "idle",
        2: "ringing",
        3: "call in progress",
    }
    CALL_INFO_MAPPING = {
        "buildingNo": "building_number",
        "floorNo": "floor_number",
        "zoneNo": "zone_number",
        "unitNo": "unit_number",
        "devNo": "device_number",
        "devType": "device_type",
        "lockNum": "lock_number",
    }

    def __init__(self):
        self._refresh_session_id = None
        self.login_valid_until = None
        self.client = _HikConnectClient()

    async def login(self, username: str, password: str):
        """Login to HikConnect and save state for use by other methods."""
        data = {
            "account": username,
            "password": hashlib.md5(password.encode("utf-8")).hexdigest(),
            # "imageCode": "",  # required when CAPTCHA is presented - plaintext captcha input
        }
        async with self.client.post(
            f"{self.BASE_URL}/v3/users/login/v2", data=data
        ) as res:
            res_json = await res.json()
        log.debug("Got login response '%s'", res_json)

        if res_json["meta"]["code"] in (1013, 1014):
            raise LoginError(
                "Login failed, probably wrong username/password combination."
            )

        if res_json["meta"]["code"] == 1015:
            raise LoginError(
                "CAPTCHA hit, please login using Hik-Connect app and then retry."
            )
            # GET v3/captcha?account=tomasbedrich&featureCode=deadbeef => receives PNG with CATPCHA, the code must be send with next request inside `imageCode` field

        if res_json["meta"]["code"] == 1100:
            # https://github.com/tomasbedrich/home-assistant-hikconnect/issues/16
            new_api_domain = res_json["loginArea"]["apiDomain"]
            self.BASE_URL = f"https://{new_api_domain}"
            log.debug("Switching API domain to '%s'", self.BASE_URL)
            return await self.login(username, password)

        try:
            session_id = res_json["loginSession"]["sessionId"]
        except KeyError as e:  # pragma: no cover
            raise LoginError("Unable to parse session_id from response.") from e
        try:
            refresh_session_id = res_json["loginSession"]["rfSessionId"]
        except KeyError as e:  # pragma: no cover
            raise LoginError("Unable to parse refresh_session_id from response.") from e

        self._handle_login_response(session_id, refresh_session_id)

        log.info("Login successful as username '%s'", username)

    async def refresh_login(self):
        """Refresh session_id for currently logged in user."""
        data = {
            "refreshSessionId": self._refresh_session_id,
            "featureCode": _HikConnectClient.FEATURE_CODE,
        }
        with self.client.without_session_id() as client:
            async with client.put(
                f"{self.BASE_URL}/v3/apigateway/login", data=data
            ) as res:
                res_json = await res.json()
        log.debug("Got refresh login response '%s'", res_json)

        try:
            session_id = res_json["sessionInfo"]["sessionId"]
        except KeyError as e:  # pragma: no cover
            raise LoginError("Unable to parse session_id from response.") from e
        try:
            refresh_session_id = res_json["sessionInfo"]["refreshSessionId"]
        except KeyError as e:  # pragma: no cover
            raise LoginError("Unable to parse refresh_session_id from response.") from e

        self._handle_login_response(session_id, refresh_session_id)

        log.info("Login refreshed successfuly")

    def _handle_login_response(self, session_id, refresh_session_id):
        self.client.set_session_id(session_id)
        self.login_valid_until = self._decode_jwt_expiration(session_id)
        log.debug(
            "Parsed session_id '%s', valid until %s", session_id, self.login_valid_until
        )
        self._refresh_session_id = refresh_session_id
        log.debug("Parsed refresh_session_id '%s'", self._refresh_session_id)

    def is_refresh_login_needed(self):
        if not self.login_valid_until:
            return True
        return (self.login_valid_until - datetime.datetime.now()) < datetime.timedelta(
            hours=1
        )

    async def get_devices(self):
        """Get info about devices associated with currently logged user."""
        limit, offset, has_next_page = 50, 0, True
        while has_next_page:
            async with self.client.get(
                f"{self.BASE_URL}/v3/userdevices/v1/devices/pagelist?groupId=-1&limit={limit}&offset={offset}&filter=TIME_PLAN,CONNECTION,SWITCH,STATUS,STATUS_EXT,WIFI,NODISTURB,P2P,KMS,HIDDNS"
            ) as res:
                res_json = await res.json()
            log.debug("Got device list response '%s'", res_json)
            log.info("Received device list")
            for device in res_json["deviceInfos"]:
                yield self._parse_device(device, res_json)
            offset += limit
            has_next_page = res_json["page"]["hasNext"]

    @classmethod
    def _parse_device(cls, device, res_json):
        serial = device["deviceSerial"]
        conn = (res_json.get("connectionInfos") or {}).get(serial) or {}
        status = (res_json.get("statusInfos") or {}).get(serial) or {}
        wifi = (res_json.get("wifiInfos") or {}).get(serial) or {}

        is_online = cls._parse_is_online(status)
        local_ip = cls._clean_ip(conn.get("localIp")) or cls._clean_ip(
            wifi.get("address")
        )
        wan_ip = cls._clean_ip(conn.get("netIp"))
        wifi_signal = (
            wifi.get("signal") if isinstance(wifi.get("signal"), int) else None
        )

        # Cloud keeps stale IP/signal after device goes offline; clear them.
        if not is_online:
            local_ip = wan_ip = wifi_signal = None

        return {
            "id": device["fullSerial"],
            "name": device["name"],
            "serial": serial,
            "type": device["deviceType"],
            "version": device["version"],
            "locks": cls._parse_locks(status),
            "local_ip": local_ip,
            "wan_ip": wan_ip,
            "is_online": is_online,
            "wifi_signal": wifi_signal,
            "update_available": cls._parse_update_available(status),
        }

    @staticmethod
    def _clean_ip(value):
        if not isinstance(value, str) or not value or value == "0.0.0.0":
            return None
        return value

    @staticmethod
    def _parse_is_online(status):
        code = status.get("globalStatus")
        return (code == 1) if code is not None else None

    @staticmethod
    def _parse_update_available(status):
        value = status.get("upgradeAvailable")
        return bool(value) if value is not None else None

    @staticmethod
    def _parse_locks(status):
        # "lockNum" format: {"1":1,"2":1,...} meaning <channel number>: <number of locks connected>
        # Some devices don't have "lockNum" (e.g. NVRs like DS-7608NI-K2-8P).
        try:
            locks_json = json.loads(status["optionals"]["lockNum"])
        except KeyError:
            return {}
        return {int(k): v for k, v in locks_json.items()}

    async def get_cameras(self, device_serial: str):
        """Get info about cameras connected to a device."""
        async with self.client.get(
            f"{self.BASE_URL}/v3/userdevices/v1/cameras/info?deviceSerial={device_serial}"
        ) as res:
            res_json = await res.json()
        log.debug("Got camera list response '%s'", res_json)
        log.info("Received camera info for device '%s'", device_serial)
        for camera in res_json["cameraInfos"]:
            yield {
                "id": camera["cameraId"],
                "name": camera["cameraName"],
                "channel_number": camera["channelNo"],
                "signal_status": camera["deviceChannelInfo"]["signalStatus"],
                "is_shown": camera["isShow"],
            }

    # ------------------------------------------------------------------
    # Area (group) management
    # ------------------------------------------------------------------

    async def get_areas(self, device_serial: str):
        """Get all areas (groups) configured on a device.

        Yields dicts with keys:
            group_id (int), device_serial (str), group_name (str),
            group_type (int), mode (int), create_time (int), modify_time (int)

        ``mode`` meanings (as observed): 0 = disarmed, 1 = armed, 2 = armed-silent.
        """
        async with self.client.get(
            f"{self.BASE_URL}/v3/devices/group/{device_serial}/list"
        ) as res:
            res_json = await res.json()
        log.debug("Got area list response '%s'", res_json)
        log.info("Received area list for device '%s'", device_serial)
        for area in res_json["list"]:
            yield {
                "group_id": area["groupId"],
                "device_serial": area["groupDevSerial"],
                "group_name": area["groupName"],
                "group_type": area["groupType"],
                "mode": area["mode"],
                "create_time": area["createTime"],
                "modify_time": area["modifyTime"],
            }

    async def get_area(self, device_serial: str, group_id: int):
        """Get the member resources belonging to an area.

        Returns a list of dicts with keys:
            group_id (int), device_serial (str), member_id (str)

        ``member_id`` corresponds to a camera ``id`` returned by ``get_cameras()``.
        """
        async with self.client.get(
            f"{self.BASE_URL}/v3/devices/group/{device_serial}/{group_id}"
        ) as res:
            res_json = await res.json()
        log.debug("Got area detail response '%s'", res_json)
        log.info(
            "Received area detail for device '%s' group '%d'", device_serial, group_id
        )
        return [
            {
                "group_id": member["groupId"],
                "device_serial": member["groupDevSerial"],
                "member_id": member["memberId"],
            }
            for member in res_json["list"]
        ]

    async def create_area(
        self, device_serial: str, group_name: str, resource_ids: list
    ):
        """Create a new area (group) on a device.

        Args:
            device_serial: Serial of the NVR/device.
            group_name: Human-readable name for the new area.
            resource_ids: List of camera ``id`` strings to include in the area.
                          Camera IDs can be obtained from ``get_cameras()``.
                          Must contain at least one ID.

        Returns:
            dict with the same shape as items yielded by ``get_areas()``:
            ``group_id``, ``device_serial``, ``group_name``, ``group_type``,
            ``mode``, ``create_time``, ``modify_time``.
        """
        payload = {"groupName": group_name, "resourceIds": resource_ids}
        async with self.client.post(
            f"{self.BASE_URL}/v3/devices/group/{device_serial}", json=payload
        ) as res:
            res_json = await res.json()
        log.debug("Got create area response '%s'", res_json)
        log.info("Created area '%s' on device '%s'", group_name, device_serial)
        if "groupInfo" not in res_json:
            raise ValueError(f"API error creating area: {res_json}")
        info = res_json["groupInfo"]
        return {
            "group_id": info["groupId"],
            "device_serial": info["groupDevSerial"],
            "group_name": info["groupName"],
            "group_type": info["groupType"],
            "mode": info["mode"],
            "create_time": info["createTime"],
            "modify_time": info["modifyTime"],
        }

    async def update_area(
        self, device_serial: str, group_id: int, group_name: str, resource_ids: list
    ):
        """Update an existing area (group) on a device.

        .. note::
            The Hik-Connect API does not support a PATCH/PUT verb for groups.
            This method implements update as **delete → recreate**: the old area
            is deleted and a new one is created with the same name and the
            supplied member list.  The returned dict contains the new
            ``group_id`` assigned by the API — callers must update any stored
            references.

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area to replace (from ``get_areas()``).
            group_name: Name for the recreated area.
            resource_ids: Complete list of camera ``id`` strings for the area.
                          Must contain at least one ID.

        Returns:
            dict with the same shape as ``create_area()`` / ``get_areas()``
            items, including the new ``group_id``.
        """
        await self.delete_area(device_serial, group_id)
        result = await self.create_area(device_serial, group_name, resource_ids)
        log.info(
            "Area '%d' on device '%s' replaced by new area '%d'",
            group_id,
            device_serial,
            result["group_id"],
        )
        return result

    # pylint: disable=too-many-arguments
    async def edit_area_members(
        self,
        device_serial: str,
        group_id: int,
        *,
        add_ids: list | None = None,
        remove_ids: list | None = None,
        group_name: str | None = None,
    ) -> dict:
        """Add and/or remove members from an area, auto-deleting if it becomes empty.

        Fetches the current member list, applies additions and removals, then
        either updates the area (members remain) or deletes it (no members left).
        The area cannot be empty on the Hik-Connect platform, so deletion is
        automatic when the last member would be removed.

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area to edit (from ``get_areas()``).
            add_ids: Camera IDs to add to the area.  Duplicates are ignored.
            remove_ids: Camera IDs to remove from the area.  Unknown IDs are
                        ignored.
            group_name: Name to preserve on the area when updating.  If ``None``
                        the name is fetched automatically via ``get_areas()``.
                        Pass it explicitly to avoid an extra API round-trip when
                        the caller already has the area info cached.

        Returns:
            dict with key ``"action"``:

            * ``"updated"`` — area was modified; also contains ``"member_ids"``
              (the new list of member IDs after the edit).
            * ``"deleted"`` — area was deleted because no members remained.

        Raises:
            ValueError: If both ``add_ids`` and ``remove_ids`` are empty or
                        ``None``.
            LookupError: If ``group_name`` is ``None`` and the area cannot be
                         found in ``get_areas()`` (e.g. wrong ``group_id``).
        """
        add_ids = list(add_ids or [])
        remove_ids_set = set(remove_ids or [])

        if not add_ids and not remove_ids_set:
            raise ValueError(
                "At least one of 'add_ids' or 'remove_ids' must be provided."
            )

        # Fetch current members
        current_members = await self.get_area(device_serial, group_id)
        current_ids = [m["member_id"] for m in current_members]

        # Resolve group_name if not supplied
        if group_name is None:
            async for area in self.get_areas(device_serial):
                if area["group_id"] == group_id:
                    group_name = area["group_name"]
                    break
            if group_name is None:
                raise LookupError(
                    f"Area with group_id={group_id} not found on device '{device_serial}'."
                )

        # Build new member list: (current ∪ add_ids) \ remove_ids, preserving order
        seen: set[str] = set()
        new_ids: list[str] = []
        for mid in current_ids + add_ids:
            if mid not in remove_ids_set and mid not in seen:
                seen.add(mid)
                new_ids.append(mid)

        if not new_ids:
            # Last member removed — the API forbids empty areas, so delete it
            await self.delete_area(device_serial, group_id)
            log.info(
                "Area '%d' on device '%s' deleted (no members remaining)",
                group_id,
                device_serial,
            )
            return {"action": "deleted", "group_id": group_id}

        # update_area = delete + recreate; returns new group info
        new_area = await self.update_area(device_serial, group_id, group_name, new_ids)
        log.info(
            "Area '%d' on device '%s' updated -> new group_id=%d, %d member(s)",
            group_id,
            device_serial,
            new_area["group_id"],
            len(new_ids),
        )
        return {
            "action": "updated",
            "group_id": new_area["group_id"],
            "member_ids": new_ids,
        }

    async def delete_area(self, device_serial: str, group_id: int):
        """Delete an area (group).

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area to delete (from ``get_areas()``).
        """
        async with self.client.delete(
            f"{self.BASE_URL}/v3/devices/group/{device_serial}/{group_id}"
        ) as res:
            res_json = await res.json()
        log.debug("Got delete area response '%s'", res_json)

        meta = res_json.get("meta", {})
        if meta.get("code") != 200:
            raise ValueError(f"API error deleting area: {res_json}")

        log.info("Deleted area '%d' on device '%s'", group_id, device_serial)

    async def set_area_defence_mode(self, device_serial: str, group_id: int, mode: int):
        """Set the defence (arm/disarm) mode for an area.

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area (from ``get_areas()``).
            mode: 0 = disarmed, 1 = armed, 2 = armed-silent.

        Use the convenience wrappers ``arm_area()``, ``arm_area_silent()``,
        and ``disarm_area()`` instead of calling this directly.
        """
        payload = {"groupId": group_id, "mode": mode}
        async with self.client.post(
            f"{self.BASE_URL}/v3/devices/group/{device_serial}/switchDefenceMode",
            json=payload,
        ) as res:
            res_json = await res.json()
        log.debug("Got set defence mode response '%s'", res_json)
        log.info(
            "Set defence mode '%d' for area '%d' on device '%s'",
            mode,
            group_id,
            device_serial,
        )

    async def arm_area(self, device_serial: str, group_id: int, mode: int = 1):
        """Arm an area.

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area (from ``get_areas()``).
            mode: Arm mode value (default 1). Use 2 for silent arming or call
                  ``arm_area_silent()`` instead.
        """
        await self.set_area_defence_mode(device_serial, group_id, mode)

    async def arm_area_silent(self, device_serial: str, group_id: int, mode: int = 2):
        """Arm an area silently (no beep/alert on the panel).

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area (from ``get_areas()``).
            mode: Silent arm mode value (default 2).
        """
        await self.set_area_defence_mode(device_serial, group_id, mode)

    async def disarm_area(self, device_serial: str, group_id: int):
        """Disarm an area.

        Args:
            device_serial: Serial of the NVR/device.
            group_id: ID of the area (from ``get_areas()``).
        """
        await self.set_area_defence_mode(device_serial, group_id, 0)

    # ------------------------------------------------------------------

    async def unlock(
        self, device_serial: str, channel_number: int, lock_index: int = 0
    ):
        """
        Send unlock request.

        The `device_serial`, `channel_number` parameters can be obtained from `get_devices()` and/or `get_cameras()`.
        Pay special attention to `locks` item in `get_devices()` response. Not only it tells you which cameras
        has "unlock capability". Also if there is more than one lock connected to a door station,
        you can specify `lock_index` parameter to control which lock to open. The `lock_index` starts with zero!
        """
        async with self.client.put(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/{channel_number}/remote/unlock?srcId=1&lockId={lock_index}&userType=0"
        ) as res:
            res_json = await res.json()
        log.debug("Got unlock response '%s'", res_json)
        log.info(
            "Unlocked device '%s' channel '%d' lock_index '%d'",
            device_serial,
            channel_number,
            lock_index,
        )

    async def get_call_status(self, device_serial: str):
        async with self.client.get(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/status"
        ) as res:
            res_json = await res.json()
        log.debug("Got call status response '%s'", res_json)
        log.info("Got call status for device '%s'", device_serial)
        if res_json["meta"]["code"] == 2003:
            raise DeviceOffline()
        data = json.loads(res_json["data"])
        try:
            status = self.CALL_STATUS_MAPPING[data["callStatus"]]
        except KeyError:
            log.warning("Unknown call status: %s", data["callStatus"])
            status = "unknown"

        info = {}
        for in_key, out_key in self.CALL_INFO_MAPPING.items():
            try:
                info[out_key] = data["callerInfo"][in_key]
            except KeyError:
                # normally we would log warning, but it seems to be pretty common situation:
                # https://github.com/tomasbedrich/home-assistant-hikconnect/issues/4#issuecomment-1022526060
                log.debug("Missing caller info key: %s", in_key)

        return {
            "status": status,
            "info": info,
        }

    async def answer_call(self, device_serial: str):
        """
        Send answer call request.

        The `device_serial` parameter can be obtained from `get_devices()` and/or `get_cameras()`.
        """
        async with self.client.put(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/operation?cmdId=2"
        ) as res:
            res_json = await res.json()
        log.debug("Got answer_call response '%s'", res_json)
        log.info("Answer call to device '%s'", device_serial)

    async def cancel_call(self, device_serial: str):
        """
        Send cancel call request.

        The `device_serial` parameter can be obtained from `get_devices()` and/or `get_cameras()`.
        """
        async with self.client.put(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/operation?cmdId=3"
        ) as res:
            res_json = await res.json()
        log.debug("Got cancel_call response '%s'", res_json)
        log.info("Cancel call to device '%s'", device_serial)

    async def hangup_call(self, device_serial: str):
        """
        Send hangup call request.

        The `device_serial` parameter can be obtained from `get_devices()` and/or `get_cameras()`.
        """
        async with self.client.put(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/operation?cmdId=5"
        ) as res:
            res_json = await res.json()
        log.debug("Got hangup_call response '%s'", res_json)
        log.info("Hangup call to device '%s'", device_serial)

    @staticmethod
    def _decode_jwt_expiration(jwt):
        # decode JWT manually because of PyJWT version incompatibility with HomeAssistant
        parts = jwt.split(".")
        claims_raw = parts[1]
        missing_padding = len(claims_raw) % 4
        if missing_padding:
            claims_raw += "=" * (4 - missing_padding)
        claims_json_raw = urlsafe_b64decode(claims_raw)
        claims = json.loads(claims_json_raw)
        return datetime.datetime.fromtimestamp(claims["exp"])

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self):
        await self.client.close()
