import datetime
import hashlib
import logging
from contextlib import contextmanager

import jwt
from httpx import AsyncClient

from hikconnect.exceptions import LoginError

log = logging.getLogger(__name__)


class _HikConnectClient(AsyncClient):
    FEATURE_CODE = "deadbeef"  # any non-empty hex string works

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = {
            "clientType": "55",
            "lang": "en-US",
            "featureCode": self.FEATURE_CODE,
        }

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
    BASE_URL = "https://apiieu.hik-connect.com"

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
        res = await self.client.post(f"{self.BASE_URL}/v3/users/login/v2", data=data)
        res.raise_for_status()
        res_json = res.json()
        log.debug("Got login response '%s'", res_json)

        if res_json["meta"]["code"] in (1013, 1014):
            raise LoginError("Login failed, probably wrong username/password combination.")

        if res_json["meta"]["code"] == 1015:
            raise LoginError("CAPTCHA hit, please login using Hik-Connect app and then retry.")
            # GET v3/captcha?account=tomasbedrich&featureCode=deadbeef => receives PNG with CATPCHA, the code must be send with next request inside `imageCode` field

        try:
            session_id = res_json["loginSession"]["sessionId"]
        except KeyError as e:
            raise LoginError("Unable to parse session_id from response.") from e
        try:
            refresh_session_id = res_json["loginSession"]["rfSessionId"]
        except KeyError as e:
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
            res = await client.put(f"{self.BASE_URL}/v3/apigateway/login", data=data)
        res.raise_for_status()
        res_json = res.json()
        log.debug("Got refresh login response '%s'", res_json)

        try:
            session_id = res_json["sessionInfo"]["sessionId"]
        except KeyError as e:
            raise LoginError("Unable to parse session_id from response.") from e
        try:
            refresh_session_id = res_json["sessionInfo"]["refreshSessionId"]
        except KeyError as e:
            raise LoginError("Unable to parse refresh_session_id from response.") from e

        self._handle_login_response(session_id, refresh_session_id)

        log.info("Login refreshed successfuly")

    def _handle_login_response(self, session_id, refresh_session_id):
        self.client.set_session_id(session_id)
        token = jwt.decode(session_id, options={"verify_signature": False})
        self.login_valid_until = datetime.datetime.fromtimestamp(token["exp"])
        log.debug("Parsed session_id '%s', valid until %s", session_id, self.login_valid_until)
        self._refresh_session_id = refresh_session_id
        log.debug("Parsed refresh_session_id '%s'", self._refresh_session_id)

    def is_refresh_login_needed(self):
        return (self.login_valid_until - datetime.datetime.now()) < datetime.timedelta(hours=1)

    async def get_devices(self):
        """Get info about devices associated with currently logged user."""
        res = await self.client.get(f"{self.BASE_URL}/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=100&offset=0")
        res.raise_for_status()
        res_json = res.json()
        log.debug("Got device list response '%s'", res_json)
        log.info("Received device list")
        for device in res_json["deviceInfos"]:
            yield {
                "id": device["fullSerial"],
                "name": device["name"],
                "serial": device["deviceSerial"],
                "type": device["deviceType"],
                "version": device["version"],
            }
        if res_json["page"]["hasNext"]:
            raise ValueError("More than 100 devices is not supported yet. Please file an issue on GitHub.")

    async def get_cameras(self, device_serial: str):
        """Get info about cameras connected to a device."""
        res = await self.client.get(f"{self.BASE_URL}/v3/userdevices/v1/cameras/info?deviceSerial={device_serial}")
        res.raise_for_status()
        res_json = res.json()
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

    async def unlock(self, device_serial: str, channel_number: int):
        """Send unlock request for given channel of given device."""
        res = await self.client.put(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/{channel_number}/remote/unlock?srcId=1&lockId=0&userType=0"
        )
        res.raise_for_status()
        log.info("Unlocked device '%s' channel '%d'", device_serial, channel_number)

    async def get_call_status(self, device_serial: str):
        res = await self.client.get(f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/status")
        res.raise_for_status()
        res_json = res.json()
        log.debug("Got call status response '%s'", res_json)
        log.info("Got call status for device '%s'", device_serial)
        # TODO parse
        # At rest looks like this:
        # {"apiId":1,"callStatus":1,"verFlag":1,"callerInfo":{"buildingNo":0,"floorNo":0,"zoneNo":0,"unitNo":0,"devNo":0,"devType":0,"lockNum":0},"rc":1}
        return res_json["data"]

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self):
        await self.client.aclose()
