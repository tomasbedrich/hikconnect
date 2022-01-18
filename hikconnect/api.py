import datetime
import hashlib
import json
import logging
from base64 import urlsafe_b64decode
from contextlib import contextmanager

from aiohttp import ClientSession

from hikconnect.exceptions import LoginError

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
    BASE_URL = "https://api.hik-connect.com"

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
            return self.login(username, password)

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
            async with client.put(
                f"{self.BASE_URL}/v3/apigateway/login", data=data
            ) as res:
                res_json = await res.json()
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
        self.login_valid_until = self._decode_jwt_expiration(session_id)
        log.debug(
            "Parsed session_id '%s', valid until %s", session_id, self.login_valid_until
        )
        self._refresh_session_id = refresh_session_id
        log.debug("Parsed refresh_session_id '%s'", self._refresh_session_id)

    def is_refresh_login_needed(self):
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
                serial = device["deviceSerial"]
                try:
                    locks_json = json.loads(
                        res_json["statusInfos"][serial]["optionals"]["lockNum"]
                    )
                    # "lockNum" format: {"1":1,"2":1,"3":1,"4":1,"5":1,"6":1,"7":1,"8":1}
                    # which means (guessing): <channel number>: <number of locks connected>
                    locks = {int(k): v for k, v in locks_json.items()}
                except KeyError:
                    # some devices doesn't have "lockNum"
                    # (for example https://www.hikvision.com/cz/products/IP-Products/Network-Video-Recorders/Pro-Series/ds-7608ni-k2-8p/)
                    locks = {}
                yield {
                    "id": device["fullSerial"],
                    "name": device["name"],
                    "serial": serial,
                    "type": device["deviceType"],
                    "version": device["version"],
                    "locks": locks,
                }
            offset += limit
            has_next_page = res_json["page"]["hasNext"]

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
        # TODO parse
        # At rest looks like this:
        # {"apiId":1,"callStatus":1,"verFlag":1,"callerInfo":{"buildingNo":0,"floorNo":0,"zoneNo":0,"unitNo":0,"devNo":0,"devType":0,"lockNum":0},"rc":1}
        return res_json["data"]

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
