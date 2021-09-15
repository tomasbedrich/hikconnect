import hashlib
import logging

from httpx import AsyncClient
from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution("hikconnect").version
except DistributionNotFound:
    __version__ = "(local)"

log = logging.getLogger(__name__)


class HikConnect:
    BASE_URL = "https://apiieu.hik-connect.com"

    def __init__(self):
        headers = {
            "clientType": "55",
            "lang": "en-US",
            "featureCode": "deadbeef",  # any non-empty hex string
        }
        self.client = AsyncClient(headers=headers)

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

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

        if res_json["meta"]["code"] == 1014:
            raise ValueError("Login failed, probably wrong username/password combination.")

        if res_json["meta"]["code"] == 1015:
            raise ValueError("CAPTCHA hit, please login using Hik-Connect app and then retry.")
            # GET v3/captcha?account=tomasbedrich&featureCode=deadbeef => receives PNG with CATPCHA, the code must be send with next request inside `imageCode` field

        try:
            session_id = res_json["loginSession"]["sessionId"]
        except KeyError as e:
            log.error("Unable to parse session_id from response.")
            log.debug("Response: '%s'", res_json)
            raise ValueError("Login failed for unknown reason.") from e

        log.debug("Parsed session_id: '%s'", session_id)
        self.client.headers.update({"sessionId": session_id})
        log.info("Login successful as username '%s'", username)

    async def get_devices(self):
        """Get info about devices associated with currently logged user."""
        res = await self.client.get(f"{self.BASE_URL}/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=100&offset=0")
        res.raise_for_status()
        log.info("Received device list")
        json = res.json()
        for device in json["deviceInfos"]:
            yield {
                "id": device["fullSerial"],
                "name": device["name"],
                "serial": device["deviceSerial"],
                "type": device["deviceType"],
                "version": device["version"],
            }
        if json["page"]["hasNext"]:
            raise ValueError("More than 100 devices is not supported yet. Please file an issue on GitHub.")

    async def get_cameras(self, device_serial: str):
        """Get info about cameras connected to a device."""
        res = await self.client.get(f"{self.BASE_URL}/v3/userdevices/v1/cameras/info?deviceSerial={device_serial}")
        res.raise_for_status()
        log.info("Received camera info for device '%s'", device_serial)
        for camera in res.json()["cameraInfos"]:
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
        res = await self.client.get(
            f"{self.BASE_URL}/v3/devconfig/v1/call/{device_serial}/status"
        )
        res.raise_for_status()
        log.info("Got call status for device '%s'", device_serial)
        json = res.json()
        # TODO parse
        # At rest looks like this:
        # {"apiId":1,"callStatus":1,"verFlag":1,"callerInfo":{"buildingNo":0,"floorNo":0,"zoneNo":0,"unitNo":0,"devNo":0,"devType":0,"lockNum":0},"rc":1}
        return json["data"]
