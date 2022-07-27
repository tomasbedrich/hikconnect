import abc
import logging
from datetime import datetime
from urllib.parse import urljoin, urlencode

from aiohttp import ClientSession, FormData, BytesPayload

from hikconnect.api import HikConnect as HikConnectAPI
from hikconnect.exceptions import HikConnectError
from hikconnect.isapi.commands import Command

log = logging.getLogger(__name__)


class Transport(abc.ABC):
    """
    Base for ISAPI transport.

    Each ISAPI transport has to support this interface, regardless of how it is implemented.
    A user can pick whichever transport works better for him and plug it in the middle.
    """

    @abc.abstractmethod
    async def request(self, command: Command) -> bytes:
        ...


# class Local(Transport):
#
#     # request params needed:
#     # HTTP Digest: username
#     # HTTP Digest: password
#     # TODO aiohttp doesn't support Digest auth easily.... :-(
#     # https://github.com/aio-libs/aiohttp/pull/2213
#
#     def __init__(self, username: str, password: str):
#         self.username = username
#         self.password = password
#         self.client = ClientSession(raise_for_status=True)
#
#     pass
#
#     async def __aenter__(self):
#         await self.client.__aenter__()
#         return self
#
#     async def __aexit__(self, exc_type, exc_val, exc_tb):
#         await self.client.__aexit__(exc_type, exc_val, exc_tb)
#
#     async def close(self):
#         await self.client.close()


class Cloud(Transport):
    BASE_URL = "https://ieuopen.ezvizlife.com/api/hikvision/ISAPI"

    # TODO get access token as part of setup of this object
    def __init__(self, access_token: str, device_serial: str):
        headers = {
            "EZO-Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EZO-AccessToken": access_token,
            "EZO-DeviceSerial": device_serial,
        }
        self.client = ClientSession(raise_for_status=True, headers=headers)

    async def request(self, command: Command) -> bytes:
        # TODO timeout
        url = self.BASE_URL + command.url
        if command.body:
            req = self.client.request(
                method=command.method,
                url=url,
                headers={"Content-Type": command.content_type},
                data=command.body,
            )
        else:
            req = self.client.request(method=command.method, url=url)
        async with req as res:
            log.debug("Got ISAPI response '%s'", res)
            if res.headers.get("EZO-Code") != "200":  # use .get() to be more deffensive
                raise HikConnectError(res.headers.get("EZO-Message"))  # FIXME misusing "HikConnect" for non-HikConnect related error
            return await res.read()

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self):
        await self.client.close()


# TODO move hikconnect.api into this class?
class HikConnect(Transport):
    def __init__(self, hikconnect: HikConnectAPI, device_serial: str):
        self.hikconnect = hikconnect
        self.device_serial = device_serial

    async def request(self, command: Command) -> bytes:
        isapi_req = f"{command.method} /ISAPI{command.url}".encode("utf-8")
        if command.method != "GET" and command.body:
            isapi_req = isapi_req + b"\r\n" + command.body

        data = {
            "apiKey": "100044",
            "channelNo": "1",
            "deviceSerial": self.device_serial,
            "apiData": isapi_req,
        }

        # TODO accessing properties (yet public) of HikConnect object smells
        async with self.hikconnect.client.post(
            url=f"{self.hikconnect.BASE_URL}/v3/userdevices/v1/isapi",
            data=BytesPayload(
                urlencode(data, doseq=True, encoding="utf-8").encode(),
                content_type="application/x-www-form-urlencoded",
            ),
        ) as res:
            log.debug("Got ISAPI response '%s'", res)
            return (await res.json())["data"].encode("utf-8")

    async def __aenter__(self):
        await self.hikconnect.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.hikconnect.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self):
        await self.hikconnect.close()
