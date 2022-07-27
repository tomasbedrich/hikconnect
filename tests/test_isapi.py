import asyncio
import logging
import os

import pytest
from dotenv import load_dotenv

from tests import ppxml
from hikconnect.api import HikConnect as HikConnectAPI
from hikconnect.isapi.commands.system import DeviceInfo, Capabilities, Time, Reboot
from hikconnect.isapi.transports import HikConnect, Cloud

pytestmark = pytest.mark.asyncio


GOLDER_MASTER = b'<?xml version="1.0" encoding="UTF-8" ?>\n<DeviceInfo version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">\n<deviceName>Embedded Net VIS</deviceName>\n<deviceID>48513037-3531-3633-3634-2428fd4585f8</deviceID>\n<model>DS-KH6320-WTE1</model>\n<serialNumber>DS-KH6320-WTE10120210618WRQ07516364CLU</serialNumber>\n<macAddress>24:28:fd:45:85:f8</macAddress>\n<firmwareVersion>V2.1.34</firmwareVersion>\n<firmwareReleasedDate>build 211118</firmwareReleasedDate>\n<encoderVersion>V1.0</encoderVersion>\n<encoderReleasedDate>build 000000</encoderReleasedDate>\n<deviceType>DVR</deviceType>\n<RS485Num>1</RS485Num>\n<telecontrolID>255</telecontrolID>\n<alarmOutNum>2</alarmOutNum>\n<alarmInNum>8</alarmInNum>\n<customizedInfo></customizedInfo>\n</DeviceInfo>\n'


async def test_hikconnect_transport():
    username = os.environ["HIKCONNECT_USERNAME"]
    password = os.environ["HIKCONNECT_PASSWORD"]
    device_serial = os.environ["DEVICE_SERIAL"]

    async with HikConnectAPI() as hikconnect:
        await hikconnect.login(username, password)
        async with HikConnect(hikconnect, device_serial) as isapi:
            cmd = DeviceInfo()
            res = await isapi.request(cmd)
            assert res == GOLDER_MASTER


async def test_cloud_transport():
    access_token = os.environ["CLOUD_ACCESS_TOKEN"]
    device_serial = os.environ["DEVICE_SERIAL"]

    async with Cloud(access_token, device_serial) as isapi:
        cmd = DeviceInfo()
        res = await isapi.request(cmd)
        assert res == GOLDER_MASTER


async def test_cloud_transport_manual():
    access_token = os.environ["CLOUD_ACCESS_TOKEN"]
    device_serial = os.environ["DEVICE_SERIAL"]

    async with Cloud(access_token, device_serial) as isapi:
        cmd = Time()
        reboot = Reboot()
        for i in range(60):
            print(ppxml(await isapi.request(cmd)))
            await asyncio.sleep(1)
            if i == 4:
                print(ppxml(await isapi.request(reboot)))
                await asyncio.sleep(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    load_dotenv()
    asyncio.run(test_cloud_transport_manual())
