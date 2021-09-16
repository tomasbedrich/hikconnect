import asyncio
import logging
import os

import pytest
from dotenv import load_dotenv

from hikconnect.api import HikConnect

pytestmark = pytest.mark.asyncio


async def test_main():
    username = os.getenv("HIKCONNECT_USERNAME")
    password = os.getenv("HIKCONNECT_PASSWORD")
    channel_number = int(os.getenv("HIKCONNECT_CHANNEL_NUMBER", 1))

    async with HikConnect() as hikconnect:
        await hikconnect.login(username, password)
        print(f"{hikconnect.is_refresh_login_needed()=}")

        devices = [device async for device in hikconnect.get_devices()]
        for device in devices:
            print(await hikconnect.get_call_status(device["serial"]))
            async for camera in hikconnect.get_cameras(device["serial"]):
                print(device, camera)

        await asyncio.sleep(1)
        await hikconnect.refresh_login()

        # BEWARE: actually unlocks door!
        print(f"hikconnect.unlock({devices[0]['serial']=}, {channel_number=})")
        # await hikconnect.unlock(devices[0]["serial"], channel_number)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    load_dotenv()
    asyncio.run(test_main())
