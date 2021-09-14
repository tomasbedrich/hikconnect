import asyncio
import logging
import os

import pytest
from dotenv import load_dotenv

from hikconnect import HikConnect


pytestmark = pytest.mark.asyncio


async def test_main():
    device_serial = os.getenv("HIKCONNECT_DEVICE_SERIAL")
    username = os.getenv("HIKCONNECT_USERNAME")
    password = os.getenv("HIKCONNECT_PASSWORD")
    channel_number = int(os.getenv("HIKCONNECT_CHANNEL_NUMBER"))

    async with HikConnect() as hikconnect:
        await hikconnect.login(username, password)
        async for camera in hikconnect.get_cameras(device_serial):
            print(camera)
        print(await hikconnect.get_callstatus(device_serial))
        # await hikconnect.unlock(device_serial, channel_number)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    load_dotenv()
    asyncio.run(test_main())
