# Usage

```python
from hikconnect.api import HikConnect

async with HikConnect() as api:

    await api.login("foo", "bar")

    devices = [device async for device in api.get_devices()]
    print(devices)
    # [{
    #   'id': 'DS-XXXXXX-YYYYYYYYYYYYYYYYYYYYYYYYY',
    #   'name': 'DS-XXXXXX-Y(ZZZZZZZZZ)',
    #   'serial': 'ZZZZZZZZZ',
    #   'type': 'DS-XXXXXX-Y',
    #   'version': 'V1.2.3 build 123456',
    #   'locks': {1: 2, 2: 0, 3: 1}
    # }]
    # locks data means (guessing): <channel number>: <number of locks connected>

    my_device_serial = devices[0]["serial"]

    cameras = [camera async for camera in api.get_cameras(my_device_serial)]
    print(cameras)
    # [
    #   {'id': '4203fd7c5f89ce96f8ff0adfdbe8b731', 'name': 'foo', 'channel_number': 1, 'signal_status': 1, 'is_shown': 0},
    #   {'id': 'cd72bc923956952194468738123b7a5e', 'name': 'bar', 'channel_number': 2, 'signal_status': 1, 'is_shown': 1},
    #   {'id': 'd2a2057d853438d9a5b4954baec136e3', 'name': 'baz', 'channel_number': 3, 'signal_status': 0, 'is_shown': 0}
    # ]

    call_status = await api.get_call_status(my_device_serial)
    print(call_status)
    # {
    #   'status': 'idle',
    #   'info': {
    #     'building_number': 0,
    #     'floor_number': 0,
    #     'zone_number': 0,
    #     'unit_number': 0,
    #     'device_number': 0,
    #     'device_type': 0,
    #     'lock_number': 0
    #   }
    # }
    # can be "idle" / "ringing" / "call in progress" - see hikconnect/api.py:45
    
    # Unlock device
    await api.unlock(my_device_serial, 1)
    
    # Cancel call for device
    await api.cancel_call(my_device_serial)

    # call this periodically at least once per 30 mins!
    if api.is_refresh_login_needed():
        await api.refresh_login()
```

If you are new to `async` Python, you simply need to wrap your code in a construction like this:

```python
import asyncio

async def main():
    # put the original code containing `async` keywords here

asyncio.run(main())
```

More info [in the `async` docs](https://docs.python.org/3/library/asyncio.html).
