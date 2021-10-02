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
    # {"apiId":1,"callStatus":1,"verFlag":1,"callerInfo":{"buildingNo":0,"floorNo":0,"zoneNo":0,"unitNo":0,"devNo":0,"devType":0,"lockNum":0},"rc":1}
    
    await api.unlock(my_device_serial, 1)

    # call this periodically at least once per 30 mins!
    if api.is_refresh_login_needed():
        await api.refresh_login()
```
