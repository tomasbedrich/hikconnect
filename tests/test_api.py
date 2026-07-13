import pytest
from aioresponses import aioresponses

from hikconnect.api import HikConnect, LoginError

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def api():
    api = HikConnect()
    yield api
    await api.close()


@pytest.fixture
def valid_login_response():
    """Return anonymized login response with real structure and fields."""
    return {
        "isolate": False,
        "loginTerminalStatus": {"terminalBinded": "0", "terminalOpened": "0"},
        "loginUser": {
            "userId": "foobar",
            "username": "foobar",
            "phone": None,
            "email": "foobar@example.com",
            "confusedPhone": None,
            "confusedEmail": "foo***@example.com",
            "customno": "1234567",
            "areaId": 118,
            "needTrans": False,
            "transferringToStandaloneRegion": False,
            "userCode": "abcdef1234567890",
            "avatarPath": None,
            "contact": None,
            "category": 0,
            "homeTitle": None,
            "location": "110101",
            "regDate": "2020-01-01 10:00:00",
            "langType": "en_US",
            "msgStatus": 0,
        },
        "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
        "hcGvIsolate": False,
        "telphoneCode": "420",
        "loginArea": {
            "apiDomain": "apiieu.hik-connect.com",
            "webDomain": "ieu.hik-connect.com",
            "areaName": "Czech",
            "areaId": 118,
        },
        "loginSession": {
            # anonymized, but valid JWTs - because they are parsed to get the expiration date
            "sessionId": "eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJmb29iYXIiLCJpc3MiOiJ5c2F1dGgiLCJleHAiOjE2MzE2OTk3NTUsImlhdCI6MTYzMTYxMzM1NSwic3ViIjoicyIsImN0IjoiNTUiLCJ0ZCI6MTYzMTYxMzQxNTAzMSwicyI6ImZvb2JhciIsImNuIjoiQW5kcm9pZCBTREsgYnVpbHQgZm8ifQ.XWXdIyAfb5Xiio8YWPR8Ab4-pI-ESVzZTR6AX4lcEz1IiqeZsKooZLkCPcs4mIMw",
            "rfSessionId": "eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJmb29iYXIiLCJpc3MiOiJ5c2F1dGgiLCJleHAiOjE2MzkzODkzNTUsImlhdCI6MTYzMTYxMzM1NSwic3ViIjoicmYiLCJjdCI6IjU1IiwicyI6ImZvb2JhciIsImNuIjoiQW5kcm9pZCBTREsgYnVpbHQgZm8ifQ.bZB0YPtBbjBMNNKwt6d_DxO5_ju5OLFmv__TAFevDXNH22y_QRuR2M68jOHMXGwm",
        },
    }


@pytest.fixture
def refresh_login_response():
    return {
        "sessionInfo": {
            # anonymized, but valid JWTs - because they are parsed to get the expiration date
            "sessionId": "eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJmb29iYXIiLCJpc3MiOiJ5c2F1dGgiLCJleHAiOjE2MzE2OTk3NTUsImlhdCI6MTYzMTYxMzM1NSwic3ViIjoicyIsImN0IjoiNTUiLCJ0ZCI6MTYzMTYxMzQxNTAzMSwicyI6ImZvb2JhciIsImNuIjoiQW5kcm9pZCBTREsgYnVpbHQgZm8ifQ.XWXdIyAfb5Xiio8YWPR8Ab4-pI-ESVzZTR6AX4lcEz1IiqeZsKooZLkCPcs4mIMw",
            "refreshSessionId": "eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJmb29iYXIiLCJpc3MiOiJ5c2F1dGgiLCJleHAiOjE2MzkzODkzNTUsImlhdCI6MTYzMTYxMzM1NSwic3ViIjoicmYiLCJjdCI6IjU1IiwicyI6ImZvb2JhciIsImNuIjoiQW5kcm9pZCBTREsgYnVpbHQgZm8ifQ.bZB0YPtBbjBMNNKwt6d_DxO5_ju5OLFmv__TAFevDXNH22y_QRuR2M68jOHMXGwm",
        },
        "isolate": False,
        "meta": {"code": 200, "message": "............", "moreInfo": None},
        "hcGvIsolate": False,
    }


class TestLogin:
    def _login_response_callback(
        self, url, **kwargs
    ):  # pylint: disable=unused-argument
        expected_body = {
            "account": "username",
            "password": "bf41b974714299201b377a9ab78cf293",
        }
        assert kwargs["data"] == expected_body

    async def test_successful_login(self, api, valid_login_response):
        with aioresponses() as mock:
            mock.post(
                "https://api.hik-connect.com/v3/users/login/v2",
                payload=valid_login_response,
                callback=self._login_response_callback,
            )
            assert api.login_valid_until is None
            await api.login("username", "password-utf-8-žluťoučký")
            assert api.login_valid_until is not None
            assert (
                api.is_refresh_login_needed()
            ), "Should be True because of old timestamp"

    async def test_failed_login(self, api):
        with aioresponses() as mock:
            mock.post(
                "https://api.hik-connect.com/v3/users/login/v2",
                payload={"meta": {"code": 1013}},
            )
            with pytest.raises(LoginError):
                await api.login("username", "wrong_password")
            assert api.login_valid_until is None

    async def test_failed_login_captcha(self, api):
        with aioresponses() as mock:
            mock.post(
                "https://api.hik-connect.com/v3/users/login/v2",
                payload={"meta": {"code": 1015}},
            )
            with pytest.raises(LoginError, match=".*CAPTCHA.*"):
                await api.login("username", "password")
            assert api.login_valid_until is None

    async def test_switch_api_domain(self, api, valid_login_response):
        with aioresponses() as mock:
            mock.post(
                "https://api.hik-connect.com/v3/users/login/v2",
                payload={
                    "meta": {
                        "code": 1100,
                        "message": "客户端需要重定向用户请求域名(海外)",
                        "moreInfo": None,
                    },
                    "loginArea": {
                        "apiDomain": "apiius.hik-connect.com",
                        "webDomain": "ius.hik-connect.com",
                        "areaName": "USA",
                        "areaId": 314,
                    },
                },
            )
            mock.post(
                "https://apiius.hik-connect.com/v3/users/login/v2",
                payload=valid_login_response,
            )
            assert api.login_valid_until is None
            assert api.BASE_URL == "https://api.hik-connect.com"
            await api.login("username", "password")
            assert api.BASE_URL == "https://apiius.hik-connect.com"
            assert api.login_valid_until is not None

    async def test_refresh_login(self, api, refresh_login_response):
        with aioresponses() as mock:
            mock.put(
                "https://api.hik-connect.com/v3/apigateway/login",
                payload=refresh_login_response,
            )
            assert api.login_valid_until is None
            assert api.is_refresh_login_needed()
            api._refresh_session_id = (  # pylint: disable=protected-access
                "dummy_refresh_id"
            )
            await api.refresh_login()
            assert api.login_valid_until is not None


@pytest.fixture
def get_devices_response():
    return {
        "connectionInfos": {
            "D12345678": {
                "localIp": "10.0.0.1",
                "netIp": "81.81.81.81",
                "localRtspPort": 0,
                "netRtspPort": 0,
                "localCmdPort": 9010,
                "netCmdPort": 0,
                "localStreamPort": 9020,
                "netHttpPort": 0,
                "localHttpPort": 0,
                "netStreamPort": 0,
                "netType": 3,
                "wanIp": None,
                "upnp": False,
            }
        },
        "cameraInfos": [],
        "hiddnsInfos": {
            "D12345678": {
                "upnpMappingMode": 0,
                "hiddnsHttpPort": 0,
                "localHiddnsHttpPort": 0,
                "mappingHiddnsHttpPort": 0,
                "mappingHiddnsCmdPort": 0,
                "localHiddnsCmdPort": 0,
                "hiddnsCmdPort": 0,
                "domain": "cas.ys7.com",
            }
        },
        "p2pInfos": {
            "D12345678": [
                {"ip": "34.34.34.34", "port": 6000},
                {"ip": "99.99.99.99", "port": 6000},
            ]
        },
        "alarmNodisturbInfos": {"D12345678": {"alarmEnable": 0, "callingEnable": 0}},
        "kmsInfos": {
            "D12345678": {
                "secretKey": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "version": "101",
            }
        },
        "timePlanInfos": {},
        "statusExtInfos": {"D12345678": {"upgradeAvailable": 0}},
        "meta": {"code": 200, "message": "............", "moreInfo": {}},
        "page": {"offset": 0, "limit": 8, "totalResults": 0, "hasNext": False},
        "statusInfos": {
            "D12345678": {
                "diskNum": 0,
                "globalStatus": 1,
                "pirStatus": 0,
                "isEncrypt": 0,
                "upgradeAvailable": 0,
                "upgradeProcess": 0,
                "upgradeStatus": -1,
                "alarmSoundMode": 0,
                "optionals": {
                    "latestUnbandTime": "1586592421107",
                    "wanIp": "81.81.81.81",
                    "lockNum": '{"1":1,"2":1,"3":2,"4":0,"5":1,"6":1,"7":1,"8":1}',
                    "httpPort": "0",
                    "domain": "D12345678",
                    "OnlineStatus": "1",
                    "cmdPort": "0",
                    "superState": "0",
                    "upnpMappingMode": "0",
                },
            },
        },
        "wifiInfos": {
            "D12345678": {"signal": 75, "address": "10.0.0.1"},
        },
        "switchStatusInfos": {},
        "deviceInfos": [
            {
                "name": "device with locks",
                "deviceSerial": "D12345678",
                "fullSerial": "DS-KH6210-L123456781234567812345678",
                "deviceType": "DS-KH6210-L",
                "devicePicPrefix": "https://devpic.ezvizlife.com/device/image/DVR/",
                "version": "V1.5.1 build 190613",
                "supportExt": '{"11":"0","78":"1","13":"0","26":"4","59":"1","154":"0","1":"0","232":"0","2":"1","233":"0","3":"0","234":9,"4":"0","5":"0","6":"1","7":"0","8":"0","9":"0","30":"0","52":"2","31":"0","10":"1"}',
                "status": 1,
                "userDeviceCreateTime": "2020-10-20 13:11:08",
                "casIp": "eucas.ezvizlife.com",
                "casPort": 6500,
                "channelNumber": 9,
                "hik": True,
                "deviceCategory": "COMMON",
                "deviceSubCategory": "VIS",
                "ezDeviceCapability": '{"264":"1","232":"0","265":"1","233":"0","266":"1","234":1,"268":"1","30":"0","31":"0","262":"1","175":"1","263":"0"}',
                "customType": "DS-KH6210-L",
                "offlineTime": "2021-08-22 10:17:54",
                "offlineNotify": 0,
                "accessPlatform": True,
                "deviceDomain": "D12345678",
                "instructionBook": "http://devpic.ezvizlife.com/device/image/DS-KH6210-L/instruction.jpeg",
                "deviceShareInfo": None,
                "feature": None,
                "riskLevel": 0,
                "offlineTimestamp": 1629627474000,
            },
            {
                "name": "device without locks",
                "deviceSerial": "D66666666",
                "fullSerial": "DS-KH6210-L123456781234567812345678",
                "deviceType": "DS-KH6210-L",
                "devicePicPrefix": "https://devpic.ezvizlife.com/device/image/DVR/",
                "version": "V1.5.1 build 190613",
                "supportExt": '{"11":"0","78":"1","13":"0","26":"4","59":"1","154":"0","1":"0","232":"0","2":"1","233":"0","3":"0","234":9,"4":"0","5":"0","6":"1","7":"0","8":"0","9":"0","30":"0","52":"2","31":"0","10":"1"}',
                "status": 1,
                "userDeviceCreateTime": "2020-10-20 13:11:08",
                "casIp": "eucas.ezvizlife.com",
                "casPort": 6500,
                "channelNumber": 9,
                "hik": True,
                "deviceCategory": "COMMON",
                "deviceSubCategory": "VIS",
                "ezDeviceCapability": '{"264":"1","232":"0","265":"1","233":"0","266":"1","234":1,"268":"1","30":"0","31":"0","262":"1","175":"1","263":"0"}',
                "customType": "DS-KH6210-L",
                "offlineTime": "2021-08-22 10:17:54",
                "offlineNotify": 0,
                "accessPlatform": True,
                "deviceDomain": "D66666666",
                "instructionBook": "http://devpic.ezvizlife.com/device/image/DS-KH6210-L/instruction.jpeg",
                "deviceShareInfo": None,
                "feature": None,
                "riskLevel": 0,
                "offlineTimestamp": 1629627474000,
            },
        ],
    }


async def test_get_devices(api, get_devices_response):
    with aioresponses() as mock:
        mock.get(
            "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=50&offset=0&filter=TIME_PLAN,CONNECTION,SWITCH,STATUS,STATUS_EXT,WIFI,NODISTURB,P2P,KMS,HIDDNS",
            payload=get_devices_response,
        )
        devices = [device async for device in api.get_devices()]
        assert len(devices) == 2
        assert devices[0]["serial"] == "D12345678"
        assert devices[0]["name"] == "device with locks"
        assert devices[0]["type"] == "DS-KH6210-L"
        assert devices[0]["locks"] == {1: 1, 2: 1, 3: 2, 4: 0, 5: 1, 6: 1, 7: 1, 8: 1}
        assert devices[0]["local_ip"] == "10.0.0.1"
        assert devices[0]["wan_ip"] == "81.81.81.81"
        assert devices[0]["is_online"] is True
        assert devices[0]["wifi_signal"] == 75
        assert devices[0]["update_available"] is False
        # device without connectionInfos/statusInfos/wifiInfos entry
        assert devices[1]["local_ip"] is None
        assert devices[1]["wan_ip"] is None
        assert devices[1]["is_online"] is None
        assert devices[1]["wifi_signal"] is None
        assert devices[1]["update_available"] is None


def _base_device(serial, name):
    return {
        "name": name,
        "deviceSerial": serial,
        "fullSerial": f"DS-KH6210-L{serial}",
        "deviceType": "DS-KH6210-L",
        "version": "V1.5.1 build 190613",
    }


def _base_response(devices, connection_infos=None, status_infos=None, wifi_infos=None):
    return {
        "deviceInfos": devices,
        "connectionInfos": connection_infos or {},
        "statusInfos": status_infos or {},
        "wifiInfos": wifi_infos or {},
        "page": {"hasNext": False},
        "meta": {"code": 200},
    }


URL = "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=50&offset=0&filter=TIME_PLAN,CONNECTION,SWITCH,STATUS,STATUS_EXT,WIFI,NODISTURB,P2P,KMS,HIDDNS"


async def test_get_devices_offline_wipes_ip_and_signal(api):
    """IP and WiFi signal must be None when device is offline (globalStatus != 1)."""
    payload = _base_response(
        devices=[_base_device("D11111111", "offline device")],
        connection_infos={"D11111111": {"localIp": "10.0.0.5", "netIp": "1.2.3.4"}},
        status_infos={"D11111111": {"globalStatus": 0, "upgradeAvailable": 0}},
        wifi_infos={"D11111111": {"signal": 80, "address": "10.0.0.5"}},
    )
    with aioresponses() as mock:
        mock.get(URL, payload=payload)
        devices = [d async for d in api.get_devices()]
    assert devices[0]["is_online"] is False
    assert devices[0]["local_ip"] is None
    assert devices[0]["wan_ip"] is None
    assert devices[0]["wifi_signal"] is None
    assert devices[0]["update_available"] is False


async def test_get_devices_local_ip_fallback_to_wifi_address(api):
    """local_ip falls back to wifiInfos.address when localIp is 0.0.0.0."""
    payload = _base_response(
        devices=[_base_device("D22222222", "wifi device")],
        connection_infos={"D22222222": {"localIp": "0.0.0.0", "netIp": "5.5.5.5"}},
        status_infos={"D22222222": {"globalStatus": 1, "upgradeAvailable": 0}},
        wifi_infos={"D22222222": {"signal": 60, "address": "192.168.1.50"}},
    )
    with aioresponses() as mock:
        mock.get(URL, payload=payload)
        devices = [d async for d in api.get_devices()]
    assert devices[0]["local_ip"] == "192.168.1.50"


async def test_get_devices_update_available_true(api):
    """update_available is True when upgradeAvailable is 1."""
    payload = _base_response(
        devices=[_base_device("D33333333", "device needing update")],
        status_infos={"D33333333": {"globalStatus": 1, "upgradeAvailable": 1}},
    )
    with aioresponses() as mock:
        mock.get(URL, payload=payload)
        devices = [d async for d in api.get_devices()]
    assert devices[0]["update_available"] is True


async def test_get_devices_missing_info_dicts(api):
    """All new fields are None when connectionInfos/statusInfos/wifiInfos are absent."""
    payload = {
        "deviceInfos": [_base_device("D44444444", "bare device")],
        "page": {"hasNext": False},
        "meta": {"code": 200},
    }
    with aioresponses() as mock:
        mock.get(URL, payload=payload)
        devices = [d async for d in api.get_devices()]
    assert devices[0]["local_ip"] is None
    assert devices[0]["wan_ip"] is None
    assert devices[0]["is_online"] is None
    assert devices[0]["wifi_signal"] is None
    assert devices[0]["update_available"] is None


async def test_get_devices_pagination(api):
    """Devices spanning two pages are all returned."""
    url_page2 = "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=50&offset=50&filter=TIME_PLAN,CONNECTION,SWITCH,STATUS,STATUS_EXT,WIFI,NODISTURB,P2P,KMS,HIDDNS"
    page1 = _base_response(devices=[_base_device("D55555555", "page1 device")])
    page1["page"] = {"hasNext": True}
    page2 = _base_response(devices=[_base_device("D66666666", "page2 device")])
    with aioresponses() as mock:
        mock.get(URL, payload=page1)
        mock.get(url_page2, payload=page2)
        devices = [d async for d in api.get_devices()]
    assert len(devices) == 2
    assert devices[0]["serial"] == "D55555555"
    assert devices[1]["serial"] == "D66666666"


@pytest.fixture
def get_cameras_response():
    return {
        "cameraInfos": [
            {
                "cameraId": "4203fd7c5f89ce96f8ff0adfdbe8b731",
                "cameraName": "foo",
                "channelNo": 1,
                "cameraCover": "https://ieu.ezvizlife.com/assets/imgs/public/homeDevice.jpeg",
                "deviceSerial": "D12345678",
                "isShow": 1,
                "videoLevel": 2,
                "videoQualityInfos": [
                    {"streamType": 2, "videoLevel": 0},
                    {"streamType": 1, "videoLevel": 2},
                ],
                "streamBizUrl": "biz=1",
                "vtmInfo": {
                    "domain": "vtmcdsfra.ezvizlife.com",
                    "externalIp": "148.148.148.148",
                    "internalIp": None,
                    "port": 8554,
                    "forceStreamType": 0,
                    "isBackup": 0,
                },
                "deviceChannelInfo": {
                    "channelDeviceSerial": "D12345678",
                    "channelNo": 1,
                    "privacyStatus": 0,
                    "powerStatus": 0,
                    "globalStatus": 0,
                    "signalStatus": 1,
                },
                "cameraShareInfo": None,
                "extPermission": None,
            },
            {
                "cameraId": "cd72bc923956952194468738123b7a5e",
                "cameraName": "bar",
                "channelNo": 2,
                "cameraCover": "https://ieu.ezvizlife.com/assets/imgs/public/homeDevice.jpeg",
                "deviceSerial": "D12345678",
                "isShow": 0,
                "videoLevel": 2,
                "videoQualityInfos": [
                    {"streamType": 2, "videoLevel": 0},
                    {"streamType": 1, "videoLevel": 2},
                ],
                "streamBizUrl": "biz=1",
                "vtmInfo": {
                    "domain": "vtmcdsfra.ezvizlife.com",
                    "externalIp": "148.148.148.148",
                    "internalIp": None,
                    "port": 8554,
                    "forceStreamType": 0,
                    "isBackup": 0,
                },
                "deviceChannelInfo": {
                    "channelDeviceSerial": "D12345678",
                    "channelNo": 2,
                    "privacyStatus": 0,
                    "powerStatus": 0,
                    "globalStatus": 0,
                    "signalStatus": 1,
                },
                "cameraShareInfo": None,
                "extPermission": None,
            },
            {
                "cameraId": "d2a2057d853438d9a5b4954baec136e3",
                "cameraName": "baz",
                "channelNo": 3,
                "cameraCover": "https://ieu.ezvizlife.com/assets/imgs/public/homeDevice.jpeg",
                "deviceSerial": "D12345678",
                "isShow": 1,
                "videoLevel": 2,
                "videoQualityInfos": [
                    {"streamType": 2, "videoLevel": 0},
                    {"streamType": 1, "videoLevel": 2},
                ],
                "streamBizUrl": "biz=1",
                "vtmInfo": {
                    "domain": "vtmcdsfra.ezvizlife.com",
                    "externalIp": "148.148.148.148",
                    "internalIp": None,
                    "port": 8554,
                    "forceStreamType": 0,
                    "isBackup": 0,
                },
                "deviceChannelInfo": {
                    "channelDeviceSerial": "D12345678",
                    "channelNo": 3,
                    "privacyStatus": 0,
                    "powerStatus": 0,
                    "globalStatus": 0,
                    "signalStatus": 0,
                },
                "cameraShareInfo": None,
                "extPermission": None,
            },
        ],
        "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
    }


async def test_get_cameras(api, get_cameras_response):
    with aioresponses() as mock:
        mock.get(
            "https://api.hik-connect.com/v3/userdevices/v1/cameras/info?deviceSerial=D12345678",
            payload=get_cameras_response,
        )
        cameras = [camera async for camera in api.get_cameras("D12345678")]
        assert len(cameras) == 3
        assert cameras == [
            {
                "id": "4203fd7c5f89ce96f8ff0adfdbe8b731",
                "name": "foo",
                "channel_number": 1,
                "signal_status": 1,
                "is_shown": 1,
            },
            {
                "id": "cd72bc923956952194468738123b7a5e",
                "name": "bar",
                "channel_number": 2,
                "signal_status": 1,
                "is_shown": 0,
            },
            {
                "id": "d2a2057d853438d9a5b4954baec136e3",
                "name": "baz",
                "channel_number": 3,
                "signal_status": 0,
                "is_shown": 1,
            },
        ]


# ---------------------------------------------------------------------------
# Area (group) management tests
# Real response shapes captured from live API (apiieu.hik-connect.com).
# ---------------------------------------------------------------------------

BASE_URL = "https://api.hik-connect.com"
DEVICE_SERIAL = "D12345678"
GROUP_ID = 242456


@pytest.fixture
def list_areas_response():
    """Real-shaped GET /v3/devices/group/{serial}/list response."""
    return {
        "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
        "list": [
            {
                "groupId": 110548,
                "groupDevSerial": DEVICE_SERIAL,
                "groupName": "aleie",
                "groupType": 2,
                "mode": 1,
                "createTime": 1737221666000,
                "modifyTime": 1737221666000,
            },
            {
                "groupId": GROUP_ID,
                "groupDevSerial": DEVICE_SERIAL,
                "groupName": "Casa",
                "groupType": 2,
                "mode": 0,
                "createTime": 1779641493000,
                "modifyTime": 1779641493000,
            },
        ],
    }


@pytest.fixture
def get_area_response():
    """Real-shaped GET /v3/devices/group/{serial}/{group_id} response."""
    return {
        "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
        "list": [
            {
                "groupId": GROUP_ID,
                "groupDevSerial": DEVICE_SERIAL,
                "memberId": "14f432199e2d4705b7dd728bfa36fb46",
            },
            {
                "groupId": GROUP_ID,
                "groupDevSerial": DEVICE_SERIAL,
                "memberId": "e31335fd6edf44d88a495a58e35aee73",
            },
        ],
    }


@pytest.fixture
def ok_response():
    """Generic success response used for write/delete/arm operations."""
    return {"meta": {"code": 200, "message": "操作成功", "moreInfo": None}}


class TestAreas:
    # ------------------------------------------------------------------ #
    # get_areas                                                            #
    # ------------------------------------------------------------------ #

    async def test_get_areas_yields_correct_shapes(
        self, api, list_areas_response
    ):
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=list_areas_response,
            )
            areas = [area async for area in api.get_areas(DEVICE_SERIAL)]

        assert len(areas) == 2
        assert areas[0] == {
            "group_id": 110548,
            "device_serial": DEVICE_SERIAL,
            "group_name": "aleie",
            "group_type": 2,
            "mode": 1,
            "create_time": 1737221666000,
            "modify_time": 1737221666000,
        }
        assert areas[1]["group_name"] == "Casa"
        assert areas[1]["mode"] == 0

    async def test_get_areas_empty_list(self, api):
        payload = {"meta": {"code": 200}, "list": []}
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=payload,
            )
            areas = [area async for area in api.get_areas(DEVICE_SERIAL)]
        assert areas == []

    # ------------------------------------------------------------------ #
    # get_area                                                             #
    # ------------------------------------------------------------------ #

    async def test_get_area_returns_member_list(self, api, get_area_response):
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=get_area_response,
            )
            members = await api.get_area(DEVICE_SERIAL, GROUP_ID)

        assert len(members) == 2
        assert members[0] == {
            "group_id": GROUP_ID,
            "device_serial": DEVICE_SERIAL,
            "member_id": "14f432199e2d4705b7dd728bfa36fb46",
        }
        assert members[1]["member_id"] == "e31335fd6edf44d88a495a58e35aee73"

    async def test_get_area_empty_group(self, api):
        payload = {"meta": {"code": 200}, "list": []}
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=payload,
            )
            members = await api.get_area(DEVICE_SERIAL, GROUP_ID)
        assert members == []

    # ------------------------------------------------------------------ #
    # create_area                                                          #
    # ------------------------------------------------------------------ #

    async def test_create_area_sends_correct_payload(self, api):
        resource_ids = ["aaa111", "bbb222"]
        captured = {}
        create_response = {
            "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
            "groupInfo": {
                "groupId": 99999,
                "groupDevSerial": DEVICE_SERIAL,
                "groupName": "TestArea",
                "groupType": 2,
                "mode": None,
                "createTime": 1783933420000,
                "modifyTime": 1783933420000,
            },
        }

        def _callback(url, **kwargs):
            captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}",
                payload=create_response,
                callback=_callback,
            )
            result = await api.create_area(DEVICE_SERIAL, "TestArea", resource_ids)

        assert captured["json"] == {
            "groupName": "TestArea",
            "resourceIds": resource_ids,
        }
        # Verify normalized return shape
        assert result == {
            "group_id": 99999,
            "device_serial": DEVICE_SERIAL,
            "group_name": "TestArea",
            "group_type": 2,
            "mode": None,
            "create_time": 1783933420000,
            "modify_time": 1783933420000,
        }

    # ------------------------------------------------------------------ #
    # update_area                                                          #
    # ------------------------------------------------------------------ #

    async def test_update_area_deletes_and_recreates(self, api):
        """update_area must delete the old area then POST to create a new one."""
        destroy_captured = {}
        create_captured = {}
        create_response = {
            "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
            "groupInfo": {
                "groupId": 99998,
                "groupDevSerial": DEVICE_SERIAL,
                "groupName": "UpdatedName",
                "groupType": 2,
                "mode": None,
                "createTime": 1783933420000,
                "modifyTime": 1783933420000,
            },
        }

        def _destroy_cb(url, **kwargs):
            destroy_captured["called"] = True

        def _create_cb(url, **kwargs):
            create_captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.delete(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload={"meta": {"code": 200}},
                callback=_destroy_cb,
            )
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}",
                payload=create_response,
                callback=_create_cb,
            )
            result = await api.update_area(DEVICE_SERIAL, GROUP_ID, "UpdatedName", ["ccc333"])

        assert destroy_captured.get("called") is True
        assert create_captured["json"] == {
            "groupName": "UpdatedName",
            "resourceIds": ["ccc333"],
        }
        assert result["group_id"] == 99998

    # ------------------------------------------------------------------ #
    # delete_area                                                          #
    # ------------------------------------------------------------------ #

    async def test_delete_area_uses_delete_endpoint(self, api, ok_response):
        with aioresponses() as mock:
            mock.delete(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=ok_response,
            )
            # delete_area returns None on success
            result = await api.delete_area(DEVICE_SERIAL, GROUP_ID)

        assert result is None

    # ------------------------------------------------------------------ #
    # set_area_defence_mode                                                #
    # ------------------------------------------------------------------ #

    async def test_set_area_defence_mode_sends_correct_payload(self, api, ok_response):
        captured = {}

        def _callback(url, **kwargs):
            captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/switchDefenceMode",
                payload=ok_response,
                callback=_callback,
            )
            await api.set_area_defence_mode(DEVICE_SERIAL, GROUP_ID, 1)

        assert captured["json"] == {"groupId": GROUP_ID, "mode": 1}

    # ------------------------------------------------------------------ #
    # Convenience wrappers                                                 #
    # ------------------------------------------------------------------ #

    async def test_arm_area_uses_mode_1_by_default(self, api, ok_response):
        captured = {}

        def _callback(url, **kwargs):
            captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/switchDefenceMode",
                payload=ok_response,
                callback=_callback,
            )
            await api.arm_area(DEVICE_SERIAL, GROUP_ID)

        assert captured["json"]["mode"] == 1

    async def test_arm_area_silent_uses_mode_2_by_default(self, api, ok_response):
        captured = {}

        def _callback(url, **kwargs):
            captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/switchDefenceMode",
                payload=ok_response,
                callback=_callback,
            )
            await api.arm_area_silent(DEVICE_SERIAL, GROUP_ID)

        assert captured["json"]["mode"] == 2

    async def test_disarm_area_uses_mode_0(self, api, ok_response):
        captured = {}

        def _callback(url, **kwargs):
            captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/switchDefenceMode",
                payload=ok_response,
                callback=_callback,
            )
            await api.disarm_area(DEVICE_SERIAL, GROUP_ID)

        assert captured["json"]["mode"] == 0


# ---------------------------------------------------------------------------
# edit_area_members tests
# ---------------------------------------------------------------------------

MEMBER_ID_1 = "aaaa1111bbbb2222cccc3333dddd4444"
MEMBER_ID_2 = "eeee5555ffff6666aaaa7777bbbb8888"
MEMBER_ID_3 = "cccc9999dddd0000eeee1111ffff2222"


@pytest.fixture
def _one_member_area_response():
    """GET /v3/devices/group/{serial}/{group_id} with a single member."""
    return {
        "meta": {"code": 200},
        "list": [{"groupId": GROUP_ID, "groupDevSerial": DEVICE_SERIAL, "memberId": MEMBER_ID_1}],
    }


@pytest.fixture
def _two_member_area_response():
    """GET /v3/devices/group/{serial}/{group_id} with two members."""
    return {
        "meta": {"code": 200},
        "list": [
            {"groupId": GROUP_ID, "groupDevSerial": DEVICE_SERIAL, "memberId": MEMBER_ID_1},
            {"groupId": GROUP_ID, "groupDevSerial": DEVICE_SERIAL, "memberId": MEMBER_ID_2},
        ],
    }


@pytest.fixture
def _list_areas_for_edit():
    """GET /v3/devices/group/{serial}/list used by edit_area_members name lookup."""
    return {
        "meta": {"code": 200},
        "list": [
            {
                "groupId": GROUP_ID,
                "groupDevSerial": DEVICE_SERIAL,
                "groupName": "MyArea",
                "groupType": 2,
                "mode": 0,
                "createTime": 1000,
                "modifyTime": 1000,
            }
        ],
    }


class TestEditAreaMembers:
    # Shared recreate response fixture value used across tests
    _RECREATE_RESPONSE = {
        "meta": {"code": 200, "message": "操作成功", "moreInfo": None},
        "groupInfo": {
            "groupId": 300000,
            "groupDevSerial": DEVICE_SERIAL,
            "groupName": "MyArea",
            "groupType": 2,
            "mode": None,
            "createTime": 1800000000000,
            "modifyTime": 1800000000000,
        },
    }

    def _mock_update(self, mock, ok_response, create_callback=None):
        """Register the DELETE → POST(create) mock pair used by update_area."""
        mock.delete(
            f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
            payload=ok_response,
        )
        mock.post(
            f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}",
            payload=self._RECREATE_RESPONSE,
            callback=create_callback,
        )

    # ------------------------------------------------------------------ #
    # add members                                                          #
    # ------------------------------------------------------------------ #

    async def test_add_member_updates_area(
        self, api, _one_member_area_response, _list_areas_for_edit, ok_response
    ):
        """Adding a camera ID appends it to existing members."""
        create_captured = {}

        def _create_cb(url, **kwargs):
            create_captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_one_member_area_response,
            )
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=_list_areas_for_edit,
            )
            self._mock_update(mock, ok_response, create_callback=_create_cb)
            result = await api.edit_area_members(
                DEVICE_SERIAL, GROUP_ID, add_ids=[MEMBER_ID_2]
            )

        assert result["action"] == "updated"
        assert result["group_id"] == 300000
        assert result["member_ids"] == [MEMBER_ID_1, MEMBER_ID_2]
        assert create_captured["json"]["resourceIds"] == [MEMBER_ID_1, MEMBER_ID_2]
        assert create_captured["json"]["groupName"] == "MyArea"

    async def test_add_duplicate_member_is_ignored(
        self, api, _one_member_area_response, _list_areas_for_edit, ok_response
    ):
        """Adding an ID already present must not create duplicates."""
        create_captured = {}

        def _create_cb(url, **kwargs):
            create_captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_one_member_area_response,
            )
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=_list_areas_for_edit,
            )
            self._mock_update(mock, ok_response, create_callback=_create_cb)
            result = await api.edit_area_members(
                DEVICE_SERIAL, GROUP_ID, add_ids=[MEMBER_ID_1]
            )

        assert result["action"] == "updated"
        assert result["member_ids"] == [MEMBER_ID_1]  # no duplicates
        assert create_captured["json"]["resourceIds"] == [MEMBER_ID_1]

    # ------------------------------------------------------------------ #
    # remove members                                                       #
    # ------------------------------------------------------------------ #

    async def test_remove_member_keeps_area_when_others_remain(
        self, api, _two_member_area_response, _list_areas_for_edit, ok_response
    ):
        """Removing one of two members recreates the area with one member."""
        create_captured = {}

        def _create_cb(url, **kwargs):
            create_captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_two_member_area_response,
            )
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=_list_areas_for_edit,
            )
            self._mock_update(mock, ok_response, create_callback=_create_cb)
            result = await api.edit_area_members(
                DEVICE_SERIAL, GROUP_ID, remove_ids=[MEMBER_ID_2]
            )

        assert result["action"] == "updated"
        assert result["member_ids"] == [MEMBER_ID_1]
        assert create_captured["json"]["resourceIds"] == [MEMBER_ID_1]

    async def test_remove_last_member_deletes_area(
        self, api, _one_member_area_response, _list_areas_for_edit, ok_response
    ):
        """Removing the last member must delete the area (not recreate it)."""
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_one_member_area_response,
            )
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=_list_areas_for_edit,
            )
            mock.delete(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=ok_response,
            )
            result = await api.edit_area_members(
                DEVICE_SERIAL, GROUP_ID, remove_ids=[MEMBER_ID_1]
            )

        assert result["action"] == "deleted"
        assert result["group_id"] == GROUP_ID

    # ------------------------------------------------------------------ #
    # add + remove simultaneously                                          #
    # ------------------------------------------------------------------ #

    async def test_add_and_remove_simultaneously(
        self, api, _two_member_area_response, _list_areas_for_edit, ok_response
    ):
        """Can add a new member and remove an existing one in a single call."""
        create_captured = {}

        def _create_cb(url, **kwargs):
            create_captured["json"] = kwargs.get("json") or kwargs.get("data")

        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_two_member_area_response,
            )
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/list",
                payload=_list_areas_for_edit,
            )
            self._mock_update(mock, ok_response, create_callback=_create_cb)
            result = await api.edit_area_members(
                DEVICE_SERIAL,
                GROUP_ID,
                add_ids=[MEMBER_ID_3],
                remove_ids=[MEMBER_ID_1],
            )

        assert result["action"] == "updated"
        # MEMBER_ID_1 removed, MEMBER_ID_2 kept, MEMBER_ID_3 appended
        assert result["member_ids"] == [MEMBER_ID_2, MEMBER_ID_3]

    # ------------------------------------------------------------------ #
    # group_name shortcut                                                  #
    # ------------------------------------------------------------------ #

    async def test_provided_group_name_skips_area_list_call(
        self, api, _one_member_area_response, ok_response
    ):
        """When group_name is passed explicitly, get_areas() must NOT be called."""
        with aioresponses() as mock:
            mock.get(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=_one_member_area_response,
            )
            # update_area = delete + recreate; no /list call should happen
            mock.delete(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}/{GROUP_ID}",
                payload=ok_response,
            )
            mock.post(
                f"{BASE_URL}/v3/devices/group/{DEVICE_SERIAL}",
                payload=self._RECREATE_RESPONSE,
            )
            result = await api.edit_area_members(
                DEVICE_SERIAL,
                GROUP_ID,
                add_ids=[MEMBER_ID_2],
                group_name="ExplicitName",
            )

        assert result["action"] == "updated"

    # ------------------------------------------------------------------ #
    # error cases                                                          #
    # ------------------------------------------------------------------ #

    async def test_raises_when_no_ids_provided(self, api):
        """ValueError if both add_ids and remove_ids are empty."""
        with pytest.raises(ValueError, match="add_ids.*remove_ids"):
            await api.edit_area_members(DEVICE_SERIAL, GROUP_ID)
