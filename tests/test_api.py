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
                "globalStatus": 0,
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
        "wifiInfos": {},
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
