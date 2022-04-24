class HikConnectError(Exception):
    pass


class LoginError(HikConnectError, ValueError):
    pass


class DeviceOffline(HikConnectError):
    pass
