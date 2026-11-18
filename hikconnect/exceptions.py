class HikConnectError(Exception):
    pass


class LoginError(HikConnectError, ValueError):
    pass


class DeviceOffline(HikConnectError):
    pass


class UnlockError(HikConnectError):
    pass


class SnapshotError(HikConnectError):
    pass


class StreamError(HikConnectError):
    pass
