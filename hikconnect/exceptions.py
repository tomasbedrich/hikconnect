class HikConnectError(Exception):
    pass


class LoginError(HikConnectError, ValueError):
    pass
