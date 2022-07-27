from hikconnect.isapi.commands import Command, ContentType


class DeviceInfo(Command):
    url = "/System/deviceInfo"
    return_type = ContentType.XML


class Capabilities(Command):
    url = "/System/capabilities"
    return_type = ContentType.XML


class Time(Command):
    url = "/System/time"
    return_type = ContentType.XML


class Reboot(Command):
    method = "PUT"
    url = "/System/reboot"
