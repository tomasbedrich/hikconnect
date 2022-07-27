import abc


# TODO implement ISAPI calls as SansIO

from enum import Enum, auto
from typing import Optional


class ContentType(Enum):
    XML = auto()
    JSON = auto()


class Command:
    """ISAPI command."""
    url: str
    method: str = "GET"
    return_type: Optional[ContentType] = None
    content_type: Optional[ContentType] = None

    @property
    @abc.abstractmethod
    def body(self) -> Optional[bytes]:
        return None

