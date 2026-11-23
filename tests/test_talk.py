# pylint: disable=protected-access
import asyncio
import re
import struct

import pytest
from aioresponses import aioresponses

from hikconnect import talk
from hikconnect.api import HikConnect
from hikconnect.exceptions import StreamError

URL = "tts://127.0.0.1:1/talk?dev=X&chann=1&encodetype=1&authssn=ut.1&cln=55&talktype=0"
START_RE = re.compile(
    rb'\{\r\n"url":"(?P<url>[^"]*)",\r\n"timestamp":"(?P<ts>\d+)",\r\n'
    rb'"uuid":"(?P<uuid>[0-9a-f-]{36})"\r\n\}'
)
OK = (2, 1, 0, b"audio_code_type=G711_A;audio_code_value=2;uuid=x")


def msg(type_, cmd, result, body=b""):
    return struct.pack(">4I", type_, cmd, result, len(body)) + body


class FakeTts:
    """
    The TTS server as CTalkClnSession expects it: [type, cmd, result, length] headers, a
    response to the start request, then audio packets until the stop message.
    """

    def __init__(self, response=OK, downlink=()):
        self.response, self.downlink = response, downlink
        self.messages: list[tuple[int, int, int, bytes]] = []
        self.closed = asyncio.Event()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()

    async def _handle(self, reader, writer):
        try:
            self.messages.append(await self._read(reader))
            writer.write(msg(*self.response))
            for packet in self.downlink:
                writer.write(packet)
            await writer.drain()
            while self.messages[-1][:2] != (1, 2):
                self.messages.append(await self._read(reader))
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
            self.closed.set()

    @staticmethod
    async def _read(reader):
        type_, cmd, result, length = struct.unpack(">4I", await reader.readexactly(16))
        return type_, cmd, result, await reader.readexactly(length)


async def open_fake(tts, url=URL):
    return await talk.open_talk("127.0.0.1", tts.port, url)


async def test_start_send_stop():
    async with FakeTts() as tts:
        async with await open_fake(tts) as session:
            assert (session.codec, session.codec_name) == (2, "G711_A")
            await session.send(b"\xd5" * 160)
            await session.send(b"\x01" * 3)
        await tts.closed.wait()
    start, audio1, audio2, stop = tts.messages
    assert start[:3] == (1, 4, 0)
    match = START_RE.fullmatch(start[3])
    assert match and match["url"] == URL.encode() + b"&tls=0"
    assert audio1 == (3, 0x4100, 0, b"\xd5" * 160)
    assert audio2 == (3, 0x4100, 0, b"\x01" * 3)
    assert stop == (1, 2, 0, URL.encode())


async def test_downlink_until_server_stops():
    packets = [msg(3, 0, 0, b"a" * 160), msg(2, 5, 0), msg(3, 0, 0, b"b" * 3)]
    async with FakeTts(downlink=packets + [msg(2, 2, 0)]) as tts:
        async with await open_fake(tts) as session:
            assert [p async for p in session.received()] == [b"a" * 160, b"b" * 3]
            with pytest.raises(StreamError, match="ended"):
                await session.send(b"x")


@pytest.mark.parametrize(
    "packet, error",
    [
        (msg(4, 0, 4321), "error 4321"),
        (msg(8, 0, 7), "error 7"),
        (msg(2, 3, 12), "error 12"),
        (msg(3, 0, 0), "Empty audio"),
        (struct.pack(">4I", 3, 0, 0, 0x2C01), "too long"),
    ],
)
async def test_downlink_errors(packet, error):
    async with FakeTts(downlink=[msg(3, 0, 0, b"a"), packet]) as tts:
        async with await open_fake(tts) as session:
            received = []
            with pytest.raises(StreamError, match=error):
                async for packet in session.received():
                    received.append(packet)
            assert received == [b"a"]


async def test_server_closes_connection():
    async with FakeTts(response=OK) as tts:
        async with await open_fake(tts) as session:
            session._writer.write(
                msg(1, 2, 0)
            )  # the fake server ends on a stop message
            with pytest.raises(StreamError, match="closed"):
                [p async for p in session.received()]


@pytest.mark.parametrize(
    "response, error",
    [
        ((4, 0, 20, b""), "error 20"),
        ((2, 3, 21, b""), "error 21"),
        ((2, 1, 5, b"timestamp=1&uuid=x&cln=55"), "result 5"),
        ((2, 7, 0, b""), "type 2, cmd 7"),
        ((6, 1, 0, b"\x24\x01"), "type 6, cmd 1"),
        ((3, 1, 0, b""), "response type 3"),
    ],
)
async def test_start_refused(response, error):
    async with FakeTts(response=response) as tts:
        with pytest.raises(StreamError, match=error):
            await open_fake(tts)


async def test_redirect():
    async with FakeTts() as target:
        new_url = f"tts://127.0.0.1:{target.port}/talk://redirected?dev=X"
        async with FakeTts(response=(2, 1, 6, new_url.encode() + b"\0junk")) as first:
            async with await open_fake(first) as session:
                assert session.codec == 2
        await target.closed.wait()
    (start,) = first.messages
    first_start, stop = target.messages
    assert START_RE.fullmatch(first_start[3])["url"] == new_url.encode() + b"&tls=0"
    # the session keeps its timestamp and UUID
    assert (
        START_RE.fullmatch(start[3])["uuid"]
        == START_RE.fullmatch(first_start[3])["uuid"]
    )
    assert stop == (1, 2, 0, new_url.encode())


@pytest.mark.parametrize(
    "body", [b"tts://127.0.0.1:1/talk?dev=X", b"tts://127.0.0.1/talk://"]
)
async def test_bad_redirect(body):
    async with FakeTts(response=(2, 1, 6, body)) as tts:
        with pytest.raises(StreamError, match="redirect"):
            await open_fake(tts)


async def test_only_one_redirect():
    async with FakeTts(response=(2, 1, 6, b"")) as target:
        body = f"tts://127.0.0.1:{target.port}/talk://".encode()
        target.response = (2, 1, 6, body)
        with pytest.raises(StreamError, match="result 6"):
            await open_fake(target)


async def test_send_checks_length():
    async with FakeTts() as tts:
        async with await open_fake(tts) as session:
            for audio in (b"", bytes(talk.MAX_SEND + 1)):
                with pytest.raises(ValueError):
                    await session.send(audio)


# CTalkClnSession::IdentifyDevAudioCodeType: first name in CODECS found anywhere in the body
@pytest.mark.parametrize(
    "name, value",
    [
        ("G722", 0),
        ("G711_MU", 1),
        ("G711_A", 2),
        ("G723", 3),
        ("MP1L2", 4),
        ("MP2L2", 5),
        ("G726", 6),
        ("AAC", 7),
        ("G726_A", 6),
        ("G726_16", 6),
        ("G729", 10),
        ("ADPCM", 11),
        ("AMR_NB", 12),
        ("RAW_DATA8", 13),
        ("RAW_UDATA16", 14),
        ("MP2L2_32", 5),
        ("MP2L2_64", 5),
        ("AAC_32", 7),
        ("AAC_64", 7),
        ("OPUS_8", 19),
        ("OPUS_16", 20),
        ("OPUS_48", 21),
        ("G729_A", 10),
        ("G729_B", 10),
        ("PCM", 24),
        ("MP3", 25),
        ("AC3", 26),
        ("G726_32", 6),
        ("RAW", 99),
        ("UNKNOWN", 1),
    ],
)
async def test_codec_type(name, value):
    assert talk._codec(f"result=0&audio_code_type={name}&x=1") == value
    async with FakeTts(response=(2, 1, 0, f"audio_code_type={name}".encode())) as tts:
        async with await open_fake(tts) as session:
            assert session.codec == value


@pytest.mark.parametrize(
    "text, value",
    [
        ("audio_code_value=21;", 21),
        ("x=1;audio_code_value= 7;audio_code_type=G711_A", 7),
        ("audio_code_value=x;audio_code_type=G722", 1),
        # without ";" after the value the type decides
        ("audio_code_value=21&audio_code_type=G722", 0),
        ("audio_code_value=21", 1),
        ("", 1),
        ("G722", 1),
    ],
)
def test_codec_value(text, value):
    assert talk._codec(text) == value


async def test_api_talk():
    pagelist = (
        "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist"
        "?groupId=-1&limit={}&offset={}&filter=TTS"
    )
    async with FakeTts() as tts, HikConnect() as api:
        with aioresponses() as mock:
            mock.get(
                pagelist.format(50, 0), payload={"TTS": {}, "page": {"hasNext": True}}
            )
            mock.get(
                pagelist.format(50, 50),
                payload={"TTS": {"X": {"domain": "127.0.0.1", "port": tts.port}}},
            )
            mock.post(
                "https://api.hik-connect.com/api/user/token/get",
                payload={"tokenArray": ["ut.1"]},
            )
            async with api.talk("X", 3) as session:
                assert session.codec == 2
    url = START_RE.fullmatch(tts.messages[0][3])["url"].decode()
    assert url == (
        f"tts://127.0.0.1:{tts.port}/talk?dev=X&chann=3&encodetype=1&authssn=ut.1"
        "&cln=55&talktype=0&tls=0"
    )


async def test_api_no_talk_server():
    async with HikConnect() as api:
        with aioresponses() as mock:
            mock.get(
                "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist"
                "?groupId=-1&limit=50&offset=0&filter=TTS",
                payload={"TTS": {"X": {"publicKey": {}}}},
            )
            with pytest.raises(StreamError, match="no cloud talk server"):
                async with api.talk("X", 1):
                    pass
