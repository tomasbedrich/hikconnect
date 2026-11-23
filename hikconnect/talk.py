"""
Two-way audio ("voice talk") through the Hik-Connect cloud TTS server.

A plain TCP connection of its own (no VTM/VTDU): every message is a header of four big-endian
uint32 [type, cmd, result, length] and a body - a JSON start request, the device codec in the
start response, then raw encoded audio in both directions. Reverse-engineered from
CTalkClnSession of libezstreamclient.so in the Hik-Connect app 7.0.220, see
https://github.com/tomasbedrich/home-assistant-hikconnect/issues/6
"""

import asyncio
import logging
import re
import struct
import time
import uuid
from collections import Counter
from contextlib import suppress
from typing import AsyncIterator

from hikconnect.exceptions import StreamError

log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
# CTalkClnSession::HandleStartMsgExReTry default
RESPONSE_TIMEOUT = 15
# CTalkClnSession::HandleStopMsg sends the stop message with a 1000 ms timeout
STOP_TIMEOUT = 1
# ponytail: frames nobody reads are dropped, the app keeps a 512 KiB buffer instead
RECEIVE_QUEUE = 500

TYPE_REQUEST = 1
TYPE_RESPONSE = 2
TYPE_AUDIO = 3
TYPE_ERROR = 4
CMD_START_RESPONSE = 1
CMD_STOP = 2
CMD_ERROR = 3
CMD_START = 4
# com.ez.stream.VoiceTalk.VOICETALK_BUTTON_NORMAL_CMD, used in full duplex
CMD_AUDIO = 0x4100
RESULT_REDIRECT = 6
# CTalkClnSession::InputTalkAudioDataEx accepts 1 byte .. 1 MiB of audio
MAX_SEND = 1 << 20
# RecvAudioDataRountine ends the session on longer bodies
MAX_RECEIVE = 0x2C00

# CTalkClnSession::IdentifyDevAudioCodeType looks for these names in this order, anywhere in
# the start response, so "AAC" wins over "AAC_32" and "G726" over "G726_16"
CODECS = (
    ("G722", 0),
    ("G711_MU", 1),
    ("G711_A", 2),
    ("G723", 3),
    ("MP1L2", 4),
    ("MP2L2", 5),
    ("G726", 6),
    ("AAC", 7),
    ("G726_A", 8),
    ("G726_16", 9),
    ("G729", 10),
    ("ADPCM", 11),
    ("AMR_NB", 12),
    ("RAW_DATA8", 13),
    ("RAW_UDATA16", 14),
    ("MP2L2_32", 15),
    ("MP2L2_64", 16),
    ("AAC_32", 17),
    ("AAC_64", 18),
    ("OPUS_8", 19),
    ("OPUS_16", 20),
    ("OPUS_48", 21),
    ("G729_A", 22),
    ("G729_B", 23),
    ("PCM", 24),
    ("MP3", 25),
    ("AC3", 26),
    ("G726_32", 27),
    ("RAW", 99),
)
CODEC_NAMES = {value: name for name, value in reversed(CODECS)}
DEFAULT_CODEC = 1  # G711_MU


def _msg(type_: int, cmd: int, body: bytes) -> bytes:
    return struct.pack(">4I", type_, cmd, 0, len(body)) + body


def _start_msg(url: str, timestamp: int, session_id: str) -> bytes:
    # CTalkClnSession::MakeStartMsgEx, plain variant (type 1); tls=0 is the plain TCP flag
    body = (
        f'{{\r\n"url":"{url}&tls=0",\r\n"timestamp":"{timestamp}",\r\n'
        f'"uuid":"{session_id}"\r\n}}'
    )
    return _msg(TYPE_REQUEST, CMD_START, body.encode())


async def _recv_header(reader: asyncio.StreamReader) -> tuple[int, int, int, int]:
    type_, cmd, result, length = struct.unpack(">4I", await reader.readexactly(16))
    return type_, cmd, result, length


async def _recv_body(reader: asyncio.StreamReader, length: int) -> bytes:
    if length > MAX_RECEIVE:
        raise StreamError(f"TTS message of {length} bytes is too long")
    return await reader.readexactly(length)


def _text(body: bytes) -> str:
    # the app reads response bodies as C strings
    return body.split(b"\0", 1)[0].decode(errors="replace")


def _codec(text: str) -> int:
    """Device codec announced in a start response, see CTalkClnSession::IdentifyDevAudioCodeType."""
    start = text.find("audio_code_value")
    end = text.find(";", start) if start >= 0 else -1
    if end >= 0:
        match = re.match(r"audio_code_value=\s*([+-]?\d+)", text[start:end])
        return int(match[1]) if match else DEFAULT_CODEC
    if "audio_code_type" in text:
        return next((value for name, value in CODECS if name in text), DEFAULT_CODEC)
    return DEFAULT_CODEC


def _codec_fields(text: str) -> list[str]:
    """The codec fields of a start response for debug logs, nothing else."""
    return re.findall(r"audio_code_(?:type|value)=[^&;]*", text)


def _redirect_address(text: str) -> tuple[str, int]:
    # CTalkClnSession::DoRedirctOperator: sscanf(body before "talk://", "tts://%[^:]:%d/")
    end = text.find("talk://")
    match = re.match(r"tts://([^:]+):\s*([+-]?\d+)/", text[:end]) if end >= 0 else None
    if not match or not 0 < int(match[2]) < 0x10000:
        raise StreamError("Unable to parse the TTS redirect")
    return match[1], int(match[2])


class Talk:
    """
    A running talk session. Send audio already encoded in `codec`; the device's audio comes
    from `received()`. Close it with `close()` or `async with`.
    """

    def __init__(self, reader, writer, url: str, codec: int):
        self.codec = codec  # value from CODECS, as announced by the device
        self._writer, self._url = writer, url
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue(RECEIVE_QUEUE)
        self._error: Exception | None = None
        self.counts: Counter[str] = Counter()  # packets sent, received and dropped
        self._task = asyncio.create_task(self._read(reader))

    @property
    def codec_name(self) -> str:
        return CODEC_NAMES.get(self.codec, str(self.codec))

    async def send(self, audio: bytes):
        """
        Send one packet of encoded audio right away. The app sends each encoder output as it
        is recorded, i.e. in real time, 20 ms per packet (160 bytes of G.711 at 8 kHz; 16 ms
        without the system echo canceller), so pace the packets the same way.
        """
        if self._task.done():
            raise self._error or StreamError("The talk session has ended")
        if not 0 < len(audio) <= MAX_SEND:
            raise ValueError(f"Audio packet of {len(audio)} bytes is out of range")
        self._writer.write(_msg(TYPE_AUDIO, CMD_AUDIO, audio))
        await self._writer.drain()
        self.counts["sent"] += 1

    async def received(self) -> AsyncIterator[bytes]:
        """Yield packets of the device's audio, encoded in `codec`, until the session ends."""
        while (packet := await self._queue.get()) is not None:
            yield packet
        if self._error:
            raise self._error

    async def _read(self, reader: asyncio.StreamReader):
        # RecvAudioDataRountine
        try:
            while True:
                type_, cmd, result, length = await _recv_header(reader)
                if type_ in (TYPE_ERROR, 8) or cmd == CMD_ERROR:
                    raise StreamError(f"TTS server ended the talk with error {result}")
                if type_ in (TYPE_RESPONSE, 6) and cmd == CMD_STOP:
                    log.info("TTS server stopped the talk")
                    return
                body = await _recv_body(reader, length)
                if type_ != TYPE_AUDIO:
                    log.debug("Ignoring TTS message type %d, cmd %#x", type_, cmd)
                elif not body:
                    raise StreamError("Empty audio packet from the TTS server")
                elif self._queue.full():
                    self.counts["dropped"] += 1
                else:
                    self.counts["received"] += 1
                    self._queue.put_nowait(body)
        except asyncio.IncompleteReadError:
            self._error = StreamError("TTS server closed the connection")
        except (StreamError, OSError) as exc:
            self._error = (
                exc if isinstance(exc, StreamError) else StreamError(repr(exc))
            )
        finally:
            if self._error:
                log.info("Talk session ended: %s", self._error)
            if self._queue.full():
                self._queue.get_nowait()
            self._queue.put_nowait(None)

    async def close(self):
        """Send the stop message (CTalkClnSession::HandleStopMsg) and close the connection."""
        if self._writer.is_closing():
            return
        with suppress(OSError, TimeoutError):
            # CTalkClnSession::MakeStopMsg: the body is the talk URL
            self._writer.write(_msg(TYPE_REQUEST, CMD_STOP, self._url.encode()))
            async with asyncio.timeout(STOP_TIMEOUT):
                await self._writer.drain()
        self._writer.close()
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        log.debug(
            "Closed talk session, %d packets sent, %d received, %d dropped",
            self.counts["sent"],
            self.counts["received"],
            self.counts["dropped"],
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


async def _start(host: str, port: int, url: str, timestamp: int, session_id: str):
    async with asyncio.timeout(CONNECT_TIMEOUT):
        reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(_start_msg(url, timestamp, session_id))
        async with asyncio.timeout(RESPONSE_TIMEOUT):
            type_, cmd, result, length = await _recv_header(reader)
            # CTalkClnSession::SendAndWaitResponse accepts only these types as a response
            if type_ not in (2, 4, 6, 8):
                raise StreamError(f"Unexpected TTS response type {type_}")
            text = _text(await _recv_body(reader, length))
    except BaseException:
        writer.close()
        raise
    return reader, writer, type_, cmd, result, text


async def open_talk(host: str, port: int, url: str) -> Talk:
    """
    Start a talk session on the TTS server `host`:`port` for the `tts://` talk URL.

    Raises:
        StreamError: if the TTS server refuses the talk.
    """
    log.debug(
        "Opening plain talk connection to TTS %s:%d, url parameters %s; the app uses ECDH "
        "only for devices with ECDH v2 for talk (hypothesis: plain works for all)",
        host,
        port,
        re.findall(r"[?&]([^=&]+)=", url),
    )
    # hypothesis: the app takes both from its statistics, any milliseconds and UUID will do
    timestamp, session_id = int(time.time() * 1000), str(uuid.uuid4())
    redirected = False
    while True:
        reader, writer, type_, cmd, result, text = await _start(
            host, port, url, timestamp, session_id
        )
        log.debug(
            "TTS start response: type %d, cmd %d, result %d, codec fields %s",
            type_,
            cmd,
            result,
            _codec_fields(text),
        )
        # CTalkClnSession::HandleStartMsgExReTry
        if type_ == TYPE_RESPONSE and cmd == CMD_START_RESPONSE and result == 0:
            codec = _codec(text)
            log.info("Talk started, device codec %s", CODEC_NAMES.get(codec, codec))
            return Talk(reader, writer, url, codec)
        writer.close()
        if type_ == TYPE_ERROR or cmd == CMD_ERROR:
            raise StreamError(f"TTS server refused the talk with error {result}")
        if type_ != TYPE_RESPONSE or cmd != CMD_START_RESPONSE:
            raise StreamError(f"Unexpected TTS response type {type_}, cmd {cmd}")
        if result != RESULT_REDIRECT or redirected:
            raise StreamError(f"TTS server refused the talk with result {result}")
        # the app follows one redirect, the body is the new URL
        host, port = _redirect_address(text)
        url, redirected = text, True
        log.debug("TTS redirects the talk to %s:%d", host, port)
