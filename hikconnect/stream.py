"""
Live video from the Hik-Connect cloud relay.

The client asks a VTM server for a stream, gets redirected to a VTDU relay and receives
RTP or MPEG-PS packets over a proprietary framed TCP protocol ("ysproto"), optionally wrapped
in an ECDH envelope. Reverse-engineered from the Hik-Connect app, see
https://github.com/tomasbedrich/home-assistant-hikconnect/issues/6
"""

# pylint: disable=too-few-public-methods

import asyncio
import base64
import logging
import os
import re
import struct
import time
import zlib
from contextlib import aclosing, suppress
from functools import lru_cache
from typing import AsyncGenerator, Awaitable, Callable, Iterator, NamedTuple

import aiohttp
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hikconnect.exceptions import StreamError

log = logging.getLogger(__name__)

CLIENT_VERSION = "v3.10.1.20260710"
CONNECT_TIMEOUT = 10
KEEPALIVE_INTERVAL = 3
STREAM_TIMEOUT = 20
MAX_ATTEMPTS = 3
BACKOFF = 1

MSG_STOP_REQ = 0x130
MSG_KEEPALIVE_REQ = 0x132
MSG_KEEPALIVE_RSP = 0x133
MSG_STREAM_INFO_REQ = 0x13B
RESULT_REDIRECT = 5302

CHANNEL_MSG = 0x00
CHANNEL_MEDIA = 0x01
CHANNEL_ECDH_MSG = 0x0A
CHANNEL_ECDH_MEDIA = 0x0B
CHANNEL_ECDH_RTP = 0x0C

RTP_VIDEO_PAYLOAD_TYPE = 96
PS_PACK = b"\x00\x00\x01\xba"
PS_CODECS = {0x1B: "h264", 0x24: "h265"}
START_CODE = b"\x00\x00\x00\x01"


class Frame(NamedTuple):
    codec: str  # "h264" or "h265"
    pts: int  # 90 kHz clock, keeps increasing across reconnects
    data: bytes  # one access unit, Annex-B, parameter sets kept in-band
    keyframe: bool  # access unit contains an IDR/IRAP NAL


class StreamTarget(NamedTuple):
    host: str  # VTM server
    port: int
    urls: list[str]  # one per connection attempt, each with its own single-use token
    public_key: bytes | None = None  # DER, enables the ECDH envelope
    key_version: int = 1


class _Lost(Exception):
    """The stream ended or could not be opened; worth a reconnect."""


_RECOVERABLE = (_Lost, OSError, EOFError, ValueError, struct.error, aiohttp.ClientError)
_Unit = tuple[str, int | None, bytes]  # codec, device timestamp, access unit


# --------------------------------------------------------------------------- messages


def _varint(n: int) -> bytes:
    res = bytearray()
    while True:
        res.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(res)


def _pb_str(field: int, value: str | bytes) -> bytes:
    value = value.encode() if isinstance(value, str) else value
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def _pb_int(field: int, n: int) -> bytes:
    return _varint(field << 3) + _varint(n)


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def _pb_decode(data: bytes) -> dict[int, list]:
    i = 0
    res: dict[int, list] = {}
    try:
        while i < len(data):
            key, i = _read_varint(data, i)
            value: int | bytes
            if key & 7 == 0:
                value, i = _read_varint(data, i)
            elif key & 7 == 2:
                n, i = _read_varint(data, i)
                value, i = data[i : i + n], i + n
            else:
                raise ValueError(f"Unsupported protobuf wire type {key & 7}")
            res.setdefault(key >> 3, []).append(value)
    except IndexError as exc:
        raise ValueError("Truncated protobuf message") from exc
    return res


def _stream_info_req(url: str, vtm_stream_key: bytes = b"") -> bytes:
    body = _pb_str(1, url)
    if vtm_stream_key:
        body += _pb_str(2, vtm_stream_key)
    return (
        body + _pb_str(3, CLIENT_VERSION) + _pb_int(4, 0) + _pb_str(6, CLIENT_VERSION)
    )


def _result(rsp: dict[int, list]) -> int:
    return rsp.get(1, [0])[0]


def _frame(body: bytes, channel: int, code: int) -> bytes:
    return struct.pack(">BBHHH", 0x24, channel, len(body), 0, code) + body


def _ysproto_host(url: str) -> tuple[str, int]:
    host, port = url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)
    return host.strip("[]"), int(port)


# --------------------------------------------------------------------------- ECDH envelope


def _chacha(key: bytes, seq: int, data: bytes) -> bytes:
    nonce = b"\0\0\0\0" + struct.pack("<I", seq) + b"\0" * 8
    return Cipher(algorithms.ChaCha20(key, nonce), None).encryptor().update(data)


def _mac(key: bytes, head: bytes, ciphertext: bytes) -> bytes:
    # only the first 8 characters of the two decimal CRCs are authenticated
    msg = f"{zlib.crc32(head)}{zlib.crc32(ciphertext)}".encode()[:8].ljust(8, b"\0")
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(msg)
    return mac.finalize()


class _Envelope:
    """
    One ECDH session: P-256 shared secret (no KDF) as the master key, a random session key,
    ChaCha20 payload, HMAC-SHA256. Type-1 packages carry the session key, type-2 only data.
    """

    def __init__(self, private_key, peer_public_key: bytes = b"", key_version: int = 1):
        self.private_key = private_key
        self._public_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._master = self._exchange(peer_public_key) if peer_public_key else b""
        self._key_version = key_version
        self._session = os.urandom(32)
        self._seq = 1
        self._handshaked = False

    def _exchange(self, peer_public_key: bytes) -> bytes:
        peer = serialization.load_der_public_key(peer_public_key)
        return self.private_key.exchange(ec.ECDH(), peer)

    def enc(self, data: bytes) -> bytes:
        if not self._handshaked:
            ecb = Cipher(algorithms.AES(self._master), modes.ECB()).encryptor()
            head = (
                b"\x24\x01\x00"
                + struct.pack(">HBBI", len(data), 1, self._key_version, 1)
                + ecb.update(self._session)
                + self._public_key
            )
            ciphertext = _chacha(self._session, 1, data)
            return head + ciphertext + _mac(self._master, head, ciphertext)
        self._seq += 1
        head = b"\x24\x02\x00" + struct.pack(">HHI", len(data), 0, self._seq)
        ciphertext = _chacha(self._session, self._seq, data)
        return head + ciphertext + _mac(self._session, head, ciphertext)

    def dec(self, package: bytes) -> bytes:
        if len(package) < 11:
            raise ValueError("Truncated ECDH package")
        kind, ext = package[1], package[2]
        length, _, seq = struct.unpack(">HHI", package[ext + 3 : ext + 11])
        if kind == 1:
            head = ext + 134
            mac_key = self._exchange(package[ext + 43 : head])
            ecb = Cipher(algorithms.AES(mac_key), modes.ECB()).decryptor()
            session = ecb.update(package[ext + 11 : ext + 43])
        elif kind == 2:
            head = ext + 11
            mac_key = session = self._session
        else:
            raise ValueError(f"Unknown ECDH package type {kind}")
        ciphertext = package[head : head + length]
        mac = package[head + length : head + length + 32]
        if _mac(mac_key, package[:head], ciphertext) != mac:
            raise ValueError("ECDH package authentication failed")
        self._session, self._handshaked = session, True
        return _chacha(session, seq, ciphertext)


class _Connection:
    def __init__(self, reader, writer, peer_key: tuple[bytes, int] | None):
        self._reader, self._writer = reader, writer
        self.envelope = (
            _Envelope(ec.generate_private_key(ec.SECP256R1()), *peer_key)
            if peer_key
            else None
        )

    def send(self, body: bytes, code: int):
        if self.envelope:
            self._writer.write(_frame(self.envelope.enc(body), CHANNEL_ECDH_MSG, code))
        else:
            self._writer.write(_frame(body, CHANNEL_MSG, code))

    async def recv(self) -> tuple[int, int, bytes]:
        header = await self._reader.readexactly(8)
        magic, channel, length, _, code = struct.unpack(">BBHHH", header)
        if magic != 0x24:
            raise ValueError(f"Unexpected frame header {header.hex()}")
        return channel, code, await self._reader.readexactly(length)

    async def recv_msg(self) -> dict[int, list]:
        channel, _, body = await self.recv()
        return self.decode_msg(channel, body)

    def decode_msg(self, channel: int, body: bytes) -> dict[int, list]:
        if channel == CHANNEL_ECDH_MSG and self.envelope:
            body = self.envelope.dec(body)
        return _pb_decode(body)

    def check_keepalive(self, channel: int, body: bytes):
        with suppress(ValueError, struct.error):
            result = _result(self.decode_msg(channel, body))
            if result:
                raise _Lost(f"keepalive result {result}")

    def close(self):
        self._writer.close()


async def _request(
    address: tuple[str, int], peer_key: tuple[bytes, int] | None, body: bytes
) -> tuple[_Connection, dict[int, list]]:
    reader, writer = await asyncio.open_connection(*address)
    connection = _Connection(reader, writer, peer_key)
    try:
        connection.send(body, MSG_STREAM_INFO_REQ)
        return connection, await connection.recv_msg()
    except BaseException:
        connection.close()
        raise


async def _negotiate(
    target: StreamTarget, url: str, peer_key: tuple[bytes, int] | None
) -> tuple[_Connection, dict[int, list]]:
    connection, rsp = await _request(
        (target.host, target.port), peer_key, _stream_info_req(url)
    )
    connection.close()
    if _result(rsp) not in (0, RESULT_REDIRECT) or 7 not in rsp:
        raise _Lost(f"VTM refused the stream with result {_result(rsp)}")
    connection, rsp = await _request(
        _ysproto_host(rsp[7][0].decode()),
        peer_key,
        _stream_info_req(url, rsp.get(5, [b""])[0]),
    )
    if _result(rsp) != 0:
        connection.close()
        raise _Lost(f"VTDU refused the stream with result {_result(rsp)}")
    return connection, rsp


async def _open(target: StreamTarget) -> tuple[_Connection, dict[int, list]]:
    peer_keys: list[tuple[bytes, int] | None] = [None]
    if target.public_key:
        peer_keys.insert(0, (target.public_key, target.key_version))
    error: Exception = _Lost("no stream token available")
    for url, peer_key in zip(target.urls, peer_keys):
        mode = "ECDH" if peer_key else "plain"
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                connection, rsp = await _negotiate(
                    target, url + ("&ecdh=1" if peer_key else ""), peer_key
                )
        except _RECOVERABLE as exc:
            log.info("Unable to open %s stream connection: %r", mode, exc)
            error = exc
        else:
            log.info("Opened %s stream connection", mode)
            return connection, rsp
    raise error


# --------------------------------------------------------------------------- video decryption
# "Image and Video Encryption" set on the device: AES-ECB over the beginning of each NAL unit,
# keyed by the device verification code. The most common type is AES-128 cut down to 3 rounds,
# which no library offers.


def _xtime(a: int) -> int:
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _gmul(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a, b = _xtime(a), b >> 1
    return res


def _make_sbox() -> list[int]:
    sbox = [0] * 256
    for x in range(256):
        inv = next((y for y in range(1, 256) if _gmul(x, y) == 1), 0)
        value = inv
        for i in range(1, 5):
            value ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox[x] = value ^ 0x63
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [_SBOX.index(i) for i in range(256)]
_INV_MIX = {m: [_gmul(x, m) for x in range(256)] for m in (9, 11, 13, 14)}


@lru_cache(maxsize=8)
def _round_keys(key: bytes, rounds: int = 3) -> list[list[int]]:
    """AES-128 key schedule truncated to the given number of rounds."""
    words = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    for i in range(4, 4 * (rounds + 1)):
        word = words[i - 1]
        if i % 4 == 0:
            rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36][
                i // 4 - 1
            ]
            word = [_SBOX[b] for b in word[1:] + word[:1]]
            word[0] ^= rcon
        words.append([a ^ b for a, b in zip(words[i - 4], word)])
    return [sum(words[4 * r : 4 * r + 4], []) for r in range(rounds + 1)]


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = [a ^ b for a, b in zip(block, round_keys[-1])]
    for r in range(len(round_keys) - 2, -1, -1):
        state = [
            _INV_SBOX[state[4 * ((col - row) % 4) + row]]
            for col in range(4)
            for row in range(4)
        ]
        state = [a ^ b for a, b in zip(state, round_keys[r])]
        if r:
            mixed = []
            for col in range(4):
                a0, a1, a2, a3 = state[4 * col : 4 * col + 4]
                mixed += [
                    _INV_MIX[14][a0]
                    ^ _INV_MIX[11][a1]
                    ^ _INV_MIX[13][a2]
                    ^ _INV_MIX[9][a3],
                    _INV_MIX[9][a0]
                    ^ _INV_MIX[14][a1]
                    ^ _INV_MIX[11][a2]
                    ^ _INV_MIX[13][a3],
                    _INV_MIX[13][a0]
                    ^ _INV_MIX[9][a1]
                    ^ _INV_MIX[14][a2]
                    ^ _INV_MIX[11][a3],
                    _INV_MIX[11][a0]
                    ^ _INV_MIX[13][a1]
                    ^ _INV_MIX[9][a2]
                    ^ _INV_MIX[14][a3],
                ]
            state = mixed
    return bytes(state)


def _decrypt_blocks(buf: bytearray, pos: int, length: int, enc_type: int, key: bytes):
    """Decrypt whole 16-byte blocks in place, at most 4096 bytes."""
    end = pos + min(length, 4096, len(buf) - pos) // 16 * 16
    if enc_type & 0x0F == 1:
        round_keys = _round_keys(key[:16])
        for i in range(pos, end, 16):
            buf[i : i + 16] = _aes_decrypt_block(buf[i : i + 16], round_keys)
    elif end > pos:
        aes = algorithms.AES(key[: 32 if enc_type & 0x0F == 3 else 16])
        buf[pos:end] = Cipher(aes, modes.ECB()).decryptor().update(bytes(buf[pos:end]))


def _encrypt_type(descriptor: bytes) -> int:
    """
    Parse the PS descriptor `80 06 00 01 b4 b5 b6 01`.

    Returns 0 = none, 1 = AES-128 with 3 rounds, 2 = AES-128, 3 = AES-256, 0x11-0x13 = the same
    with a length field in each NAL unit.
    """
    if len(descriptor) < 8 or descriptor[1] < 6:
        return 0
    algorithm, key_length, mode = (
        descriptor[4] & 0xF,
        descriptor[5] & 0xF,
        descriptor[5] >> 4,
    )
    if algorithm == 1 and key_length == 3 and mode in (2, 3):
        mode = 3
    elif mode not in (1, 2):
        return 0
    return mode + (0x10 if descriptor[4] >> 4 == 3 else 0)


def _nal_spans(data: bytes) -> Iterator[tuple[int, int]]:
    """Yield (start, end) of each NAL unit in an Annex-B stream, without start codes."""
    starts = [m.start() for m in re.finditer(b"\x00\x00\x01", data)]
    for start, end in zip(starts, starts[1:] + [len(data)]):
        if end < len(data) and data[end - 1] == 0:
            end -= 1
        yield start + 3, end


def _next_start_code(data: bytes, pos: int) -> int:
    i = data.find(b"\x00\x00\x01", pos)
    if i < 0:
        return len(data)
    return i - 1 if i > pos and data[i - 1] == 0 else i


def _decrypt_extlen(au: bytes, hevc: bool, enc_type: int, key: bytes) -> bytes:
    """NAL unit = start code | 2-byte header (H.265 only) | length | flags | payload."""
    buf, res, pos = bytearray(au), bytearray(), 0
    while buf[pos : pos + 3] in (b"\x00\x00\x00", b"\x00\x00\x01"):
        head = pos + (3 if buf[pos + 2] else 4) + (2 if hevc else 0)
        if head >= len(buf):
            break
        length_size = 1 + (buf[head] >> 6)
        length = int.from_bytes(buf[head : head + length_size], "big")
        length &= (1 << (8 * length_size - 2)) - 1
        payload = head + length_size + 1
        # the encrypted payload may contain fake start codes, trust the length field
        end = _next_start_code(buf, max(pos + 3, min(head + length, len(buf))))
        _decrypt_blocks(buf, payload, 16 if enc_type == 0x11 else length, enc_type, key)
        res += buf[pos:head] + buf[payload:end]
        pos = end
    return bytes(res)


def _decrypt(au: bytes, hevc: bool, enc_type: int, key: bytes) -> bytes:
    if enc_type > 0x10:
        return _decrypt_extlen(au, hevc, enc_type, key)
    buf = bytearray(au)
    for start, end in _nal_spans(au):
        start += 2 if hevc else 0
        if start + 16 <= end:
            _decrypt_blocks(
                buf, start, 16 if enc_type == 1 else end - start, enc_type, key
            )
    return bytes(buf)


# --------------------------------------------------------------------------- demux


def _is_keyframe(au: bytes, codec: str) -> bool:
    headers = (au[start] for start, end in _nal_spans(au) if start < end)
    if codec == "h265":
        return any(16 <= (header >> 1) & 0x3F <= 23 for header in headers)
    return any(header & 0x1F == 5 for header in headers)


def _parse_stream_head(stream_head: bytes) -> tuple[str | None, str | None]:
    """Return (container, codec) from the base64 encoded 40-byte "IMKH" media header."""
    try:
        head = base64.b64decode(stream_head)
    except ValueError:
        head = b""
    if len(head) < 12 or head[:4] != b"IMKH":
        return None, None
    system_format, video_format = struct.unpack("<HH", head[8:12])
    return (
        {2: "ps", 4: "rtp"}.get(system_format),
        {0x100: "h264", 5: "h265"}.get(video_format),
    )


def _sniff_codec(payload: bytes) -> str | None:
    """Recognize the codec from an RTP payload carrying a parameter set."""
    if len(payload) < 2 or payload[0] & 0x80:
        return None
    # H.265 VPS/SPS/PPS/aggregation packet; these first bytes are unused NAL types in H.264
    if payload[0] >> 1 in (32, 33, 34, 48) and payload[1] == 1:
        return "h265"
    # H.264 SPS/STAP-A; H.265 first byte is never odd and 24 maps to reserved NAL types
    if payload[0] & 0x1F in (7, 24):
        return "h264"
    return None


class _RtpDepay:
    """RFC 6184 (H.264) / RFC 7798 (H.265) payloads to Annex-B access units."""

    def __init__(self, codec: str | None):
        self._codec = codec
        self._sniffed = False
        self._timestamp: int | None = None
        self._au = bytearray()

    def feed(self, timestamp: int, payload: bytes) -> Iterator[_Unit]:
        if not self._sniffed:
            codec = _sniff_codec(payload)
            if codec:
                log.info("Stream codec: %s (stream head says %s)", codec, self._codec)
                self._codec, self._sniffed = codec, True
        if not self._codec:
            return
        # ponytail: an access unit ends when the timestamp changes, which delays it by one
        # frame; use the RTP marker bit if latency matters
        if timestamp != self._timestamp and self._au:
            yield self._codec, self._timestamp, bytes(self._au)
            self._au.clear()
        self._timestamp = timestamp
        self._depay(payload, self._codec == "h265")

    def _depay(self, payload: bytes, hevc: bool):
        header_size = 2 if hevc else 1
        if len(payload) <= header_size:
            return
        nal_type = (payload[0] >> 1) & 0x3F if hevc else payload[0] & 0x1F
        if nal_type == (48 if hevc else 24):  # aggregation packet
            pos = header_size
            while pos + 2 <= len(payload):
                size = int.from_bytes(payload[pos : pos + 2], "big")
                self._au += START_CODE + payload[pos + 2 : pos + 2 + size]
                pos += 2 + size
        elif nal_type == (49 if hevc else 28):  # fragmentation unit
            fu_header = payload[header_size]
            if fu_header & 0x80 and hevc:
                self._au += START_CODE
                self._au += bytes(
                    [(payload[0] & 0x81) | (fu_header & 0x3F) << 1, payload[1]]
                )
            elif fu_header & 0x80:
                self._au += START_CODE + bytes(
                    [(payload[0] & 0xE0) | (fu_header & 0x1F)]
                )
            self._au += payload[header_size + 1 :]
        else:
            self._au += START_CODE + payload


class _PsDemux:
    """MPEG program stream to access units, one per pack."""

    def __init__(self, key: bytes | None):
        self._key = key
        self._buf = bytearray()
        self._es = bytearray()
        self._pts: int | None = None
        self._codec: str | None = None
        self._enc_type = 0
        self._warned = False

    def feed(self, data: bytes) -> Iterator[_Unit]:
        self._buf += data
        buf, pos = self._buf, 0
        while True:
            i = buf.find(b"\x00\x00\x01", pos)
            if i < 0:
                pos = max(pos, len(buf) - 2)
                break
            pos = i
            if i + 6 > len(buf):
                break
            stream_id = buf[i + 3]
            if stream_id < 0xBA:
                pos = i + 3
                continue
            end = i + 6 + int.from_bytes(buf[i + 4 : i + 6], "big")
            if stream_id == 0xBA:  # pack header has a fixed size and stuffing bytes
                end = i + 14 + (buf[i + 13] & 7 if i + 14 <= len(buf) else 0)
            if end > len(buf):
                break
            body = bytes(buf[i + 6 : end])
            if stream_id == 0xBA:
                yield from self._flush()
            elif stream_id == 0xBC:
                self._parse_map(body)
            elif 0xE0 <= stream_id <= 0xEF and len(body) > 3:
                if body[1] & 0x80 and len(body) >= 8 and self._pts is None:
                    self._pts = (
                        (body[3] >> 1 & 7) << 30
                        | body[4] << 22
                        | body[5] >> 1 << 15
                        | body[6] << 7
                        | body[7] >> 1
                    )
                self._es += body[3 + body[2] :]
            pos = end
        del buf[:pos]

    def _parse_map(self, body: bytes):
        i = body.find(b"\x80\x06\x00\x01")
        enc_type = _encrypt_type(body[i : i + 8]) if i >= 0 else 0
        codec = self._codec
        pos = 6 + int.from_bytes(body[2:4], "big")
        while pos + 4 <= len(body) - 4:
            if body[pos] in PS_CODECS:
                codec = PS_CODECS[body[pos]]
                break
            pos += 4 + int.from_bytes(body[pos + 2 : pos + 4], "big")
        if (codec, enc_type) != (self._codec, self._enc_type):
            log.info("Stream codec: %s, device encryption type: %#x", codec, enc_type)
        self._codec, self._enc_type = codec, enc_type

    def _flush(self) -> Iterator[_Unit]:
        es, pts = bytes(self._es), self._pts
        self._es.clear()
        self._pts = None
        if not es or not self._codec:
            return
        if self._enc_type and self._key:
            es = _decrypt(es, self._codec == "h265", self._enc_type, self._key)
        elif self._enc_type and not self._warned:
            self._warned = True
            log.warning(
                "Video is encrypted by the device, set the verification code to decrypt it"
            )
        yield self._codec, pts, es


class _Demuxer:
    """Media packets of either container to access units."""

    def __init__(self, stream_head: bytes, key: bytes | None):
        self._hint, codec = _parse_stream_head(stream_head)
        self._container = "rtp" if self._hint == "rtp" else None
        self._rtp_carries_ps: bool | None = None
        self._rtp = _RtpDepay(codec)
        self._ps = _PsDemux(key)

    def feed(self, packet: bytes) -> Iterator[_Unit]:
        if self._container is None:
            if packet[:3] == b"\x00\x00\x01":
                self._container = "ps"
            elif len(packet) >= 12 and packet[0] >> 6 == 2:
                self._container = "rtp"
            else:
                self._container = self._hint
            if self._container:
                log.info(
                    "Stream container: %s (stream head says %s)",
                    self._container,
                    self._hint,
                )
        if self._container == "ps":
            yield from self._ps.feed(packet)
        elif self._container == "rtp" and len(packet) >= 12 and packet[0] >> 6 == 2:
            yield from self._feed_rtp(packet)

    def _feed_rtp(self, packet: bytes) -> Iterator[_Unit]:
        start = 12 + 4 * (packet[0] & 0x0F)
        if packet[0] & 0x10 and len(packet) >= start + 4:
            start += 4 + 4 * int.from_bytes(packet[start + 2 : start + 4], "big")
        end = len(packet) - (packet[-1] if packet[0] & 0x20 else 0)
        # ponytail: Hikvision sends video as payload type 96; audio and private data are dropped
        if end <= start or packet[1] & 0x7F != RTP_VIDEO_PAYLOAD_TYPE:
            return
        payload = packet[start:end]
        if self._rtp_carries_ps is None:
            self._rtp_carries_ps = payload[:4] == PS_PACK
        if self._rtp_carries_ps:
            yield from self._ps.feed(payload)
        else:
            yield from self._rtp.feed(int.from_bytes(packet[4:8], "big"), payload)


# --------------------------------------------------------------------------- stream


def _make_clock() -> Callable[[int | None], int]:
    """Map device timestamps to a 90 kHz clock, which starts at 0 and never goes back."""
    last, offset, step, started = -3600, 0, 3600, False

    def pts(timestamp: int | None) -> int:
        nonlocal last, offset, step, started
        value = last + step
        delta = 0 if timestamp is None else timestamp + offset - last
        if started and 0 < delta <= 900000:
            value, step = last + delta, min(delta, 18000)
        elif timestamp is not None:
            # new connection, counter wrap-around or a jump of the device clock
            offset = value - timestamp
        last, started = value, True
        return value

    return pts


async def _keepalive(connection: _Connection, body: bytes):
    while True:
        connection.send(body, MSG_KEEPALIVE_REQ)
        await asyncio.sleep(KEEPALIVE_INTERVAL)


def _decrypt_media(
    envelope: _Envelope | None, channel: int, body: bytes
) -> bytes | None:
    """Return a media packet from a frame, None if the frame carries a message."""
    if channel == CHANNEL_MEDIA:
        return body
    if channel not in (CHANNEL_ECDH_MEDIA, CHANNEL_ECDH_RTP) or not envelope:
        return None
    # the 12-byte RTP header stays in clear on the RTP channel
    head = body[:12] if channel == CHANNEL_ECDH_RTP else b""
    try:
        data = envelope.dec(body[len(head) :])
    except (ValueError, struct.error) as exc:
        log.debug("Dropping stream package: %r", exc)
        return b""
    if len(data) <= 1:  # the first package carries only the session key
        return b""
    return bytes([head[0] & 0xDF]) + head[1:] + data if head else data


async def _session(
    target: StreamTarget, key: bytes | None
) -> AsyncGenerator[_Unit, None]:
    """Open one stream connection and yield access units until it dies."""
    connection, rsp = await _open(target)
    ssn = _pb_str(1, rsp.get(4, [b""])[0])
    keepalive = asyncio.create_task(_keepalive(connection, ssn))
    keepalive.add_done_callback(lambda task: task.cancelled() or task.exception())
    # the stream has its own ECDH session, opened by the server with our connection key
    envelope = connection.envelope and _Envelope(connection.envelope.private_key)
    demuxer = _Demuxer(rsp.get(3, [b""])[0], key)
    seen = dict.fromkeys(("video data", "keepalive response"), time.monotonic())
    try:
        while True:
            stale = [
                k for k, v in seen.items() if time.monotonic() - v > STREAM_TIMEOUT
            ]
            if stale:
                raise _Lost(f"no {stale[0]} for {STREAM_TIMEOUT} s")
            try:
                async with asyncio.timeout(STREAM_TIMEOUT):
                    channel, code, body = await connection.recv()
            except TimeoutError:
                continue
            packet = _decrypt_media(envelope, channel, body)
            if packet:
                seen["video data"] = time.monotonic()
                for unit in demuxer.feed(packet):
                    yield unit
            elif packet is None and code == MSG_KEEPALIVE_RSP:
                seen["keepalive response"] = time.monotonic()
                connection.check_keepalive(channel, body)
    finally:
        keepalive.cancel()
        with suppress(Exception):
            connection.send(ssn, MSG_STOP_REQ)
        connection.close()


async def live(
    get_target: Callable[[], Awaitable[StreamTarget]],
    name: str,
    verification_code: str | None = None,
) -> AsyncGenerator[Frame, None]:
    """
    Yield video frames until closed, reconnecting when the stream dies.

    `get_target` is called before each connection. `StreamError` raised from it is not
    retried.
    """
    key = (
        verification_code.encode()[:16].ljust(32, b"\0") if verification_code else None
    )
    pts = _make_clock()
    failures = 0
    while True:
        streaming = False
        try:
            async with aclosing(_session(await get_target(), key)) as units:
                async for codec, timestamp, data in units:
                    streaming = True
                    yield Frame(codec, pts(timestamp), data, _is_keyframe(data, codec))
        except _RECOVERABLE as exc:
            failures = 0 if streaming else failures + 1
            if failures >= MAX_ATTEMPTS:
                raise StreamError(
                    f"Unable to open live stream '{name}' in {failures} attempts: {exc!r}"
                ) from exc
            log.info("Reconnecting live stream '%s': %r", name, exc)
            if failures:
                await asyncio.sleep(BACKOFF * 2 ** (failures - 1))
