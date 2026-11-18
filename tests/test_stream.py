# pylint: disable=protected-access
import asyncio
import base64
import logging
import os
import struct
import zlib
from contextlib import aclosing

import pytest
from aioresponses import aioresponses
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hikconnect import stream
from hikconnect.api import HikConnect
from hikconnect.exceptions import StreamError

SC = b"\x00\x00\x00\x01"
BODY = bytes(range(1, 251)) * 12  # no start code inside
RTP_HEAD = base64.b64encode(b"IMKH\x01\x01\x00\x00\x04\x00\x00\x01" + bytes(28))
PS_HEAD = base64.b64encode(b"IMKH\x01\x01\x00\x00\x02\x00\x00\x01" + bytes(28))
CODE = "ABCDEF"
# first 16 bytes of the NAL units below, encrypted by the reference implementation of
# AES-128 with 3 rounds using CODE as the key
SPS = bytes([0x67]) + bytes(range(1, 40))
IDR = bytes([0x65]) + bytes(range(0x80, 0x80 + 60))
SPS_ENCRYPTED = bytes.fromhex("73c267d155fd6edc07280169dccd0727") + SPS[16:]
IDR_ENCRYPTED = bytes.fromhex("c47034336aa70f5b8f78852f30a69155") + IDR[16:]


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(stream, "BACKOFF", 0)


# --------------------------------------------------------------------------- stream builders


def rtp(payload, timestamp, payload_type=96):
    return struct.pack(">BBHII", 0x80, payload_type, 0, timestamp, 1) + payload


def rtp_stream(count, hevc=False):
    """Return (RTP packets, access units), the first one is a keyframe with parameter sets."""
    packets, units = [], []
    for n in range(count):
        timestamp, unit = 1000 + 3600 * n, b""
        nal_types = [1] if n else ([32, 33, 34, 19] if hevc else [7, 8, 5])
        for nal_type in nal_types:
            header = bytes([nal_type << 1, 1]) if hevc else bytes([0x60 | nal_type])
            if nal_type in (7, 8, 32, 33, 34):
                unit += SC + header + BODY[:20]
                packets.append(rtp(header + BODY[:20], timestamp))
                continue
            unit += SC + header + BODY
            for i in range(0, len(BODY), 1000):
                flags = (0x80 if i == 0 else 0) | (0x40 if i + 1000 >= len(BODY) else 0)
                indicator = bytes([49 << 1, 1]) if hevc else bytes([0x60 | 28])
                packets.append(
                    rtp(
                        indicator + bytes([flags | nal_type]) + BODY[i : i + 1000],
                        timestamp,
                    )
                )
        units.append(unit)
    return packets, units


def pes_pts(pts):
    return bytes(
        [
            0x21 | pts >> 29 & 0x0E,
            pts >> 22 & 0xFF,
            0x01 | pts >> 14 & 0xFE,
            pts >> 7 & 0xFF,
            0x01 | pts << 1 & 0xFE,
        ]
    )


def ps_stream(units, descriptor=b""):
    """One pack per access unit, 3600 ticks apart, split into chunks like a TCP stream."""
    pack = b"\x00\x00\x01\xba" + bytes(10)
    psm = b"\xe0\xff" + struct.pack(">H", len(descriptor)) + descriptor
    psm += struct.pack(">H", 4) + b"\x1b\xe0\x00\x00" + bytes(4)
    res = b""
    for n, unit in enumerate(units):
        res += pack + b"\x00\x00\x01\xbc" + struct.pack(">H", len(psm)) + psm
        for i in range(0, len(unit), 1000):
            header = (
                b"\x80\x00\x00" if i else b"\x80\x80\x05" + pes_pts(5000 + 3600 * n)
            )
            body = header + unit[i : i + 1000]
            res += b"\x00\x00\x01\xe0" + struct.pack(">H", len(body)) + body
    res += pack  # flushes the last access unit
    return [res[i : i + 700] for i in range(0, len(res), 700)]


# --------------------------------------------------------------------------- fake cloud
# Server side of the ECDH envelope, taken from the reference implementation reconstructed
# from the Hik-Connect app.


def public_der(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def chacha(key, seq, data):
    nonce = b"\0\0\0\0" + struct.pack("<I", seq) + b"\0" * 8
    return Cipher(algorithms.ChaCha20(key, nonce), None).encryptor().update(data)


def mac(key, head, ciphertext):
    msg = (f"{zlib.crc32(head)}{zlib.crc32(ciphertext)}".encode() + b"\0" * 8)[:8]
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def enc_req(private_key, peer_public_der, session, data):
    master = private_key.exchange(
        ec.ECDH(), serialization.load_der_public_key(peer_public_der)
    )
    ecb = Cipher(algorithms.AES(master), modes.ECB()).encryptor()
    head = b"\x24\x01\x00" + struct.pack(">H", len(data)) + b"\x01\x01"
    head += struct.pack(">I", 1) + ecb.update(session) + public_der(private_key)
    ciphertext = chacha(session, 1, data)
    return head + ciphertext + mac(master, head, ciphertext)


def enc_data(session, seq, data):
    head = b"\x24\x02\x00" + struct.pack(">H", len(data)) + b"\0\0"
    head += struct.pack(">I", seq)
    ciphertext = chacha(session, seq, data)
    return head + ciphertext + mac(session, head, ciphertext)


def dec(package, private_key, state):
    kind = package[1]
    (length,) = struct.unpack(">H", package[3:5])
    (seq,) = struct.unpack(">I", package[7:11])
    if kind == 1:
        head = 134
        state["peer_public"] = package[43:134]
        master = private_key.exchange(
            ec.ECDH(), serialization.load_der_public_key(state["peer_public"])
        )
        ecb = Cipher(algorithms.AES(master), modes.ECB()).decryptor()
        state["session"] = ecb.update(package[11:43])
        mac_key = master
    else:
        head, mac_key = 11, state["session"]
    ciphertext = package[head : head + length]
    assert mac(mac_key, package[:head], ciphertext) == package[head + length :]
    return chacha(state["session"], seq, ciphertext)


def frame(body, channel, code):
    return struct.pack(">BBHHH", 0x24, channel, len(body), 0, code) + body


class FakeCloud:
    """
    Fake VTM and VTDU servers.

    after: what the VTDU does when all packets are sent - "hold" the connection and answer
    keepalives, "close" it or stay "silent".
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, packets, stream_head=RTP_HEAD, after="hold", private_key=None):
        self.packets, self.stream_head, self.after = packets, stream_head, after
        self.private_key = private_key
        self.vtm_client_public = None
        self.keepalive_result = 0
        self.urls, self.keepalives, self.stops = [], 0, 0
        self.vtm: asyncio.Server = None  # type: ignore[assignment]
        self.vtdu: asyncio.Server = None  # type: ignore[assignment]

    async def __aenter__(self):
        self.vtm = await asyncio.start_server(self._handler(self._vtm), "127.0.0.1", 0)
        self.vtdu = await asyncio.start_server(
            self._handler(self._vtdu), "127.0.0.1", 0
        )
        return self

    async def __aexit__(self, *exc):
        self.vtm.close()
        self.vtdu.close()

    @property
    def vtm_port(self):
        return self.vtm.sockets[0].getsockname()[1]

    def target(self, public_key=None):
        urls = [f"ysproto://vtm/live?dev=X&chn=1&ssn=token{n}" for n in (1, 2)]
        return stream.StreamTarget("127.0.0.1", self.vtm_port, urls, public_key)

    @staticmethod
    def _handler(handle):
        async def run(reader, writer):
            try:
                await handle(reader, writer, {})
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        return run

    async def _read(self, reader, state):
        header = await reader.readexactly(8)
        _, channel, length, _, code = struct.unpack(">BBHHH", header)
        body = await reader.readexactly(length)
        if channel == 0x0A:
            if not self.private_key:
                raise ConnectionError("ECDH is not supported")
            body = dec(body, self.private_key, state)
        return code, stream._pb_decode(body)

    @staticmethod
    def _write(writer, state, body, code):
        if state:
            state["seq"] = state.get("seq", 1) + 1
            body = enc_data(state["session"], state["seq"], body)
        writer.write(frame(body, 0x0A if state else 0x00, code))

    async def _vtm(self, reader, writer, state):
        code, req = await self._read(reader, state)
        assert code == 0x13B and 2 not in req
        self.vtm_client_public = state.get("peer_public")
        port = self.vtdu.sockets[0].getsockname()[1]
        rsp = stream._pb_int(1, 5302) + stream._pb_str(5, "vtmkey")
        rsp += stream._pb_str(7, f"ysproto://127.0.0.1:{port}/live?dev=X&chn=1")
        self._write(writer, state, rsp, 0x13C)

    async def _vtdu(self, reader, writer, state):
        code, req = await self._read(reader, state)
        assert code == 0x13B and req[2] == [b"vtmkey"]
        self.urls.append(req[1][0].decode())
        rsp = stream._pb_int(1, 0) + stream._pb_int(2, 7)
        rsp += stream._pb_str(3, self.stream_head) + stream._pb_str(4, "ssn1")
        self._write(writer, state, rsp, 0x13C)
        if state:
            # the stream has its own session, announced by a package without data; the device
            # wraps its key for the client key from the VTM request (NVR-4-E-X, issue #6)
            key, session = ec.generate_private_key(ec.SECP256R1()), os.urandom(32)
            package = enc_req(key, self.vtm_client_public, session, b"")
            writer.write(frame(package, 0x0B, 0x13C))
            for seq, packet in enumerate(self.packets):
                writer.write(frame(enc_data(session, seq + 2, packet), 0x0B, 0x2C84))
        else:
            for packet in self.packets:
                writer.write(frame(packet, 0x01, 0xBE9))
        while self.after != "close":
            code, req = await self._read(reader, state)
            assert req[1] == [b"ssn1"]
            self.stops += code == 0x130
            self.keepalives += code == 0x132
            if code == 0x132 and self.after == "hold":
                rsp = stream._pb_int(1, self.keepalive_result)
                self._write(writer, state, rsp, 0x133)


async def collect(frames, count):
    res = []
    async with asyncio.timeout(5), aclosing(frames):
        async for item in frames:
            res.append(item)
            if len(res) == count:
                break
    return res


def live(cloud, public_key=None, code=None):
    async def get_target():
        return cloud.target(public_key)

    return stream.live(get_target, "X/1", code)


# --------------------------------------------------------------------------- live stream


@pytest.mark.parametrize("hevc", [False, True])
async def test_rtp(hevc):
    packets, units = rtp_stream(4, hevc)
    video_format = b"\x05\x00" if hevc else b"\x00\x01"
    head = base64.b64encode(b"IMKH\x01\x01\x00\x00\x04\x00" + video_format + bytes(28))
    async with FakeCloud(packets, head) as cloud:
        frames = await collect(live(cloud), 3)
    assert [f.data for f in frames] == units[:3]
    assert {f.codec for f in frames} == {"h265" if hevc else "h264"}
    assert [f.keyframe for f in frames] == [True, False, False]
    assert [f.pts for f in frames] == [0, 3600, 7200]
    assert cloud.urls == ["ysproto://vtm/live?dev=X&chn=1&ssn=token1"]


async def test_frames_before_keyframe_are_skipped():
    packets, units = rtp_stream(3)
    inter = rtp(
        bytes([0x61]) + BODY[:20], 500
    )  # non-IDR slice of a GOP started earlier
    async with FakeCloud([inter] + packets) as cloud:
        frames = await collect(live(cloud), 2)
    assert [f.data for f in frames] == units[:2]
    assert [f.pts for f in frames] == [0, 3600]


async def test_keepalive_and_stop(monkeypatch):
    monkeypatch.setattr(stream, "KEEPALIVE_INTERVAL", 0.02)
    async with FakeCloud(rtp_stream(2)[0]) as cloud:
        frames = live(cloud)
        await anext(frames)
        await asyncio.sleep(0.2)
        assert cloud.keepalives >= 3
        await frames.aclose()
        await asyncio.sleep(0.05)
        assert cloud.stops == 1


@pytest.mark.parametrize("after", ["close", "silent", "keepalive error"])
async def test_reconnect(monkeypatch, caplog, after):
    monkeypatch.setattr(stream, "STREAM_TIMEOUT", 0.2)
    monkeypatch.setattr(stream, "VIDEO_STALL_TIMEOUT", 0.1)
    caplog.set_level(logging.INFO)
    packets, units = rtp_stream(4)
    async with FakeCloud(packets, after=after.split()[0]) as cloud:
        cloud.after, cloud.keepalive_result = (
            ("hold", 1) if " " in after else (after, 0)
        )
        frames = await collect(live(cloud), 6)
    assert [f.data for f in frames] == units[:3] * 2
    assert [f.pts for f in frames] == [3600 * n for n in range(6)]
    assert [f.keyframe for f in frames] == [True, False, False] * 2
    assert len(cloud.urls) == 2
    reason = {"close": "IncompleteReadError", "silent": "no video data for 0.1 s"}.get(
        after, "keepalive result 1"
    )
    assert f"Reconnecting live stream 'X/1': {reason}" in caplog.text.replace(
        "_Lost('", ""
    )


async def test_ecdh():
    key = ec.generate_private_key(ec.SECP256R1())
    packets, units = rtp_stream(4)
    async with FakeCloud(packets, private_key=key) as cloud:
        frames = await collect(live(cloud, public_der(key)), 3)
    assert [f.data for f in frames] == units[:3]
    assert cloud.urls == ["ysproto://vtm/live?dev=X&chn=1&ssn=token1&ecdh=1"]


async def test_ecdh_falls_back_to_plain(caplog):
    caplog.set_level(logging.INFO)
    key = ec.generate_private_key(ec.SECP256R1())
    packets, units = rtp_stream(4)
    async with FakeCloud(packets) as cloud:
        frames = await collect(live(cloud, public_der(key)), 3)
    assert [f.data for f in frames] == units[:3]
    assert cloud.urls == ["ysproto://vtm/live?dev=X&chn=1&ssn=token2"]
    assert "Unable to open ECDH stream connection" in caplog.text
    assert "Opened plain stream connection" in caplog.text


@pytest.mark.parametrize("stream_head", [PS_HEAD, b""])
async def test_ps(stream_head):
    units = rtp_stream(3)[1]
    async with FakeCloud(ps_stream(units), stream_head) as cloud:
        frames = await collect(live(cloud), 3)
    assert [f.data for f in frames] == units
    assert [f.keyframe for f in frames] == [True, False, False]
    assert [f.pts for f in frames] == [0, 3600, 7200]


async def test_ps_in_rtp():
    units = rtp_stream(3)[1]
    packets = [rtp(chunk, 0) for chunk in ps_stream(units)]
    async with FakeCloud(packets) as cloud:
        frames = await collect(live(cloud), 3)
    assert [f.data for f in frames] == units


@pytest.mark.parametrize("code", [CODE, None])
async def test_ps_encrypted(monkeypatch, caplog, code):
    monkeypatch.setattr(
        stream, "MAX_SKIPPED_FRAMES", 0
    )  # undecrypted, no keyframe is seen
    encrypted = [SC + SPS_ENCRYPTED + SC + IDR_ENCRYPTED] * 2
    packets = ps_stream(encrypted, bytes.fromhex("8006000101100001"))
    async with FakeCloud(packets, PS_HEAD) as cloud:
        frames = await collect(live(cloud, code=code), 2)
    if code:
        assert [(f.data, f.keyframe) for f in frames] == [
            (SC + SPS + SC + IDR, True)
        ] * 2
    else:
        assert [f.data for f in frames] == encrypted
        assert caplog.text.count("Video is encrypted by the device") == 1


@pytest.mark.parametrize("code", [CODE, None])
async def test_rtp_encrypted(monkeypatch, caplog, code):
    monkeypatch.setattr(stream, "MAX_SKIPPED_FRAMES", 0)
    # the descriptor is in an RTP header extension with profile 0x4000 (NVR-4-E-X, issue #6)
    ext = bytes.fromhex("40000002 8006000101100001")
    packets = [
        bytes([0x90]) + rtp(nal, timestamp)[1:12] + ext + nal
        for timestamp in (0, 3600, 7200)
        for nal in (SPS_ENCRYPTED, IDR_ENCRYPTED)
    ]
    async with FakeCloud(packets, RTP_HEAD) as cloud:
        frames = await collect(live(cloud, code=code), 2)
    if code:
        assert [(f.data, f.keyframe) for f in frames] == [
            (SC + SPS + SC + IDR, True)
        ] * 2
    else:
        assert [f.data for f in frames] == [SC + SPS_ENCRYPTED + SC + IDR_ENCRYPTED] * 2
        assert caplog.text.count("Video is encrypted by the device") == 1


async def test_error_after_failed_attempts():
    calls = []
    async with FakeCloud([]) as cloud:
        port = cloud.vtm_port

    async def get_target():
        calls.append(1)
        return stream.StreamTarget("127.0.0.1", port, ["ysproto://vtm/live?ssn=t"])

    with pytest.raises(StreamError, match="in 3 attempts"):
        await collect(stream.live(get_target, "X/1"), 1)
    assert len(calls) == 3


async def test_permanent_error_is_not_retried():
    calls = []

    async def get_target():
        calls.append(1)
        raise StreamError("no stream server")

    with pytest.raises(StreamError, match="no stream server"):
        await collect(stream.live(get_target, "X/1"), 1)
    assert len(calls) == 1


PAGELIST_URL = "https://api.hik-connect.com/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=50&offset=0&filter=VTM,TTS"
CAMERAS_URL = (
    "https://api.hik-connect.com/v3/userdevices/v1/cameras/info?deviceSerial=X"
)
TOKEN_URL = "https://api.hik-connect.com/api/user/token/get"


class TestApi:
    @staticmethod
    def mock_http(mock, vtm):
        mock.get(
            CAMERAS_URL,
            payload={"cameraInfos": [{"channelNo": 2, "streamBizUrl": "biz=1"}]},
            repeat=True,
        )
        mock.post(TOKEN_URL, payload={"tokenArray": ["ut.1", "ut.2"]}, repeat=True)
        mock.get(
            "https://api.hik-connect.com/v3/streaming/vtm/X/2",
            payload={"streamServerConfig": vtm},
        )

    async def test_live_stream(self):
        key = ec.generate_private_key(ec.SECP256R1())
        public_key = {"key": base64.b64encode(public_der(key)).decode(), "version": 1}
        packets, units = rtp_stream(4)
        async with FakeCloud(packets, private_key=key) as cloud, HikConnect() as api:
            vtm = {"domain": "127.0.0.1", "port": cloud.vtm_port}
            with aioresponses() as mock:
                mock.get(
                    PAGELIST_URL,
                    payload={
                        "VTM": {"X": vtm},
                        "TTS": {"X": {"publicKey": public_key}},
                    },
                )
                self.mock_http(mock, vtm)
                frames = await collect(api.live_stream("X", 2, main_stream=False), 3)
        assert [f.data for f in frames] == units[:3]
        (url,) = cloud.urls
        assert url.startswith(
            f"ysproto://127.0.0.1:{vtm['port']}/live?dev=X&chn=2&stream=2&cln=55"
            "&isp=0&auth=1&ssn=ut.1&biz=1&vip=0&timestamp="
        )
        assert url.endswith("&ecdh=1")

    async def test_vtm_fallback(self):
        packets, units = rtp_stream(4)
        async with FakeCloud(packets) as cloud, HikConnect() as api:
            with aioresponses() as mock:
                mock.get(PAGELIST_URL, payload={"page": {"hasNext": False}})
                self.mock_http(mock, {"domain": "127.0.0.1", "port": cloud.vtm_port})
                frames = await collect(api.live_stream("X", 2), 3)
        assert [f.data for f in frames] == units[:3]
        assert "&stream=1&" in cloud.urls[0] and "ecdh" not in cloud.urls[0]

    async def test_no_stream_server(self):
        async with HikConnect() as api:
            with aioresponses() as mock:
                mock.get(PAGELIST_URL, payload={})
                self.mock_http(mock, None)
                with pytest.raises(StreamError, match="no cloud stream server"):
                    await collect(api.live_stream("X", 2), 1)


# --------------------------------------------------------------------------- units


def test_depay_h264():
    depay = stream._RtpDepay(None)
    stap = bytes([24]) + b"\x00\x02\x67\x42\x00\x02\x68\xce"
    fu = [b"\x7c\x85AA", b"\x7c\x05BB", b"\x7c\x45CC"]  # FU-A of an IDR slice
    assert not list(depay.feed(1, b"\x61xx"))  # codec is not known yet
    units = [u for p in [stap] + fu for u in depay.feed(2, p)]
    units += list(depay.feed(3, b"\x61xx"))
    assert units == [
        ("h264", 2, SC + b"\x67\x42" + SC + b"\x68\xce" + SC + b"\x65AABBCC")
    ]


def test_depay_h265():
    depay = stream._RtpDepay(None)
    packets = [b"\x40\x01vps", b"\x62\x01\x93AA", b"\x62\x01\x53BB", b"\x02\x01xx"]
    units = [u for n, p in enumerate(packets) for u in depay.feed(n // 3, p)]
    assert units == [("h265", 0, SC + b"\x40\x01vps" + SC + b"\x26\x01AABB")]
    assert stream._is_keyframe(units[0][2], "h265")


def test_depay_decrypts_by_last_packet():
    # the player decrypts the whole access unit with the type of its last packet (issue #6)
    depay = stream._RtpDepay("h264", CODE.encode().ljust(32, b"\0"))
    packets = [(1, SPS_ENCRYPTED, 0), (1, IDR_ENCRYPTED, 1), (2, IDR_ENCRYPTED, 1)]
    packets += [(2, SPS, 0), (3, b"\x61xx", 0)]
    units = [u for t, p, e in packets for u in depay.feed(t, p, e)]
    assert units == [
        ("h264", 1, SC + SPS + SC + IDR),
        ("h264", 2, SC + IDR_ENCRYPTED + SC + SPS),
    ]
    assert depay.encrypted == 1


def test_foreign_ssrc_is_dropped():
    demuxer = stream._Demuxer(RTP_HEAD, None)
    packets, units = rtp_stream(3)
    foreign = struct.pack(">BBHII", 0x80, 96, 0, 99, 2) + b"\x61garbage"
    res = [
        u[2] for p in packets[:-1] + [foreign] + packets[-1:] for u in demuxer.feed(p)
    ]
    assert res == units[:2]
    assert demuxer.foreign_ssrc == 1


def test_first_slice_valid():
    assert stream._first_slice_valid(SC + SPS + SC + b"\x65\x88xx", "h264")
    assert not stream._first_slice_valid(SC + b"\x41\x08xx", "h264")
    assert stream._first_slice_valid(
        SC + b"\x40\x01vps" + SC + b"\x26\x01\xa0xx", "h265"
    )
    assert stream._first_slice_valid(SC + SPS, "h264") is None


def test_ps_demux_bytewise():
    units = rtp_stream(2)[1]
    data = b"".join(ps_stream(units))
    demux = stream._PsDemux()
    res = [u for i in range(len(data)) for u in demux.feed(data[i : i + 1])]
    assert res == [("h264", 5000, units[0]), ("h264", 8600, units[1])]


def test_stream_head():
    assert stream._parse_stream_head(RTP_HEAD) == ("rtp", "h264")
    head = base64.b64encode(b"IMKH\x01\x01\x00\x00\x02\x00\x05\x00" + bytes(28))
    assert stream._parse_stream_head(head) == ("ps", "h265")
    assert stream._parse_stream_head(b"") == (None, None)
    assert stream._parse_stream_head(b"not base64!") == (None, None)


def test_container_is_sniffed_without_stream_head():
    demuxer = stream._Demuxer(b"", None)
    packets = rtp_stream(2)[0]
    assert [u[0] for p in packets for u in demuxer.feed(p)] == ["h264"]


def test_clock():
    pts = stream._make_clock()
    assert [pts(t) for t in (90000, 93000, 96000)] == [0, 3000, 6000]
    assert pts(None) == 9000
    assert pts(500) == 12000  # new connection
    assert pts(2**32 - 1) == 15000  # jump
    assert pts(2999) == 18000  # wrap-around
    assert pts(5999) == 21000


def test_aes():
    # FIPS-197 C.1
    round_keys = stream._round_keys(bytes(range(16)), 10)
    block = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert stream._aes_decrypt_block(block, round_keys).hex() == (
        "00112233445566778899aabbccddeeff"
    )


@pytest.mark.parametrize("enc_type, hevc", [(2, False), (3, True), (0x12, False)])
def test_decrypt_full_aes(enc_type, hevc):
    key = CODE.encode().ljust(32, b"\0")
    aes = algorithms.AES(key[: 32 if enc_type & 0xF == 3 else 16])
    header, payload = (b"\x26\x01" if hevc else b""), IDR[:50]
    encrypted = Cipher(aes, modes.ECB()).encryptor().update(payload[:48]) + payload[48:]
    extlen = bytes([len(payload), 0]) if enc_type > 0x10 else b""
    nal = SC + header + extlen + encrypted
    assert stream._decrypt(nal * 2, hevc, enc_type, key) == (SC + header + payload) * 2


def test_encrypt_type():
    for descriptor, enc_type in [
        ("8006000101100001", 1),
        ("8006000131100001", 0x11),
        ("8006000101330001", 3),
        ("8006000101300001", 0),
        ("8004000101100001", 0),
    ]:
        assert stream._encrypt_type(bytes.fromhex(descriptor)) == enc_type


def test_envelope():
    server_key = ec.generate_private_key(ec.SECP256R1())
    envelope = stream._Envelope(
        ec.generate_private_key(ec.SECP256R1()), public_der(server_key)
    )
    state: dict = {}
    assert dec(envelope.enc(b"hello"), server_key, state) == b"hello"
    assert envelope.dec(enc_data(state["session"], 2, b"world")) == b"world"
    package = envelope.enc(b"again")
    assert package[1] == 2 and dec(package, server_key, state) == b"again"
    with pytest.raises(ValueError, match="authentication failed"):
        envelope.dec(enc_data(os.urandom(32), 3, b"spoofed"))
