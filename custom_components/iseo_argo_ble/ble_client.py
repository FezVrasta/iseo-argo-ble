"""
ISEO Argo BLE Lock protocol client.

Standalone module — no Home Assistant dependency.
Implements: BLE GATT → SLIP framing → CSL session layer (AES-128-CBC + CBC-MAC) → SBT command frame.

Dependencies: bleak, cryptography
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from bleak import BleakClient
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP224R1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

_LOGGER = logging.getLogger(__name__)

# ── BLE GATT characteristics ──────────────────────────────────────────────────
# GATT service UUID — only visible after connecting, not in advertisements.
BLE_SERVICE_UUID = "00001000-d102-11e1-9b23-00025b00a6a6"
_S2C_UUID        = "00000001-0000-1000-8000-00805f9b34fb"  # notify  (lock → phone)
_C2S_UUID        = "00000002-0000-1000-8000-00805f9b34fb"  # write   (phone → lock)

# ── ISEO advertisement detection ──────────────────────────────────────────────
# ISEO locks advertise 16-bit service UUIDs that encode device type, system state,
# and protocol info.  Device-type UUIDs satisfy (short_uuid & 0xFFC0) == 0xF000
# (range 0xF000–0xF03F, e.g. 0xF001 = X1R_EVO).
# Standard 16-bit UUIDs appear in full 128-bit form: 0000XXXX-0000-1000-8000-00805f9b34fb
_BT_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"

def is_iseo_advertisement(service_uuids: list[str]) -> bool:
    """Return True if the advertisement looks like an ISEO lock.

    Checks for a 16-bit service UUID in the range 0xF000–0xF03F, which the
    Argo app uses as its device-type identifier (DefaultSbtBtAdvertisingParser).
    """
    for uuid in service_uuids:
        lower = uuid.lower()
        if not lower.endswith(_BT_BASE_SUFFIX):
            continue
        prefix = lower.split("-")[0]   # "0000f001"
        if len(prefix) != 8:
            continue
        try:
            short = int(prefix, 16) & 0xFFFF
            if (short & 0xFFC0) == 0xF000:
                return True
        except ValueError:
            pass
    return False

# ── Session key material ──────────────────────────────────────────────────────
_M = bytes([
    0x6A, 0xA6, 0x42, 0xD1, 0xC8, 0xF3, 0x1E, 0x27,
    0x4B, 0x5C, 0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2,
])
_PL = bytes([
    0xCA, 0xB7, 0x60, 0xE2, 0x8C, 0xA6, 0x78, 0x50,
    0xC3, 0xC5, 0xD7, 0x35, 0x53, 0x7D, 0x5F, 0x3D,
])
_SIG = bytes([
    0xDA, 0xB7, 0x60, 0xE2, 0x8C, 0xA6, 0x78, 0x50,
    0xC3, 0xC5, 0xD7, 0x35, 0x53, 0x7D, 0x5F, 0x3D,
])
_BASE_PL_KEY  = bytes(a ^ b for a, b in zip(_PL,  _M))
_BASE_SIG_KEY = bytes(a ^ b for a, b in zip(_SIG, _M))

_LM    = bytes([0x22, 0x33, 0x11, 0x55, 0x44, 0x11, 0x77, 0x22, 0x11, 0x33, 0x44, 0x22, 0x55])
_LABEL = bytes([0x6B, 0x72, 0x52, 0x1D, 0x31, 0x73, 0x24, 0x47, 0x62, 0x40, 0x2D, 0x4D, 0x3B])
_KDF_LABEL = bytes(a ^ b for a, b in zip(_LABEL, _LM))

_CM  = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC])
_CTX = bytes([0x11, 0x37, 0x71, 0xE8, 0x89, 0x99, 0x77, 0x9D, 0xDB, 0x06, 0x67, 0x33])
_KDF_CONTEXT = bytes(a ^ b for a, b in zip(_CTX, _CM))

# ── Protocol constants ────────────────────────────────────────────────────────
_SBT_PREAMBLE = 42602       # 0xA66A
_ADDR_LOCK, _ADDR_APP = 1, 2
_CSL_VERSION = 2
_BLOCK = 16
_ZERO_IV = bytes(16)

_FT_SESSION_REQUEST   = 1
_FT_SESSION_HANDSHAKE = 2
_FT_DATA              = 4

_CRYPTO_SYS_ECDH = 17      # AES128_ECDH224R1_KD56C

_OP_TLV_OPEN            = 43
_OP_TLV_INFO            = 32
_OP_TLV_LOGIN           = 41   # OPCODE_TLV_LOGIN — authenticate as a specific BT user (required before master cmds)
_OP_READ_LOG            = 23   # OPCODE_READ_LOG_INFO — paginated access-log read
_OP_TLV_READ_USER_BLOCK = 36   # OPCODE_TLV_READ_USER_BLOCK — paginated user whitelist read

_LOG_ENTRY_SIZE = 71        # fixed per SbtLogEntryCodec
_LOG_STATUS_EOF = {7, 80}   # status codes that mean "no more entries"

_SBT_STATUS_OK = 0

# SbtInfoClient TLV payload for exchangeInfo (TLV_INFO with client feature level).
# Tag 1 = featureLevel, value = 9 (FL_9) as UINT16 big-endian.
# The Argo app always sends this after the ECDH handshake to tell the lock
# "I support up to FL_9". Without it the lock treats the session as FL_0 and
# returns CMD_UNSUPPORTED (status=3) for FL_3 commands like TLV_LOGIN.
_INFO_CLIENT_PAYLOAD = bytes([0x01, 0x02, 0x00, 0x09])   # tag=1, len=2, FL_9=0x0009

# Capabilities (Tag 4): bit 7 = door status supported
_CAP_DOOR_STATUS = 0x80
# SystemState (Tag 5): bit 11 = door is closed; bits 7-5 = battery level
_STATE_DOOR_CLOSED = 0x0800
_STATE_BATTERY_SHIFT = 5
_STATE_BATTERY_MASK  = 0x7   # 3-bit field

# Battery level enum values (SbtDeviceBatteryLevel)
BATTERY_LEVEL_PERMANENT = 0   # permanently powered
BATTERY_LEVEL_MEASURE   = 1   # measurement required
BATTERY_LEVEL_OK        = 2
BATTERY_LEVEL_LOW       = 3
BATTERY_LEVEL_VERY_LOW  = 4
BATTERY_LEVEL_CRITICAL  = 5

# Human-readable labels for battery level enum
BATTERY_LEVEL_LABELS: dict[int, str] = {
    BATTERY_LEVEL_PERMANENT: "Permanent power",
    BATTERY_LEVEL_MEASURE:   "Measuring",
    BATTERY_LEVEL_OK:        "OK",
    BATTERY_LEVEL_LOW:       "Low",
    BATTERY_LEVEL_VERY_LOW:  "Very low",
    BATTERY_LEVEL_CRITICAL:  "Critical",
}


# ── Public exceptions and result types ───────────────────────────────────────

class IseoError(Exception):
    """Base class for ISEO protocol errors."""


class IseoAuthError(IseoError):
    """Lock rejected our identity (UUID not registered or key mismatch)."""


class IseoConnectionError(IseoError):
    """BLE connection or handshake failed."""


class LockState:
    """Parsed state from a TLV_INFO response."""

    def __init__(
        self,
        door_closed: bool | None,
        firmware_info: str | None = None,
        battery_level: int | None = None,
    ) -> None:
        # None means the lock does not expose a door-contact sensor.
        self.door_closed    = door_closed
        # 8-char ASCII from Tag 2: chars 0-4 = product name, 5-7 = version.
        self.firmware_info  = firmware_info
        # 3-bit enum from SystemState bits 7-5 (see BATTERY_LEVEL_* constants).
        self.battery_level  = battery_level


@dataclass
class UserEntry:
    """A single whitelist entry from the lock."""
    user_type: int  # outer TLV tag: 16=RFID 17=BT 18=PIN 19=INVITATION 20=FP 21=ACCOUNT
    uuid_hex:  str  # hex of raw UUID bytes (32 chars for BT = 16-byte UUID)
    name:      str  # Tag 2 description; empty string if the user has no name set


@dataclass
class LogEntry:
    """A single access-log entry from the lock."""
    event_code:        int       # UINT8 — event type
    extra_description: str       # up to 32 chars, trimmed
    user_info:         str       # up to 32 chars, trimmed (UUID or name)
    list_code:         int       # UINT8 — log list type (0 or 1)
    battery:           int       # UINT8 — battery level at event time
    timestamp:         datetime  # UTC datetime (from UINT32 Unix epoch)

    @classmethod
    def _from_bytes(cls, data: bytes) -> LogEntry:
        """Decode a 71-byte log entry from the wire format."""
        if len(data) != _LOG_ENTRY_SIZE:
            raise ValueError(f"Expected {_LOG_ENTRY_SIZE}B entry, got {len(data)}B")
        event_code        = data[0]
        extra_description = data[1:33].decode("utf-8", errors="replace").rstrip()
        user_info         = data[33:65].decode("utf-8", errors="replace").rstrip()
        list_code         = data[65]
        battery           = data[66]
        ts_unix           = struct.unpack_from(">I", data, 67)[0]
        timestamp         = datetime.fromtimestamp(ts_unix, tz=timezone.utc)
        return cls(event_code, extra_description, user_info, list_code, battery, timestamp)


# ── SLIP ──────────────────────────────────────────────────────────────────────
_SLIP_END, _SLIP_ESC = 0xC0, 0xDB
_SLIP_ESC_END, _SLIP_ESC_ESC = 0xDC, 0xDD

def _slip_encode(data: bytes) -> bytes:
    out = bytearray([_SLIP_END])
    for b in data:
        if b == _SLIP_END:
            out += bytes([_SLIP_ESC, _SLIP_ESC_END])
        elif b == _SLIP_ESC:
            out += bytes([_SLIP_ESC, _SLIP_ESC_ESC])
        else:
            out.append(b)
    out.append(_SLIP_END)
    return bytes(out)

def _slip_decode(data: bytes) -> bytes:
    result, escaped = bytearray(), False
    for b in data:
        if b == _SLIP_END:
            if escaped:
                raise ValueError("SLIP ESC followed by END")
        elif b == _SLIP_ESC:
            escaped = True
        elif escaped:
            escaped = False
            if b == _SLIP_ESC_END:
                result.append(_SLIP_END)
            elif b == _SLIP_ESC_ESC:
                result.append(_SLIP_ESC)
            else:
                raise ValueError(f"Bad SLIP escape 0x{b:02x}")
        else:
            result.append(b)
    return bytes(result)

# ── CRC helpers ───────────────────────────────────────────────────────────────
def _make_crc8_table() -> list[int]:
    poly = 0x8C
    return [
        (lambda c: [c := ((c >> 1) ^ poly) if (c & 1) else (c >> 1) for _ in range(8)] and c)(i)
        for i in range(256)
    ]

def _make_crc16_table() -> list[int]:
    poly = 0x8408
    t = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
        t.append(crc & 0xFFFF)
    return t

_CRC8_TABLE  = _make_crc8_table()
_CRC16_TABLE = _make_crc16_table()

def _crc8(data: bytes) -> int:
    acc = 0
    for b in data:
        acc = _CRC8_TABLE[(acc ^ b) & 0xFF]
    return acc

def _crc16(data: bytes) -> int:
    acc = 0xFFFF
    for b in data:
        acc = (acc >> 8) ^ _CRC16_TABLE[(acc ^ b) & 0xFF]
    return acc & 0xFFFF

def _sbt_checksum(data: bytes) -> int:
    acc = 0
    for b in data:
        tmp = (acc ^ b) & 0xFF
        acc = ((tmp << 1) & 0xFF) | (tmp >> 7)
    return acc & 0xFF

# ── TLV ───────────────────────────────────────────────────────────────────────
def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value

def _parse_tlv(data: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    i = 0
    while i + 1 < len(data):
        tag    = data[i]
        length = data[i + 1]
        i += 2
        if i + length > len(data):
            break
        result[tag] = data[i : i + length]
        i += length
    return result

def _parse_tlv_list(data: bytes) -> list[tuple[int, bytes]]:
    """Like _parse_tlv but returns a list, preserving duplicate tags (e.g. multiple users of the same type)."""
    result: list[tuple[int, bytes]] = []
    i = 0
    while i + 1 < len(data):
        tag    = data[i]
        length = data[i + 1]
        i += 2
        if i + length > len(data):
            break
        result.append((tag, data[i : i + length]))
        i += length
    return result

def _tlv_user_bt(uuid_bytes: bytes, pub_key_bytes: bytes | None = None) -> bytes:
    """
    SbtUserDataTlvCodec format for a BLUETOOTH / BT_SMARTPHONE user.

    Wire: [Tag17][Len][Tag0,1,0x10][Tag1,16,UUID][Tag32,56,PubKey?]
    """
    inner = _tlv(0, bytes([0x10])) + _tlv(1, uuid_bytes)
    if pub_key_bytes is not None:
        assert len(pub_key_bytes) == 56
        inner += _tlv(32, pub_key_bytes)
    return _tlv(17, inner)

# ── AES helpers ───────────────────────────────────────────────────────────────
def _aes_enc(key: bytes, data: bytes, iv: bytes = _ZERO_IV) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()
    return e.update(data) + e.finalize()

def _aes_dec(key: bytes, data: bytes, iv: bytes = _ZERO_IV) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(data) + d.finalize()

def _aes_cbc_mac(key: bytes, data: bytes) -> bytes:
    return _aes_enc(key, data)[-16:]

def _cmac(key: bytes, data: bytes) -> bytes:
    cm = CMAC(algorithms.AES(key), backend=default_backend())
    cm.update(data)
    return cm.finalize()

# ── ECDH ──────────────────────────────────────────────────────────────────────
def _pub_to_bytes(priv: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return raw[1:]  # 56 bytes X||Y, strip 0x04 prefix

def _pub_from_bytes(data: bytes) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(SECP224R1(), b"\x04" + data)

# ── Key derivation ────────────────────────────────────────────────────────────
def _derive_shs_keys(shared: bytes, rnd_c: bytes, rnd_s: bytes) -> tuple[bytes, bytes]:
    kdk = _cmac(rnd_c + rnd_s, shared)
    mac_size = 32
    shs_pl  = _cmac(kdk, _KDF_LABEL + b"\x00" + _KDF_CONTEXT + bytes([mac_size, 0]))
    shs_sig = _cmac(kdk, _KDF_LABEL + b"\x00" + _KDF_CONTEXT + bytes([mac_size, 1]))
    return shs_pl, shs_sig

def _derive_data_keys(
    kb0: bytes, kb2: bytes, shs_pl: bytes, shs_sig: bytes
) -> tuple[bytes, bytes]:
    final_key = kb0 + kb2
    return _aes_enc(final_key, shs_pl), _aes_enc(final_key, shs_sig)

def _shs_encrypt(data: bytes, pl: bytes, sig: bytes) -> bytes:
    return _aes_enc(sig, _aes_enc(pl, data))

def _shs_decrypt(data: bytes, pl: bytes, sig: bytes) -> bytes:
    return _aes_dec(pl, _aes_dec(sig, data))

# ── CSL frame ─────────────────────────────────────────────────────────────────
def _csl_header(ft: int, sid: int, pay_len: int, ta: int) -> bytes:
    flags = ((ft & 7) << 5) | (_CSL_VERSION & 7)
    hdr = bytes([flags]) + struct.pack(">HHH", sid, pay_len, ta)
    return hdr + bytes([_crc8(hdr)])

def _parse_csl_header(raw: bytes) -> dict:
    flags = raw[0]
    sid, plen, ta = struct.unpack_from(">HHH", raw, 1)
    return {
        "frame_type":  (flags >> 5) & 7,
        "is_response": bool(flags & 8),
        "session_id":  sid,
        "payload_len": plen,
        "ta_num":      ta,
        "crc8_ok":     _crc8(raw[:7]) == raw[7],
    }

def _csl_payload_enc(raw: bytes, pl_key: bytes) -> bytes:
    salt    = os.urandom(12)
    raw_len = len(raw)
    inner   = struct.pack(">H", raw_len) + salt
    crc_val = struct.pack(">H", _crc16(inner))
    pad_len = (-raw_len) % _BLOCK
    padding = bytes([pad_len] * pad_len) if pad_len else b""
    pt = crc_val + inner + raw + padding
    return _aes_enc(pl_key, pt)

def _csl_payload_dec(data: bytes, pl_key: bytes) -> bytes:
    pt      = _aes_dec(pl_key, data)
    raw_len = struct.unpack_from(">H", pt, 2)[0]
    return pt[16 : 16 + raw_len]

def _csl_signature(header: bytes, payload: bytes, sig_key: bytes) -> bytes:
    data    = header + payload
    pad_len = (-len(data)) % _BLOCK
    padding = bytes([pad_len] * pad_len) if pad_len else b""
    mac = _aes_cbc_mac(sig_key, data + padding)
    return padding + mac

def _encode_csl(ft: int, sid: int, ta: int, raw: bytes, pl_key: bytes, sig_key: bytes) -> bytes:
    payload = _csl_payload_enc(raw, pl_key)
    header  = _csl_header(ft, sid, len(payload), ta)
    sig     = _csl_signature(header, payload, sig_key)
    return header + payload + sig

# ── SBT frame ─────────────────────────────────────────────────────────────────
def _build_sbt(opcode: int, payload: bytes) -> bytes:
    ts   = int(time.time())
    body = struct.pack(">HHBBBBI", _SBT_PREAMBLE, len(payload),
                       0, _ADDR_APP, _ADDR_LOCK, 0, ts) + bytes([opcode]) + payload
    return body + bytes([_sbt_checksum(body)])

def _parse_sbt(data: bytes) -> dict:
    if len(data) < 14:
        return {"error": f"too short ({len(data)}B)"}
    pre = struct.unpack_from(">H", data)[0]
    if pre != _SBT_PREAMBLE:
        return {"error": f"bad preamble {pre:#06x}"}
    pay_len = struct.unpack_from(">H", data, 2)[0]
    src     = data[5]
    if src == _ADDR_LOCK:
        return {
            "src":     src,
            "opcode":  data[8],
            "status":  data[9],
            "payload": data[13 : 13 + pay_len],
        }
    return {
        "src":     src,
        "opcode":  data[12],
        "payload": data[13 : 13 + pay_len],
    }


# ── Main client ───────────────────────────────────────────────────────────────
class IseoClient:
    """
    Manages a single BLE session with an ISEO X1R lock.

    A new instance should be created per operation — sessions are not
    re-used across calls since the lock terminates them after each command.
    """

    def __init__(self, address: str, uuid_bytes: bytes, identity_priv: Any) -> None:
        self._address       = address
        self._uuid_bytes    = uuid_bytes
        self._identity_priv = identity_priv

        self._rxq      = asyncio.Queue()
        self._slip_buf = bytearray()
        self._sid      = 0
        self._ta       = 1
        self._pl_key   = _BASE_PL_KEY
        self._sig_key  = _BASE_SIG_KEY

    # ── BLE notification handler ───────────────────────────────────────────
    def _on_notify(self, _sender: Any, data: bytearray) -> None:
        self._slip_buf.extend(data)
        while True:
            buf   = self._slip_buf
            start = next((i for i, b in enumerate(buf) if b == _SLIP_END), None)
            if start is None:
                break
            end = next((i for i in range(start + 1, len(buf)) if buf[i] == _SLIP_END), None)
            if end is None:
                break
            frame_raw = bytes(buf[start : end + 1])
            self._slip_buf = buf[end + 1 :]
            try:
                decoded = _slip_decode(frame_raw)
                if decoded:
                    self._rxq.put_nowait(decoded)
            except Exception as exc:
                _LOGGER.debug("SLIP decode error: %s", exc)

    # ── Low-level I/O ──────────────────────────────────────────────────────
    async def _send_raw(self, client: BleakClient, data: bytes) -> None:
        framed = _slip_encode(data)
        _LOGGER.debug("→ BLE [%dB] %s", len(framed), framed.hex())
        await client.write_gatt_char(_C2S_UUID, framed, response=False)

    async def _send_csl(self, client: BleakClient, ft: int, raw: bytes) -> None:
        frame = _encode_csl(ft, self._sid, self._ta, raw, self._pl_key, self._sig_key)
        self._ta += 1
        await self._send_raw(client, frame)

    async def _recv_csl(self, timeout: float = 15.0) -> dict:
        raw = await asyncio.wait_for(self._rxq.get(), timeout=timeout)
        _LOGGER.debug("← BLE [%dB] %s", len(raw), raw.hex())
        hdr = _parse_csl_header(raw)
        if not hdr["crc8_ok"]:
            _LOGGER.warning("CSL header CRC8 mismatch")
        pend = 8 + hdr["payload_len"]
        enc  = raw[8:pend]
        if enc:
            try:
                hdr["raw_data"] = _csl_payload_dec(enc, self._pl_key)
            except Exception as exc:
                _LOGGER.debug("Payload decrypt failed: %s", exc)
                hdr["raw_data"] = enc
        else:
            hdr["raw_data"] = b""
        self._ta = max(self._ta, hdr["ta_num"] + 1)
        return hdr

    async def _send_sbt(self, client: BleakClient, opcode: int, payload: bytes = b"") -> None:
        _LOGGER.debug("→ SBT op=%d payload=%s", opcode, payload.hex())
        await self._send_csl(client, _FT_DATA, _build_sbt(opcode, payload))

    async def _recv_sbt(self, timeout: float = 10.0) -> dict:
        csl = await self._recv_csl(timeout)
        sbt = _parse_sbt(csl.get("raw_data") or b"")
        _LOGGER.debug("← SBT %s", sbt)
        return sbt

    # ── ECDH handshake ─────────────────────────────────────────────────────
    async def _handshake(self, client: BleakClient) -> None:
        priv      = self._identity_priv
        local_pub = _pub_to_bytes(priv)
        local_rnd = os.urandom(8)

        req = struct.pack(">H", _CRYPTO_SYS_ECDH) + local_pub + local_rnd
        await self._send_csl(client, _FT_SESSION_REQUEST, req)

        resp = await self._recv_csl(timeout=15)
        if resp["frame_type"] != _FT_SESSION_HANDSHAKE:
            raise IseoConnectionError(
                f"Expected HANDSHAKE frame, got type={resp['frame_type']}"
            )
        self._sid = resp["session_id"]

        raw      = resp["raw_data"]
        KB       = 8
        enc_step = raw[:KB * 2]
        srv_pub  = raw[KB * 2 : KB * 2 + 56]
        srv_rnd  = raw[KB * 2 + 56 : KB * 2 + 64]

        shared          = priv.exchange(ECDH(), _pub_from_bytes(srv_pub))
        shs_pl, shs_sig = _derive_shs_keys(shared, local_rnd, srv_rnd)

        step_plain = _shs_decrypt(enc_step, shs_pl, shs_sig)
        kb0 = step_plain[:KB]

        kb2       = os.urandom(KB)
        step2_enc = _shs_encrypt(kb2 + kb0, shs_pl, shs_sig)
        await self._send_csl(client, _FT_SESSION_HANDSHAKE, step2_enc)

        resp2 = await self._recv_csl(timeout=15)
        if resp2["frame_type"] != _FT_SESSION_HANDSHAKE:
            raise IseoConnectionError(
                f"Expected HANDSHAKE step3, got type={resp2['frame_type']}"
            )
        step3 = _shs_decrypt(resp2["raw_data"], shs_pl, shs_sig)
        if step3[:KB] != kb0 or step3[KB:] != kb2:
            raise IseoConnectionError("Handshake mutual-auth failed (key block mismatch)")

        self._pl_key, self._sig_key = _derive_data_keys(kb0, kb2, shs_pl, shs_sig)
        _LOGGER.debug("Handshake complete — session %d", self._sid)

    # ── Public API ─────────────────────────────────────────────────────────
    async def open_lock(self, connect_timeout: float = 20.0) -> None:
        """
        Connect to the lock, authenticate, send TLV_OPEN, then disconnect.

        Raises:
            IseoConnectionError: BLE or handshake failure.
            IseoAuthError:       Lock rejected our identity (status ≠ 0).
        """
        _LOGGER.debug("Connecting to %s", self._address)
        async with BleakClient(self._address, timeout=connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=2)
            except asyncio.TimeoutError:
                pass

            pub_key = _pub_to_bytes(self._identity_priv)
            payload = (
                _tlv(48, b"\x00")                              # OpenType = NORMAL
                + _tlv(49, b"\x00")                            # ValidationMode = WHITELIST_CREDENTIAL
                + _tlv_user_bt(self._uuid_bytes, pub_key)      # UUID + public key (Tag 32, enrollment)
            )

            _LOGGER.debug("Sending TLV_OPEN for UUID %s", self._uuid_bytes.hex())
            await self._send_sbt(client, _OP_TLV_OPEN, payload)

            try:
                sbt = await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_OPEN") from exc

            status = sbt.get("status")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(
                    f"Lock returned status={status} for TLV_OPEN "
                    f"(UUID={self._uuid_bytes.hex()})"
                )

        _LOGGER.info("Lock opened successfully (UUID=%s)", self._uuid_bytes.hex())

    async def read_state(self, connect_timeout: float = 20.0) -> LockState:
        """
        Connect to the lock, send TLV_INFO (opcode 32), read door state, disconnect.

        Returns LockState with door_closed=True/False, or door_closed=None if
        the lock doesn't advertise door-contact capability (bit 7 of Tag 4).

        Raises:
            IseoConnectionError: BLE or handshake failure.
            IseoAuthError:       Lock returned a non-zero status.
        """
        _LOGGER.debug("Reading state from %s", self._address)
        async with BleakClient(self._address, timeout=connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=2)
            except asyncio.TimeoutError:
                pass

            await self._send_sbt(client, _OP_TLV_INFO)

            try:
                sbt = await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_INFO") from exc

            status = sbt.get("status")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(
                    f"Lock returned status={status} for TLV_INFO"
                )

            tags = _parse_tlv(sbt.get("payload", b""))
            _LOGGER.debug("TLV_INFO tags: %s", {k: v.hex() for k, v in tags.items()})

            # Tag 2: FirmwareInfo — 8-byte ASCII, chars 0-4 = name, 5-7 = version.
            fw_bytes = tags.get(2, b"")
            firmware_info: str | None = (
                fw_bytes.decode("ascii", errors="replace") if len(fw_bytes) == 8 else None
            )

            # Tag 5: SystemState — parse battery level (bits 7-5) regardless of
            # whether the door sensor is supported; door_closed follows after.
            state_bytes  = tags.get(5, b"")
            system_state = struct.unpack_from(">H", state_bytes)[0] if len(state_bytes) >= 2 else None
            battery_level: int | None = (
                (system_state >> _STATE_BATTERY_SHIFT) & _STATE_BATTERY_MASK
                if system_state is not None
                else None
            )

            cap_bytes    = tags.get(4, b"\x00")
            capabilities = int.from_bytes(cap_bytes, "big") if cap_bytes else 0
            if not (capabilities & _CAP_DOOR_STATUS):
                _LOGGER.debug(
                    "Door status not supported (capabilities=0x%x)", capabilities
                )
                return LockState(door_closed=None, firmware_info=firmware_info,
                                 battery_level=battery_level)

            if system_state is None:
                _LOGGER.debug("SystemState tag missing or too short")
                return LockState(door_closed=None, firmware_info=firmware_info,
                                 battery_level=battery_level)

            door_closed = bool(system_state & _STATE_DOOR_CLOSED)
            _LOGGER.debug(
                "SystemState=0x%04x  door_closed=%s  battery_level=%s",
                system_state, door_closed, battery_level,
            )
            return LockState(door_closed=door_closed, firmware_info=firmware_info,
                             battery_level=battery_level)

    async def read_logs(
        self,
        start: int = 0,
        max_entries: int = 200,
        connect_timeout: float = 20.0,
    ) -> list[LogEntry]:
        """
        Read access-log entries from the lock (opcode 23, READ_LOG_INFO).

        Sends TLV_LOGIN (opcode 41) first so the lock can verify the caller
        has admin privileges, then paginates until all available entries up to
        `max_entries` have been fetched or the lock reports no more.

        Args:
            start:          Index of the first entry to fetch (0 = oldest).
            max_entries:    Maximum total entries to return.
            connect_timeout: BLE connection timeout in seconds.

        Returns:
            List of LogEntry objects, oldest first.

        Raises:
            IseoConnectionError: BLE or handshake failure.
            IseoAuthError:       Lock rejected our identity or we lack admin rights.
        """
        _LOGGER.debug("Reading logs from %s (start=%d, max=%d)", self._address, start, max_entries)
        entries: list[LogEntry] = []

        async with BleakClient(self._address, timeout=connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=2)
            except asyncio.TimeoutError:
                pass

            # ── exchangeInfo: announce FL_9 so the lock enables FL_3 commands ──
            # The Argo app always calls TLV_INFO with the SbtInfoClient payload
            # (feature level FL_9) right after the handshake. Without it the
            # lock treats the session as FL_0 and returns CMD_UNSUPPORTED (3)
            # for FL_3 commands like TLV_LOGIN.
            _LOGGER.debug("Sending exchangeInfo (TLV_INFO with FL_9 payload)")
            await self._send_sbt(client, _OP_TLV_INFO, _INFO_CLIENT_PAYLOAD)
            try:
                info_resp = await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to exchangeInfo") from exc
            _LOGGER.debug("exchangeInfo response: %s", info_resp)

            # ── TLV_LOGIN: identify ourselves so the lock checks admin rights ─
            # Payload: outer tag 17 (BLUETOOTH), inner tag 1 (UUID only).
            # No Tag 0 (SubType) and no Tag 32 (PublicKey) — the app never
            # includes them in TLV_LOGIN; the outer tag already encodes the
            # user type, and the public key was enrolled at TLV_OPEN time.
            login_payload = _tlv(17, _tlv(1, self._uuid_bytes))
            _LOGGER.debug("Sending TLV_LOGIN (opcode 41) for UUID %s", self._uuid_bytes.hex())
            await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)

            try:
                login_resp = await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_LOGIN") from exc

            login_status = login_resp.get("status", 0)
            if login_status != _SBT_STATUS_OK:
                raise IseoAuthError(
                    f"TLV_LOGIN failed with status={login_status} — "
                    "ensure this UUID has admin rights in the Argo app"
                )
            _LOGGER.debug("TLV_LOGIN accepted")

            index      = min(start, 0xFFFF)
            remaining  = min(max_entries, 0xFFFF)
            more       = True

            while more and remaining > 0 and index <= 0xFFFF:
                page_size = min(remaining, 0xFFFF)
                req_payload = struct.pack(">HH", index, page_size)
                await self._send_sbt(client, _OP_READ_LOG, req_payload)

                try:
                    sbt = await self._recv_sbt(timeout=10)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to READ_LOG") from exc

                status = sbt.get("status", 0)
                if status in _LOG_STATUS_EOF:
                    _LOGGER.debug("READ_LOG EOF (status=%d)", status)
                    break
                if status != _SBT_STATUS_OK:
                    raise IseoAuthError(f"Lock returned status={status} for READ_LOG")

                raw = sbt.get("payload", b"")
                if len(raw) < 3:
                    _LOGGER.debug("READ_LOG response too short (%dB)", len(raw))
                    break

                entry_count, more_flag = struct.unpack_from(">HB", raw)
                more = bool(more_flag)
                body = raw[3:]

                _LOGGER.debug(
                    "READ_LOG page: index=%d count=%d more=%s", index, entry_count, more
                )

                for i in range(entry_count):
                    chunk = body[i * _LOG_ENTRY_SIZE : (i + 1) * _LOG_ENTRY_SIZE]
                    if len(chunk) < _LOG_ENTRY_SIZE:
                        _LOGGER.debug("Truncated log entry at i=%d, stopping", i)
                        more = False
                        break
                    try:
                        entries.append(LogEntry._from_bytes(chunk))
                    except Exception as exc:
                        _LOGGER.debug("Failed to decode log entry %d: %s", i, exc)

                index     += entry_count
                remaining -= entry_count

                if entry_count == 0:
                    break  # lock returned no entries despite more=True

        _LOGGER.debug("read_logs: fetched %d entries", len(entries))
        return entries

    async def read_users(self, connect_timeout: float = 20.0) -> list[UserEntry]:
        """
        Read all users from the lock whitelist (opcode 36, TLV_READ_USER_BLOCK).

        Requires TLV_LOGIN with admin rights (same prerequisites as read_logs).
        Returns a list of UserEntry objects with uuid_hex and name for each user.

        Raises:
            IseoConnectionError: BLE or handshake failure.
            IseoAuthError:       Lock rejected our identity or admin rights missing.
        """
        _LOGGER.debug("Reading users from %s", self._address)
        entries: list[UserEntry] = []

        async with BleakClient(self._address, timeout=connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=2)
            except asyncio.TimeoutError:
                pass

            # exchangeInfo — announce FL_9 so the lock enables FL_3+ commands
            await self._send_sbt(client, _OP_TLV_INFO, _INFO_CLIENT_PAYLOAD)
            try:
                await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to exchangeInfo") from exc

            # TLV_LOGIN — authenticate as admin BT user
            login_payload = _tlv(17, _tlv(1, self._uuid_bytes))
            await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
            try:
                login_resp = await self._recv_sbt(timeout=10)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_LOGIN") from exc

            if login_resp.get("status", 0) != _SBT_STATUS_OK:
                raise IseoAuthError(
                    f"TLV_LOGIN failed with status={login_resp.get('status')} — "
                    "ensure this UUID has admin rights in the Argo app"
                )

            # Paginated user block read
            # Request:  [start UINT16 BE][max_count UINT16 BE]
            # Response: [count UINT8][remaining UINT16 BE][TLV array]
            # Each TLV: outer tag = user type (16-21), value = inner TLV bytes
            # Inner TLVs: tag 1 = UUID (raw bytes), tag 2 = description (UTF-8)
            fetch_start = 0
            fetch_max   = 0xFFFF

            while True:
                req = struct.pack(">HH", fetch_start, fetch_max)
                await self._send_sbt(client, _OP_TLV_READ_USER_BLOCK, req)

                try:
                    sbt = await self._recv_sbt(timeout=10)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to TLV_READ_USER_BLOCK") from exc

                status = sbt.get("status", 0)
                if status != _SBT_STATUS_OK:
                    # Non-zero on first call most likely means empty whitelist
                    _LOGGER.debug("TLV_READ_USER_BLOCK status=%d (done)", status)
                    break

                raw = sbt.get("payload", b"")
                if len(raw) < 3:
                    break

                page_count = raw[0]
                remaining  = struct.unpack_from(">H", raw, 1)[0]
                tlv_data   = raw[3:]

                for outer_tag, inner_bytes in _parse_tlv_list(tlv_data):
                    if outer_tag not in range(16, 22):
                        continue  # not a recognised user-type tag
                    inner    = _parse_tlv(inner_bytes)
                    uuid_raw = inner.get(1, b"")
                    name_raw = inner.get(2, b"")
                    entries.append(UserEntry(
                        user_type = outer_tag,
                        uuid_hex  = uuid_raw.hex(),
                        name      = name_raw.decode("utf-8", errors="replace").rstrip()
                                    if name_raw else "",
                    ))

                fetch_start += page_count
                fetch_max    = remaining

                if remaining == 0 or page_count == 0:
                    break

        _LOGGER.debug("read_users: fetched %d users", len(entries))
        return entries
