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
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from bleak import BleakClient

try:
    from bleak_retry_connector import establish_connection as _bleak_establish_connection
except ImportError:
    _bleak_establish_connection = None
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP224R1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

_LOGGER = logging.getLogger(__name__)

# ── BLE GATT characteristics ──────────────────────────────────────────────────
# GATT service UUID — only visible after connecting, not in advertisements.
BLE_SERVICE_UUID = "00001000-d102-11e1-9b23-00025b00a6a6"
_S2C_UUID = "00000001-0000-1000-8000-00805f9b34fb"  # notify  (lock → phone)
_C2S_UUID = "00000002-0000-1000-8000-00805f9b34fb"  # write   (phone → lock)

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
        prefix = lower.split("-")[0]  # "0000f001"
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
_M = bytes(
    [
        0x6A,
        0xA6,
        0x42,
        0xD1,
        0xC8,
        0xF3,
        0x1E,
        0x27,
        0x4B,
        0x5C,
        0x7D,
        0x8E,
        0x9F,
        0xA0,
        0xB1,
        0xC2,
    ]
)
_PL = bytes(
    [
        0xCA,
        0xB7,
        0x60,
        0xE2,
        0x8C,
        0xA6,
        0x78,
        0x50,
        0xC3,
        0xC5,
        0xD7,
        0x35,
        0x53,
        0x7D,
        0x5F,
        0x3D,
    ]
)
_SIG = bytes(
    [
        0xDA,
        0xB7,
        0x60,
        0xE2,
        0x8C,
        0xA6,
        0x78,
        0x50,
        0xC3,
        0xC5,
        0xD7,
        0x35,
        0x53,
        0x7D,
        0x5F,
        0x3D,
    ]
)
_BASE_PL_KEY = bytes(a ^ b for a, b in zip(_PL, _M, strict=True))
_BASE_SIG_KEY = bytes(a ^ b for a, b in zip(_SIG, _M, strict=True))

_LM = bytes([0x22, 0x33, 0x11, 0x55, 0x44, 0x11, 0x77, 0x22, 0x11, 0x33, 0x44, 0x22, 0x55])
_LABEL = bytes([0x6B, 0x72, 0x52, 0x1D, 0x31, 0x73, 0x24, 0x47, 0x62, 0x40, 0x2D, 0x4D, 0x3B])
_KDF_LABEL = bytes(a ^ b for a, b in zip(_LABEL, _LM, strict=True))

_CM = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC])
_CTX = bytes([0x11, 0x37, 0x71, 0xE8, 0x89, 0x99, 0x77, 0x9D, 0xDB, 0x06, 0x67, 0x33])
_KDF_CONTEXT = bytes(a ^ b for a, b in zip(_CTX, _CM, strict=True))

# ── Protocol constants ────────────────────────────────────────────────────────
_SBT_PREAMBLE = 42602  # 0xA66A
_ADDR_LOCK, _ADDR_APP = 1, 2
_CSL_VERSION = 2
_BLOCK = 16
_ZERO_IV = bytes(16)

_FT_SESSION_REQUEST = 1
_FT_SESSION_HANDSHAKE = 2
_FT_SESSION_FIN = 3
_FT_DATA = 4
_FT_ERROR = 5

_CRYPTO_SYS_ECDH = 17  # AES128_ECDH224R1_KD56C

_OP_TLV_OPEN = 43
_OP_TLV_INFO = 32
_OP_TLV_LOGIN = 41  # OPCODE_TLV_LOGIN — authenticate as a specific BT user (required before master cmds)
_OP_READ_LOG = 23  # OPCODE_READ_LOG_INFO — paginated access-log read
_OP_TLV_READ_USER_BLOCK = 36  # OPCODE_TLV_READ_USER_BLOCK — paginated user whitelist read
_OP_TLV_STORE_USER_BLOCK = 38  # OPCODE_TLV_STORE_USER_BLOCK — register/update user in whitelist
_OP_TLV_ERASE_USER_BLOCK = 40  # OPCODE_TLV_ERASE_USER_BLOCK — remove user from whitelist

_OP_TLV_LOG_NOTIF_REGISTER = 64  # OPCODE_TLV_LOG_NOTIFICATION_REGISTER
_OP_TLV_LOG_NOTIF_UNREGISTER = 65  # OPCODE_TLV_LOG_NOTIFICATION_UNREGISTER
_OP_TLV_LOG_NOTIF_GET_UNREAD = 66  # OPCODE_TLV_LOG_NOTIFICATION_GET_UNREAD

_LOG_ENTRY_SIZE = 71  # fixed per SbtLogEntryCodec
_LOG_STATUS_EOF = {7, 80}  # status codes that mean "no more entries"

_SBT_STATUS_OK = 0
_SBT_STATUS_ERROR = -1

_USER_TLV_TAG_ORDER = [0, 1, 2, 3, 4, 5, 7, 16, 8, 32, 9, 17, 20, 18, 19, 21, 22, 23]  # SbtUserDataTlvCodec.java

# SbtInfoClient TLV payload for exchangeInfo (TLV_INFO with client feature level).
# Tag 1 = featureLevel, value = 9 (FL_9) as UINT16 big-endian.
# The Argo app always sends this after the ECDH handshake to tell the lock
# "I support up to FL_9". Without it the lock treats the session as FL_0 and
# returns CMD_UNSUPPORTED (status=3) for FL_3 commands like TLV_LOGIN.
_INFO_CLIENT_PAYLOAD = bytes([0x01, 0x02, 0x00, 0x09])  # tag=1, len=2, FL_9=0x0009

# Capabilities (Tag 4): bit 7 = door status supported
_CAP_DOOR_STATUS = 0x80
# SystemState (Tag 5): bit 11 = door is closed; bits 7-5 = battery level
_STATE_DOOR_CLOSED = 0x0800
_STATE_BATTERY_SHIFT = 5
_STATE_BATTERY_MASK = 0x7  # 3-bit field

# Outer TLV tag / user type values (SbtUserType)
USER_TYPE_RFID = 16
USER_TYPE_BT = 17
USER_TYPE_PIN = 18
USER_TYPE_INVITATION = 19
USER_TYPE_FINGERPRINT = 20
USER_TYPE_ACCOUNT = 21
_USER_TYPE_RANGE = range(USER_TYPE_RFID, USER_TYPE_ACCOUNT + 1)

# Battery level enum values (SbtDeviceBatteryLevel)
BATTERY_LEVEL_PERMANENT = 0  # permanently powered
BATTERY_LEVEL_MEASURE = 1  # measurement required
BATTERY_LEVEL_OK = 2
BATTERY_LEVEL_LOW = 3
BATTERY_LEVEL_VERY_LOW = 4
BATTERY_LEVEL_CRITICAL = 5

# Human-readable labels for battery level enum
BATTERY_LEVEL_LABELS: dict[int, str] = {
    BATTERY_LEVEL_PERMANENT: "Permanent power",
    BATTERY_LEVEL_MEASURE: "Measuring",
    BATTERY_LEVEL_OK: "OK",
    BATTERY_LEVEL_LOW: "Low",
    BATTERY_LEVEL_VERY_LOW: "Very low",
    BATTERY_LEVEL_CRITICAL: "Critical",
}

# Approximate percentage for each battery enum value (for HA sensor reporting)
BATTERY_LEVEL_PCT: dict[int, int] = {
    BATTERY_LEVEL_PERMANENT: 100,
    BATTERY_LEVEL_MEASURE: 100,
    BATTERY_LEVEL_OK: 80,
    BATTERY_LEVEL_LOW: 30,
    BATTERY_LEVEL_VERY_LOW: 10,
    BATTERY_LEVEL_CRITICAL: 5,
}


def battery_enum_to_pct(raw: int) -> int | None:
    """Convert a raw ISEO battery enum value to an approximate percentage."""
    return BATTERY_LEVEL_PCT.get(raw)


# ── User types ───────────────────────────────────────────────────────────────
class UserSubType:
    """ISEO User SubTypes (SbtUserSubType)."""

    BT_SMARTPHONE = 0x10  # 16
    BT_GATEWAY = 0x11  # 17


# ── Public exceptions and result types ───────────────────────────────────────


class IseoError(Exception):
    """Base class for ISEO protocol errors."""


class IseoAuthError(IseoError):
    """Lock rejected our identity (UUID not registered or key mismatch)."""


class MasterAuthError(IseoError):
    """Lock rejected the master password."""


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
        self.door_closed = door_closed
        # 8-char ASCII from Tag 2: chars 0-4 = product name, 5-7 = version.
        self.firmware_info = firmware_info
        # 3-bit enum from SystemState bits 7-5 (see BATTERY_LEVEL_* constants).
        self.battery_level = battery_level


@dataclass
class UserEntry:
    """A user registered in the lock's whitelist."""

    user_type: int  # outer TLV tag: 16=RFID 17=BT 18=PIN 19=INVITATION 20=FP 21=ACCOUNT
    uuid_hex: str  # hex of raw UUID bytes (32 chars for BT = 16-byte UUID)
    name: str  # Tag 2 description; empty string if the user has no name set
    inner_subtype: int | None = None  # Tag 0 inner subtype (e.g. 16=Smartphone, 17=Gateway)
    disabled: bool = False  # True if tag 16 time profile has an expired validity end


@dataclass
class LogEntry:
    """A single access-log entry from the lock."""

    event_code: int  # UINT8 — event type
    extra_description: str  # up to 32 chars, trimmed
    user_info: str  # up to 32 chars, trimmed (UUID or name)
    list_code: int  # UINT8 — log list type (0 or 1)
    battery: int  # UINT8 — battery level at event time
    timestamp: datetime  # UTC datetime (from UINT32 Unix epoch)

    @classmethod
    def _from_bytes(cls, data: bytes) -> LogEntry:
        """Decode a 71-byte log entry from the wire format."""
        if len(data) != _LOG_ENTRY_SIZE:
            raise ValueError(f"Expected {_LOG_ENTRY_SIZE}B entry, got {len(data)}B")
        event_code = data[0]
        extra_description = data[1:33].decode("utf-8", errors="replace").strip("\x00 ")
        user_info = data[33:65].decode("utf-8", errors="replace").strip("\x00 ")
        list_code = data[65]
        battery = data[66]
        ts_unix = struct.unpack_from(">I", data, 67)[0]
        timestamp = datetime.fromtimestamp(ts_unix, tz=timezone.utc)
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
    if escaped:
        raise ValueError("Incomplete SLIP escape at end of buffer")
    return bytes(result)


# Receive timeouts (seconds)
_TIMEOUT_CSL_ELECTION = 2     # brief wait for unsolicited CSL frame after connect
_TIMEOUT_HANDSHAKE = 15       # CSL handshake round-trips (includes crypto)
_TIMEOUT_OP = 10              # standard SBT command/response
_TIMEOUT_SLOW_OP = 30         # paginated reads (user blocks, log pages)

# ── CRC helpers ───────────────────────────────────────────────────────────────
def _make_crc8_table() -> list[int]:
    poly = 0x8C

    def _crc_byte(c: int, poly: int) -> int:
        for _ in range(8):
            c = ((c >> 1) ^ poly) if (c & 1) else (c >> 1)
        return c

    return [_crc_byte(i, poly) for i in range(256)]


def _make_crc16_table() -> list[int]:
    poly = 0x8408
    t = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
        t.append(crc & 0xFFFF)
    return t


_CRC8_TABLE = _make_crc8_table()
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
        tag = data[i]
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
        tag = data[i]
        length = data[i + 1]
        i += 2
        if i + length > len(data):
            break
        result.append((tag, data[i : i + length]))
        i += length
    return result


def _tlv_user_bt(
    uuid_bytes: bytes, pub_key_bytes: bytes | None = None, subtype: int = UserSubType.BT_SMARTPHONE
) -> bytes:
    """
    SbtUserDataTlvCodec format for a BLUETOOTH user (outer tag 17).
    Used by TLV_STORE_USER_BLOCK (opcode 38) and standard TLV_OPEN.
    """
    inner = _tlv(0, bytes([subtype])) + _tlv(1, uuid_bytes)
    if pub_key_bytes is not None:
        if len(pub_key_bytes) != 56:
            raise ValueError(f"Expected 56-byte public key, got {len(pub_key_bytes)}")
        inner += _tlv(32, pub_key_bytes)
    return _tlv(17, inner)


def bcd_encode_pin(pin: str) -> bytes:
    """
    SbtUserExtraPinBcdCodec format: 7 bytes, BCD, right-aligned, 0xF padded.
    Example "12345" -> FF FF FF FF F1 23 45
    """
    if not pin.isdigit():
        raise ValueError("PIN must contain only digits")
    # 14 nibbles total
    s = pin.rjust(14, "f")
    res = bytearray()
    for i in range(0, 14, 2):
        res.append(int(s[i : i + 2], 16))
    return bytes(res)


def _tlv_user_pin(uuid_bytes: bytes, pin: str, name: str | None = None, disabled: bool = False) -> bytes:
    """
    SbtUserDataTlvCodec format for a PIN user (outer tag 18).
    Used by TLV_STORE_USER_BLOCK (opcode 38).

    If disabled=True, a SbtTimeProfile (tag 16) is included with validity disabled
    (SbtTpValidityRange.DISABLED), which blocks access without deleting the user.
    """
    if len(uuid_bytes) != 7:
        # PIN users in Argo use a shortened 7-byte UUID.
        # We take the first 7 bytes if a full UUID was provided.
        uuid_bytes = uuid_bytes[:7]

    # Tag 1: UUID (7 bytes for PIN)
    inner = _tlv(1, uuid_bytes)
    if name:
        inner += _tlv(2, name.encode("utf-8"))

    # Tag 3: SbtUserOptions. Default value 0x50 enables:
    # Bit 4: Privacy Capability
    # Bit 6: Passage Mode Capability
    inner += _tlv(3, bytes([0x50]))

    # Tag 23: SbtUserBtReaderCapabilities. Default 0x02 enables:
    # Bit 1: PIN Capability
    inner += _tlv(23, bytes([0x02]))

    # Tag 4: CreationTs (UINT32 BE).
    now_ts = int(time.time())
    inner += _tlv(4, struct.pack(">I", now_ts))

    if disabled:
        # Tag 16: SbtTimeProfile — validity enabled but already expired.
        # The app won't allow end dates before today, so we use start=today_midnight,
        # end=today_midnight (zero-length range), which is immediately expired.
        # Lock interprets timestamps in local time, so compute local midnight as a UTC epoch value.
        now_local = time.localtime()
        today_local_midnight = int(time.mktime(time.struct_time(
            (now_local.tm_year, now_local.tm_mon, now_local.tm_mday, 0, 0, 0, 0, 0, -1)
        )))
        inner += _tlv(16, bytes([0x01]) + struct.pack(">II", today_local_midnight, today_local_midnight) + bytes(10))

    if pin:
        # Tag 18: SbtUserPassword (BCD PIN).
        inner += _tlv(18, bcd_encode_pin(pin))

    return _tlv(18, inner)


def _tlv_pin_user_id(uuid_bytes: bytes) -> bytes:
    """
    SbtUserIdTlvCodec format for a PIN user (outer tag 2).
    Used by TLV_ERASE_USER_BLOCK (opcode 40).
    """
    if len(uuid_bytes) != 7:
        uuid_bytes = uuid_bytes[:7]
    return _tlv(2, _tlv(1, uuid_bytes))


def _tlv_user_id(uuid_bytes: bytes, subtype: int = UserSubType.BT_SMARTPHONE) -> bytes:
    """
    SbtUserIdTlvCodec format for a BLUETOOTH user (outer tag 1).
    Used by gateway-specific TLV_OPEN (opcode 43) and TLV_LOGIN (opcode 41).

    Wire: [Tag1][Len][Tag0,1,Subtype][Tag1,16,UUID]
    """
    inner = _tlv(0, bytes([subtype])) + _tlv(1, uuid_bytes)
    return _tlv(1, inner)


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
    shs_pl = _cmac(kdk, _KDF_LABEL + b"\x00" + _KDF_CONTEXT + bytes([mac_size, 0]))
    shs_sig = _cmac(kdk, _KDF_LABEL + b"\x00" + _KDF_CONTEXT + bytes([mac_size, 1]))
    return shs_pl, shs_sig


def _derive_data_keys(kb0: bytes, kb2: bytes, shs_pl: bytes, shs_sig: bytes) -> tuple[bytes, bytes]:
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
        "frame_type": (flags >> 5) & 0x07,
        "is_response": bool(flags & 0x08),
        "session_id": sid,
        "payload_len": plen,
        "ta_num": ta,
        "crc8_ok": _crc8(raw[:7]) == raw[7],
    }


def _csl_payload_enc(raw: bytes, pl_key: bytes) -> bytes:
    salt = os.urandom(12)
    raw_len = len(raw)
    inner = struct.pack(">H", raw_len) + salt
    crc_val = struct.pack(">H", _crc16(inner))
    pad_len = (-raw_len) % _BLOCK
    padding = bytes([pad_len] * pad_len) if pad_len else b""
    pt = crc_val + inner + raw + padding
    return _aes_enc(pl_key, pt)


def _csl_payload_dec(data: bytes, pl_key: bytes) -> bytes:
    pt = _aes_dec(pl_key, data)
    raw_len = struct.unpack_from(">H", pt, 2)[0]
    return pt[16 : 16 + raw_len]


def _csl_signature(header: bytes, payload: bytes, sig_key: bytes) -> bytes:
    data = header + payload
    pad_len = (-len(data)) % _BLOCK
    padding = bytes([pad_len] * pad_len) if pad_len else b""
    mac = _aes_cbc_mac(sig_key, data + padding)
    return padding + mac


def _encode_csl(ft: int, sid: int, ta: int, raw: bytes, pl_key: bytes, sig_key: bytes) -> bytes:
    payload = _csl_payload_enc(raw, pl_key)
    header = _csl_header(ft, sid, len(payload), ta)
    sig = _csl_signature(header, payload, sig_key)
    return header + payload + sig


# ── SBT frame ─────────────────────────────────────────────────────────────────
def _build_sbt(opcode: int, payload: bytes) -> bytes:
    ts = int(time.time())
    body = (
        struct.pack(">HHBBBBI", _SBT_PREAMBLE, len(payload), 0, _ADDR_APP, _ADDR_LOCK, 0, ts)
        + bytes([opcode])
        + payload
    )
    return body + bytes([_sbt_checksum(body)])


def _parse_sbt(data: bytes) -> dict:
    if len(data) < 14:
        return {"error": f"too short ({len(data)}B)"}
    pre = struct.unpack_from(">H", data)[0]
    if pre != _SBT_PREAMBLE:
        return {"error": f"bad preamble {pre:#06x}"}
    pay_len = struct.unpack_from(">H", data, 2)[0]
    src = data[5]
    if src == _ADDR_LOCK:
        return {
            "src": src,
            "opcode": data[8],
            "status": data[9],
            "payload": data[13 : 13 + pay_len],
        }
    return {
        "src": src,
        "opcode": data[12],
        "payload": data[13 : 13 + pay_len],
    }


# ── Main client ───────────────────────────────────────────────────────────────
class IseoClient:
    """
    Manages a single BLE session with an ISEO X1R lock.

    A new instance should be created per operation — sessions are not
    re-used across calls since the lock terminates them after each command.
    """

    def __init__(
        self,
        address: str,
        uuid_bytes: bytes,
        identity_priv: Any,
        subtype: int = UserSubType.BT_SMARTPHONE,
        ble_device: Any = None,
    ) -> None:
        self._address = address
        self._uuid_bytes = uuid_bytes
        self._identity_priv = identity_priv
        self._subtype = subtype
        self._ble_device = ble_device  # bleak BLEDevice; enables retry-connector when set

        self._rxq: asyncio.Queue[bytes] = asyncio.Queue()
        self._slip_buf = bytearray()
        self._sid = 0
        self._ta = 1
        self._pl_key = _BASE_PL_KEY
        self._sig_key = _BASE_SIG_KEY

    def update_ble_device(self, device: Any) -> None:
        """Update the BLEDevice used for the next connection attempt."""
        self._ble_device = device

    # ── BLE notification handler ───────────────────────────────────────────
    def _on_notify(self, _sender: Any, data: bytearray) -> None:
        self._slip_buf.extend(data)
        while True:
            buf = self._slip_buf
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
                    # Put the raw bytes frame into the queue.
                    # _recv_csl will pull from here and parse the CSL wrapper.
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

    async def _recv_csl(self, timeout: float = 15.0) -> dict[str, Any]:
        raw = await asyncio.wait_for(self._rxq.get(), timeout=timeout)
        _LOGGER.debug("← BLE [%dB] %s", len(raw), raw.hex())
        hdr = _parse_csl_header(raw)
        if not hdr["crc8_ok"]:
            _LOGGER.warning("CSL header CRC8 mismatch")
        pend = 8 + hdr["payload_len"]
        enc = raw[8:pend]
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
        if csl["frame_type"] == _FT_ERROR:
            err_code = struct.unpack_from(">H", csl["raw_data"])[0] if len(csl["raw_data"]) >= 2 else "unknown"
            _LOGGER.debug("Received CSL ERROR frame: %s", err_code)
            return {"status": _SBT_STATUS_ERROR, "csl_error": err_code}

        sbt = _parse_sbt(csl.get("raw_data") or b"")
        _LOGGER.debug("← SBT %s", sbt)
        return sbt

    # ── BLE connection helper ──────────────────────────────────────────────
    @asynccontextmanager
    async def _connected_client(self, timeout: float):
        """
        Yield a connected BleakClient.

        Uses bleak-retry-connector (establish_connection) when a BLEDevice
        object is available — this is the HA-recommended path that avoids the
        habluetooth.wrappers warning and provides automatic retry logic.
        Falls back to a plain BleakClient(address) for CLI / standalone use.
        """
        if self._ble_device is not None and _bleak_establish_connection is not None:
            client = await _bleak_establish_connection(BleakClient, self._ble_device, self._address)
            try:
                yield client
            finally:
                await client.disconnect()
        else:
            if self._ble_device is None and _bleak_establish_connection is not None:
                # bleak_retry_connector is available (HA production context) but no BLEDevice
                # was provided — the device is not advertising and we cannot connect reliably.
                raise IseoConnectionError(
                    f"{self._address}: BLEDevice not found; device may be out of range or not advertising"
                )
            # CLI / standalone path: bleak_retry_connector not installed, fall back to address-only.
            if self._ble_device is None:
                _LOGGER.warning(
                    "%s: BLEDevice not set and bleak-retry-connector unavailable; "
                    "using address-only BleakClient (less reliable).",
                    self._address,
                )
            async with BleakClient(self._address, timeout=timeout) as client:
                yield client

    # ── ECDH handshake ─────────────────────────────────────────────────────
    async def _handshake(self, client: BleakClient) -> None:
        """
        Perform 4-way ECDH handshake to establish a secure session.
        Resets session state (SID, TA, keys) before starting.
        """
        # Reset session state for a new connection
        self._sid = 0
        self._ta = 1
        self._pl_key = _BASE_PL_KEY
        self._sig_key = _BASE_SIG_KEY

        priv = self._identity_priv
        local_pub = _pub_to_bytes(priv)
        local_rnd = os.urandom(8)

        # req payload: [Sys(16)][PubKey(56)][Rnd(8)]
        req = struct.pack(">H", _CRYPTO_SYS_ECDH) + local_pub + local_rnd
        await self._send_csl(client, _FT_SESSION_REQUEST, req)

        resp = await self._recv_csl(timeout=_TIMEOUT_HANDSHAKE)
        if resp["frame_type"] == _FT_ERROR:
            err_code = struct.unpack_from(">H", resp["raw_data"])[0] if len(resp["raw_data"]) >= 2 else "unknown"
            raise IseoConnectionError(f"Lock rejected session request (step 1) with CSL error code {err_code}")

        if resp["frame_type"] != _FT_SESSION_HANDSHAKE:
            raise IseoConnectionError(f"Expected HANDSHAKE frame (step 1), got type={resp['frame_type']}")
        self._sid = resp["session_id"]

        raw = resp["raw_data"]
        KB = 8
        enc_step = raw[: KB * 2]
        srv_pub = raw[KB * 2 : KB * 2 + 56]
        srv_rnd = raw[KB * 2 + 56 : KB * 2 + 64]

        shared = priv.exchange(ECDH(), _pub_from_bytes(srv_pub))
        shs_pl, shs_sig = _derive_shs_keys(shared, local_rnd, srv_rnd)

        step_plain = _shs_decrypt(enc_step, shs_pl, shs_sig)
        kb0 = step_plain[:KB]

        kb2 = os.urandom(KB)
        step2_enc = _shs_encrypt(kb2 + kb0, shs_pl, shs_sig)
        await self._send_csl(client, _FT_SESSION_HANDSHAKE, step2_enc)

        resp2 = await self._recv_csl(timeout=_TIMEOUT_HANDSHAKE)
        if resp2["frame_type"] == _FT_ERROR:
            err_code = struct.unpack_from(">H", resp2["raw_data"])[0] if len(resp2["raw_data"]) >= 2 else "unknown"
            raise IseoConnectionError(f"Lock rejected handshake (step 3) with CSL error code {err_code}")

        if resp2["frame_type"] != _FT_SESSION_HANDSHAKE:
            raise IseoConnectionError(f"Expected HANDSHAKE (step 3), got type={resp2['frame_type']}")
        step3 = _shs_decrypt(resp2["raw_data"], shs_pl, shs_sig)
        if step3[:KB] != kb0 or step3[KB:] != kb2:
            raise IseoConnectionError("Handshake mutual-auth failed (key block mismatch)")

        self._pl_key, self._sig_key = _derive_data_keys(kb0, kb2, shs_pl, shs_sig)
        _LOGGER.debug("Handshake complete — session %d", self._sid)

    async def _exchange_info(self, client: BleakClient) -> None:
        """Announce FL_9 feature level to the lock (exchangeInfo)."""
        _LOGGER.debug("Sending exchangeInfo (TLV_INFO with FL_9 payload)")
        await self._send_sbt(client, _OP_TLV_INFO, _INFO_CLIENT_PAYLOAD)
        try:
            info_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
        except asyncio.TimeoutError as exc:
            raise IseoConnectionError("No response to exchangeInfo") from exc
        _LOGGER.debug("exchangeInfo response: %s", info_resp)

    # ── Public API ─────────────────────────────────────────────────────────
    async def open_lock(self, connect_timeout: float = 20.0) -> None:
        """
        Connect to the lock, authenticate, send TLV_OPEN, then disconnect.
        Standard opening mode (uses registered UUID/Key).
        """
        _LOGGER.debug("Connecting to %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            pub_key = _pub_to_bytes(self._identity_priv)

            # Standard users use WHITELIST_CREDENTIAL (0).
            val_mode = 0

            payload = (
                _tlv(48, b"\x00")  # OpenType = NORMAL
                + _tlv(49, bytes([val_mode]))  # ValidationMode
                + _tlv_user_bt(self._uuid_bytes, pub_key, self._subtype)  # UUID + PubKey + SubType
            )

            _LOGGER.debug("Sending TLV_OPEN for UUID %s (subtype=%d)", self._uuid_bytes.hex(), self._subtype)
            await self._send_sbt(client, _OP_TLV_OPEN, payload)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_OPEN") from exc

            status = sbt.get("status")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"Lock returned status={status} for TLV_OPEN (UUID={self._uuid_bytes.hex()})")

        _LOGGER.info("Lock opened successfully (UUID=%s)", self._uuid_bytes.hex())

    async def gw_open(self, remote_user_name: str = "Home Assistant", connect_timeout: float = 20.0) -> None:
        """
        Gateway-specific opening (CREDENTIAL_LESS).
        Requires the client to be registered as UserSubType.BT_GATEWAY.
        """
        if self._subtype != UserSubType.BT_GATEWAY:
            raise ValueError("gw_open requires BT_GATEWAY subtype")

        _LOGGER.debug("Connecting to %s for Gateway Open", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            # Tag 64 (0x40): Custom Description (the remote user name)
            desc_bytes = remote_user_name.encode("utf-8")

            payload = (
                _tlv(48, b"\x00")  # OpenType = NORMAL
                + _tlv(49, b"\x03")  # ValidationMode = CREDENTIAL_LESS (3)
                + _tlv_user_id(self._uuid_bytes, self._subtype)  # SbtUserId (Tag 1)
                + _tlv(64, desc_bytes)  # Remote user description
            )

            _LOGGER.debug("Sending TLV_OPEN (GW) for UUID %s, remote_user=%s", self._uuid_bytes.hex(), remote_user_name)
            await self._send_sbt(client, _OP_TLV_OPEN, payload)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_OPEN") from exc

            status = sbt.get("status")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"Lock returned status={status} for TLV_OPEN (GW)")

        _LOGGER.info("Lock opened via Gateway (UUID=%s)", self._uuid_bytes.hex())

    async def read_state(self, connect_timeout: float = 20.0) -> LockState:
        """
        Connect to the lock, send TLV_INFO (opcode 32), read door state, disconnect.
        """
        _LOGGER.debug("Reading state from %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._send_sbt(client, _OP_TLV_INFO)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_INFO") from exc

            status = sbt.get("status")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"Lock returned status={status} for TLV_INFO")

            tags = _parse_tlv(sbt.get("payload", b""))
            _LOGGER.debug("TLV_INFO tags: %s", {k: v.hex() for k, v in tags.items()})

            fw_bytes = tags.get(2, b"")
            firmware_info: str | None = fw_bytes.decode("ascii", errors="replace") if len(fw_bytes) == 8 else None

            state_bytes = tags.get(5, b"")
            system_state = struct.unpack_from(">H", state_bytes)[0] if len(state_bytes) >= 2 else None
            battery_level: int | None = (
                (system_state >> _STATE_BATTERY_SHIFT) & _STATE_BATTERY_MASK if system_state is not None else None
            )

            cap_bytes = tags.get(4, b"\x00")
            capabilities = int.from_bytes(cap_bytes, "big") if cap_bytes else 0
            if not (capabilities & _CAP_DOOR_STATUS):
                _LOGGER.debug("Door status not supported (capabilities=0x%x)", capabilities)
                return LockState(door_closed=None, firmware_info=firmware_info, battery_level=battery_level)

            if system_state is None:
                _LOGGER.debug("SystemState tag missing or too short")
                return LockState(door_closed=None, firmware_info=firmware_info, battery_level=battery_level)

            door_closed = bool(system_state & _STATE_DOOR_CLOSED)
            return LockState(door_closed=door_closed, firmware_info=firmware_info, battery_level=battery_level)

    async def read_logs(
        self,
        start: int = 0,
        max_entries: int = 200,
        connect_timeout: float = 20.0,
        skip_login: bool = False,
    ) -> list[LogEntry]:
        """
        Read access-log entries from the lock (opcode 23, READ_LOG_INFO).
        """
        _LOGGER.debug(
            "Reading logs from %s (start=%d, max=%d, skip_login=%s)", self._address, start, max_entries, skip_login
        )
        entries: list[LogEntry] = []

        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if not skip_login:
                login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                try:
                    login_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to TLV_LOGIN") from exc

                if login_resp.get("status", 0) != _SBT_STATUS_OK:
                    raise IseoAuthError(f"TLV_LOGIN failed with status={login_resp.get('status')}")
            else:
                _LOGGER.debug("Skipping TLV_LOGIN (assume Master Mode/Pre-authorized)")

            index = min(start, 0xFFFF)
            remaining = min(max_entries, 0xFFFF)
            more = True

            while more and remaining > 0 and index <= 0xFFFF:
                page_size = min(remaining, 0xFFFF)
                req_payload = struct.pack(">HH", index, page_size)
                await self._send_sbt(client, _OP_READ_LOG, req_payload)

                try:
                    sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to READ_LOG") from exc

                status = sbt.get("status", 0)
                if status in _LOG_STATUS_EOF:
                    break
                if status != _SBT_STATUS_OK:
                    raise IseoAuthError(f"Lock returned status={status} for READ_LOG")

                raw = sbt.get("payload", b"")
                if len(raw) < 3:
                    break

                entry_count, more_flag = struct.unpack_from(">HB", raw)
                more = bool(more_flag)
                body = raw[3:]

                for i in range(entry_count):
                    chunk = body[i * _LOG_ENTRY_SIZE : (i + 1) * _LOG_ENTRY_SIZE]
                    if len(chunk) < _LOG_ENTRY_SIZE:
                        more = False
                        break
                    try:
                        entries.append(LogEntry._from_bytes(chunk))
                    except Exception as exc:
                        _LOGGER.debug("Failed to decode log entry %d: %s", i, exc)

                index += entry_count
                remaining -= entry_count
                if entry_count == 0:
                    break

        _LOGGER.debug("read_logs: fetched %d entries", len(entries))
        return entries

    async def read_users(self, connect_timeout: float = 20.0, skip_login: bool = False) -> list[UserEntry]:
        """
        Read all users from the lock whitelist (opcode 36, TLV_READ_USER_BLOCK).
        """
        _LOGGER.debug("Reading users from %s (skip_login=%s)", self._address, skip_login)
        entries: list[UserEntry] = []

        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if not skip_login:
                login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                try:
                    login_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to TLV_LOGIN") from exc

                if login_resp.get("status", 0) != _SBT_STATUS_OK:
                    raise IseoAuthError(f"TLV_LOGIN failed with status={login_resp.get('status')}")
            else:
                _LOGGER.debug("Skipping TLV_LOGIN (assume Master Mode/Pre-authorized)")

            fetch_start = 0
            fetch_max = 0xFFFF
            first_block = True

            while True:
                req = struct.pack(">HH", fetch_start, fetch_max)
                await self._send_sbt(client, _OP_TLV_READ_USER_BLOCK, req)

                try:
                    sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP if first_block else _TIMEOUT_OP)
                    first_block = False
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("No response to TLV_READ_USER_BLOCK") from exc

                status = sbt.get("status", 0)
                if status != _SBT_STATUS_OK:
                    break

                raw = sbt.get("payload", b"")
                if len(raw) < 3:
                    break

                page_count = raw[0]
                remaining = struct.unpack_from(">H", raw, 1)[0]
                tlv_data = raw[3:]

                for outer_tag, inner_bytes in _parse_tlv_list(tlv_data):
                    if outer_tag not in _USER_TYPE_RANGE:
                        continue
                    inner = _parse_tlv(inner_bytes)
                    uuid_raw = inner.get(1, b"")
                    name_raw = inner.get(2, b"")
                    subtype_raw = inner.get(0, b"")
                    inner_subtype = subtype_raw[0] if subtype_raw else None

                    disabled = False
                    tp_raw = inner.get(16, b"")
                    if len(tp_raw) >= 9:
                        tp_enabled = (tp_raw[0] & 0x01) != 0
                        tp_start = struct.unpack_from(">I", tp_raw, 1)[0]
                        tp_end = struct.unpack_from(">I", tp_raw, 5)[0]
                        now = int(time.time())
                        disabled = tp_enabled and tp_start == tp_end and tp_end <= now

                    entries.append(
                        UserEntry(
                            user_type=outer_tag,
                            uuid_hex=uuid_raw.hex(),
                            name=name_raw.decode("utf-8", errors="replace").rstrip() if name_raw else "",
                            inner_subtype=inner_subtype,
                            disabled=disabled,
                        )
                    )

                fetch_start += page_count
                fetch_max = remaining
                if remaining == 0 or page_count == 0:
                    break

        _LOGGER.debug("read_users: fetched %d users", len(entries))
        return entries

    async def master_login(self, client: BleakClient, password: str) -> None:
        """
        Authenticate using the Master Password (OEM Login).
        Must be called within a connection context after handshake.
        """
        pwd_bytes = password.encode("utf-8")
        _LOGGER.debug("Sending Master Login (opcode 41)")
        await self._send_sbt(client, _OP_TLV_LOGIN, pwd_bytes)

        try:
            sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
        except asyncio.TimeoutError as exc:
            raise IseoConnectionError("No response to Master Login") from exc

        if sbt.get("status") != _SBT_STATUS_OK:
            raise MasterAuthError(f"Master login failed (status={sbt.get('status')})")
        _LOGGER.debug("Master login accepted")

    async def _register_user_internal(self, client: BleakClient, name: str) -> None:
        """Internal logic to register ourselves in the whitelist."""
        pub_key = _pub_to_bytes(self._identity_priv)

        inner = (
            _tlv(0, bytes([self._subtype]))
            + _tlv(1, self._uuid_bytes)
            + _tlv(2, name.encode("utf-8"))
            # Tag 3: Options (MasterLogin + Privacy + Passage)
            + _tlv(3, bytes([0x70]))
            # Tag 4: CreationTs
            + _tlv(4, struct.pack(">I", int(time.time())))
            + _tlv(32, pub_key)
        )
        user_tlv = _tlv(17, inner)

        # Opcode 38 (STORE_USER_BLOCK) expects a raw TLV block (no item count).
        _LOGGER.debug("Sending TLV_STORE_USER_BLOCK (opcode 38)")
        await self._send_sbt(client, _OP_TLV_STORE_USER_BLOCK, user_tlv)

        try:
            sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
        except asyncio.TimeoutError as exc:
            raise IseoConnectionError("No response to register_user (did you scan the Master Card?)") from exc

        status = sbt.get("status", 0)
        if status == 68:
            raise IseoAuthError("Invalid user data: The lock rejected this identity payload.")
        if status != _SBT_STATUS_OK:
            raise IseoAuthError(f"User registration failed (status={status})")

    async def _register_log_notif_internal(self, client: BleakClient) -> None:
        """Internal logic to register for log notifications."""
        # Register for log notifications (opcode 64)
        # Payload is our SbtUserId (Tag 1)
        payload = _tlv_user_id(self._uuid_bytes, self._subtype)
        await self._send_sbt(client, _OP_TLV_LOG_NOTIF_REGISTER, payload)

        try:
            sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
        except asyncio.TimeoutError as exc:
            raise IseoConnectionError("No response to LOG_NOTIF_REGISTER (did you scan the Master Card?)") from exc

        if sbt.get("status") != _SBT_STATUS_OK:
            raise IseoAuthError(f"Log notification registration failed (status={sbt.get('status')})")

    async def setup_gateway(
        self,
        master_password: str | None = None,
        name: str = "Home Assistant",
        connect_timeout: float = 20.0,
    ) -> None:
        """
        Connect to the lock and perform full Gateway setup in a single session.
        Registers the user and enables log notifications.
        Requires scanning the Master Card once (or master_password).
        """
        if self._subtype != UserSubType.BT_GATEWAY:
            raise ValueError("setup_gateway requires BT_GATEWAY subtype")

        _LOGGER.debug("Starting full Gateway setup on %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if master_password:
                await self.master_login(client, master_password)

            _LOGGER.debug("Step 1/2: Registering user")
            await self._register_user_internal(client, name)

            _LOGGER.debug("Step 2/2: Enabling log notifications")
            await self._register_log_notif_internal(client)

        _LOGGER.info("Gateway setup completed successfully (UUID=%s)", self._uuid_bytes.hex())

    async def register_user(
        self,
        master_password: str | None = None,
        name: str = "Home Assistant",
        connect_timeout: float = 20.0,
    ) -> None:
        """
        Connect to the lock, login as Master (if password provided),
        and register ourselves in the whitelist.
        """
        _LOGGER.debug("Registering identity on lock %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if master_password:
                await self.master_login(client, master_password)

            await self._register_user_internal(client, name)

        _LOGGER.info("User registered successfully (UUID=%s, subtype=%d)", self._uuid_bytes.hex(), self._subtype)

    async def register_pin_user(
        self,
        pin_uuid_bytes: bytes,
        pin: str,
        name: str | None = None,
        master_password: str | None = None,
        connect_timeout: float = 20.0,
        skip_login: bool = False,
        disabled: bool = False,
    ) -> None:
        """
        Connect to the lock and register/update a PIN user (outer tag 18).

        If skip_login is False, requires admin rights.
        If skip_login is True, assumes lock is already in Master Mode.
        If disabled is True, the user is stored with a disabled time profile so
        access is denied without deleting the user from the lock.
        """
        if not (4 <= len(pin) <= 14 and pin.isdigit()):
            raise ValueError("PIN must be 4-14 digits")

        _LOGGER.debug("Registering PIN user %s on lock %s (skip_login=%s)", pin_uuid_bytes.hex(), self._address, skip_login)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if not skip_login:
                # 1. Master Login (only if password provided)
                if master_password:
                    await self.master_login(client, master_password)
                else:
                    # Standard admin login
                    login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                    await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                    try:
                        login_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
                    except asyncio.TimeoutError as exc:
                        raise IseoConnectionError("No response to TLV_LOGIN") from exc
                    if login_resp.get("status", 0) != _SBT_STATUS_OK:
                        raise IseoAuthError(
                            f"TLV_LOGIN failed with status={login_resp.get('status')} — "
                            "UUID may not be registered on the lock"
                        )
            else:
                _LOGGER.debug("Skipping TLV_LOGIN (assume Master Mode/Pre-authorized)")

            # 2. Store User (opcode 38)
            user_tlv = _tlv_user_pin(pin_uuid_bytes, pin, name, disabled=disabled)

            # Opcode 38 (STORE_USER_BLOCK) expects a raw TLV block (no item count).
            _LOGGER.debug("Sending TLV_STORE_USER_BLOCK (opcode 38) for PIN")
            await self._send_sbt(client, _OP_TLV_STORE_USER_BLOCK, user_tlv)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError(
                    "No response to register_pin_user (did you scan the Master Card?)"
                ) from exc

            status = sbt.get("status", 0)
            if status == 5:
                raise IseoAuthError("Master Mode Required: Scan your physical Master Card on the lock first.")
            if status == 68:
                raise IseoAuthError("Invalid PIN: The lock rejected this code (it may be too simple or already in use).")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"Register PIN User failed with status={status}")

        _LOGGER.info(
            "PIN user %s registered successfully on lock %s", pin_uuid_bytes.hex(), self._address
        )

    async def set_user_disabled(
        self,
        uuid_hex: str,
        user_type: int,
        disabled: bool,
        connect_timeout: float = 20.0,
        master_password: str | None = None,
        skip_login: bool = False,
    ) -> None:
        """
        Enable or disable any enrolled user by patching their time profile (tag 16).

        Reads the raw user TLV from the lock, inserts/removes the disabled time profile
        (start == end == local midnight today), and writes it back via opcode 38.
        Works for any user type (PIN, BT, RFID, etc.).
        """
        _LOGGER.debug("set_user_disabled(%s, type=%d, disabled=%s)", uuid_hex, user_type, disabled)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)
            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass
            await self._exchange_info(client)

            if not skip_login:
                if master_password:
                    await self.master_login(client, master_password)
                else:
                    login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                    await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                    await self._recv_sbt(timeout=_TIMEOUT_OP)

            # Read all users within the same connection to get raw inner TLV bytes.
            users_raw: list[tuple[int, bytes]] = []
            fetch_start = 0
            while True:
                req = struct.pack(">HH", fetch_start, 0xFFFF)
                await self._send_sbt(client, _OP_TLV_READ_USER_BLOCK, req)
                try:
                    sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
                except asyncio.TimeoutError as exc:
                    raise IseoConnectionError("Timed out reading user block from lock") from exc
                if sbt.get("status", 0) != _SBT_STATUS_OK:
                    break
                raw = sbt.get("payload", b"")
                if len(raw) < 3:
                    break
                page_count = raw[0]
                remaining = struct.unpack_from(">H", raw, 1)[0]
                for outer_tag, inner_bytes in _parse_tlv_list(raw[3:]):
                    if outer_tag in _USER_TYPE_RANGE:
                        users_raw.append((outer_tag, inner_bytes))
                fetch_start += page_count
                if remaining == 0 or page_count == 0:
                    break

            match = next(
                (raw for ut, raw in users_raw if ut == user_type and _parse_tlv(raw).get(1, b"").hex() == uuid_hex),
                None,
            )
            if match is None:
                raise ValueError(f"User {uuid_hex} (type {user_type}) not found on lock")

            # Rebuild inner TLV in SDK-defined tag order (SbtUserDataTlvCodec.java).
            tags = {t: v for t, v in _parse_tlv_list(match)}
            if disabled:
                # Compute local midnight as a Unix timestamp using the system timezone (e.g. CET).
                # datetime.now().astimezone() correctly reflects the current DST offset, avoiding
                # the tm_isdst=-1 ambiguity that time.mktime() has during DST transitions.
                today_local_midnight = int(
                    datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
                )
                tags[16] = bytes([0x01]) + struct.pack(">II", today_local_midnight, today_local_midnight) + bytes(10)
            else:
                # Use SDK SbtTpValidityRange.DISABLED (enabled=false, start=MIN=0, end=MIN=0).
                # enabled=false means "no time restriction" to the lock firmware.
                tags[16] = bytes([0x00]) + struct.pack(">II", 0, 0) + bytes(10)
            tags = [(t, tags[t]) for t in _USER_TLV_TAG_ORDER if t in tags]

            inner = b"".join(_tlv(t, v) for t, v in tags)
            user_tlv = _tlv(user_type, inner)

            await self._send_sbt(client, _OP_TLV_STORE_USER_BLOCK, user_tlv)
            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to set_user_disabled") from exc

            status = sbt.get("status", 0)
            if status == 5:
                raise IseoAuthError("Master Mode Required")
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"set_user_disabled failed with status={status}")

    async def gw_read_unread_logs(self, connect_timeout: float = 20.0) -> list[LogEntry]:
        """
        Read unread access-log entries specifically for this Gateway (opcode 66).
        Requires the client to be registered as UserSubType.BT_GATEWAY.
        """
        if self._subtype != UserSubType.BT_GATEWAY:
            raise ValueError("gw_read_unread_logs requires BT_GATEWAY subtype")

        _LOGGER.debug("Reading unread Gateway logs from %s", self._address)
        entries: list[LogEntry] = []

        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            # TLV_LOGIN
            login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
            await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
            try:
                login_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to TLV_LOGIN") from exc
            if login_resp.get("status", 0) != _SBT_STATUS_OK:
                raise IseoAuthError(
                    f"TLV_LOGIN failed with status={login_resp.get('status')} — "
                    "UUID may not be registered on the lock"
                )

            # OPCODE_TLV_LOG_NOTIFICATION_GET_UNREAD (66)
            # Payload is our SbtUserId (Tag 1) - this one stays Tag 1 as confirmed by SDK
            payload = _tlv_user_id(self._uuid_bytes, self._subtype)
            await self._send_sbt(client, _OP_TLV_LOG_NOTIF_GET_UNREAD, payload)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to GET_UNREAD_LOGS") from exc

            status = sbt.get("status", 0)
            if status in _LOG_STATUS_EOF:
                return []
            if status != _SBT_STATUS_OK:
                raise IseoAuthError(f"Lock returned status={status} for GET_UNREAD_LOGS")

            raw = sbt.get("payload", b"")
            if len(raw) < 3:
                return []

            entry_count, more_flag = struct.unpack_from(">HB", raw)
            body = raw[3:]

            for i in range(entry_count):
                chunk = body[i * _LOG_ENTRY_SIZE : (i + 1) * _LOG_ENTRY_SIZE]
                if len(chunk) < _LOG_ENTRY_SIZE:
                    _LOGGER.warning(
                        "gw_read_unread_logs: partial data at entry %d/%d "
                        "(got %d bytes, expected %d) — remaining entries dropped",
                        i, entry_count, len(chunk), _LOG_ENTRY_SIZE,
                    )
                    break
                try:
                    entries.append(LogEntry._from_bytes(chunk))
                except Exception as exc:
                    _LOGGER.debug("Failed to decode log entry %d: %s", i, exc)

            if more_flag:
                _LOGGER.warning(
                    "gw_read_unread_logs: lock reports additional unread entries beyond this page "
                    "but opcode 66 does not support offset pagination — some entries may have been missed",
                )

        _LOGGER.debug("gw_read_unread_logs: fetched %d entries", len(entries))
        return entries

    async def gw_register_log_notif(
        self,
        master_password: str | None = None,
        connect_timeout: float = 20.0,
    ) -> None:
        """
        Register this Gateway to receive log notifications (opcode 64).
        Requires Master Mode.
        """
        if self._subtype != UserSubType.BT_GATEWAY:
            raise ValueError("gw_register_log_notif requires BT_GATEWAY subtype")

        _LOGGER.debug("Registering Gateway for log notifications on %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            # 1. Master Login (if provided)
            if master_password:
                await self.master_login(client, master_password)
            else:
                _LOGGER.debug("No master password provided, assuming lock is already in Master Mode")
                # Even in master mode, some locks might require a standard login first?
                # The SDK shows performBtUserLogin before some master tasks.
                login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                await self._recv_sbt(timeout=_TIMEOUT_OP)

            await self._register_log_notif_internal(client)

        _LOGGER.info("Gateway registered for log notifications (UUID=%s)", self._uuid_bytes.hex())

    async def erase_user(
        self,
        master_password: str | None = None,
        connect_timeout: float = 20.0,
        skip_login: bool = False,
    ) -> None:
        """Erase ourselves from the whitelist."""
        # Bluetooth users always use USER_TYPE_BT (outer tag).
        await self.erase_user_by_uuid(
            self._uuid_bytes,
            17,
            self._subtype,
            master_password,
            connect_timeout,
            skip_login=skip_login,
        )

    async def erase_user_by_uuid(
        self,
        uuid_bytes: bytes,
        user_type: int,
        subtype: int | None = None,
        master_password: str | None = None,
        connect_timeout: float = 20.0,
        skip_login: bool = False,
    ) -> None:
        """
        Connect to the lock and remove a specific user from the whitelist.

        If skip_login is False, requires admin rights.
        If skip_login is True, assumes lock is already in Master Mode.
        """
        _LOGGER.debug(
            "Erasing user %s (type=%d, skip_login=%s) from lock %s",
            uuid_bytes.hex(),
            user_type,
            skip_login,
            self._address,
        )
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            if not skip_login:
                # 1. Master Login (only if password provided)
                if master_password:
                    await self.master_login(client, master_password)
                else:
                    # Standard admin login
                    login_payload = _tlv_user_bt(self._uuid_bytes, subtype=self._subtype)
                    await self._send_sbt(client, _OP_TLV_LOGIN, login_payload)
                    try:
                        login_resp = await self._recv_sbt(timeout=_TIMEOUT_OP)
                    except asyncio.TimeoutError as exc:
                        raise IseoConnectionError("No response to TLV_LOGIN") from exc
                    if login_resp.get("status", 0) != _SBT_STATUS_OK:
                        raise IseoAuthError(
                            f"TLV_LOGIN failed with status={login_resp.get('status')} — "
                            "UUID may not be registered on the lock"
                        )
            else:
                _LOGGER.debug("Skipping TLV_LOGIN (assume Master Mode/Pre-authorized)")

            # 2. Erase User (opcode 40)
            if user_type == USER_TYPE_BT:
                payload = _tlv_user_id(uuid_bytes, subtype or UserSubType.BT_SMARTPHONE)
            elif user_type == USER_TYPE_PIN:
                payload = _tlv_pin_user_id(uuid_bytes)
            else:
                # Fallback for other types (RFID, Fingerprint, etc.): wrap UUID in outer type tag
                payload = _tlv(user_type, _tlv(1, uuid_bytes))

            _LOGGER.debug("Sending TLV_ERASE_USER_BLOCK (opcode 40)")
            await self._send_sbt(client, _OP_TLV_ERASE_USER_BLOCK, payload)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_SLOW_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to erase_user (did you scan the Master Card?)") from exc

            if sbt.get("status") != _SBT_STATUS_OK:
                raise IseoAuthError(f"User deletion failed (status={sbt.get('status')})")

        _LOGGER.info("User erased successfully (UUID=%s)", uuid_bytes.hex())

    async def gw_unregister_log_notif(
        self,
        master_password: str | None = None,
        connect_timeout: float = 20.0,
    ) -> None:
        """
        Unregister this Gateway from log notifications (opcode 65).
        Requires Master Mode.
        """
        if self._subtype != UserSubType.BT_GATEWAY:
            raise ValueError("gw_unregister_log_notif requires BT_GATEWAY subtype")

        _LOGGER.debug("Unregistering Gateway for log notifications on %s", self._address)
        async with self._connected_client(connect_timeout) as client:
            await client.start_notify(_S2C_UUID, self._on_notify)
            await self._handshake(client)

            try:
                await self._recv_csl(timeout=_TIMEOUT_CSL_ELECTION)
            except asyncio.TimeoutError:
                pass

            await self._exchange_info(client)

            # 1. Master Login
            if master_password:
                await self.master_login(client, master_password)

            # 2. Unregister log notifications (opcode 65)
            payload = _tlv_user_id(self._uuid_bytes, self._subtype)
            await self._send_sbt(client, _OP_TLV_LOG_NOTIF_UNREGISTER, payload)

            try:
                sbt = await self._recv_sbt(timeout=_TIMEOUT_OP)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("No response to LOG_NOTIF_UNREGISTER") from exc

            if sbt.get("status") != _SBT_STATUS_OK:
                raise IseoAuthError(f"Log notification unregistration failed (status={sbt.get('status')})")

        _LOGGER.info("Gateway unregistered from log notifications (UUID=%s)", self._uuid_bytes.hex())
