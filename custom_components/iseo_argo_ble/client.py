"""
ISEO Argo BLE Lock protocol client.

Implements the ISEO Argo BLE communication stack:
BLE GATT → SLIP framing → CSL session layer (AES-128-CBC + CBC-MAC) → SBT command frame.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP224R1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from bleak import BleakClient

from .const import (
    BASE_PL_KEY, BASE_SIG_KEY, KDF_LABEL, KDF_CONTEXT,
    BLE_S2C_UUID, BLE_C2S_UUID,
)

_LOGGER = logging.getLogger(__name__)

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

_OP_PING     = 48
_OP_TLV_OPEN = 43

_SBT_STATUS_OK = 0


class IseoError(Exception):
    """Base class for ISEO protocol errors."""


class IseoAuthError(IseoError):
    """Lock rejected our identity (UUID not registered or key mismatch)."""


class IseoConnectionError(IseoError):
    """BLE connection or handshake failed."""


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
    shs_pl  = _cmac(kdk, KDF_LABEL + b"\x00" + KDF_CONTEXT + bytes([mac_size, 0]))
    shs_sig = _cmac(kdk, KDF_LABEL + b"\x00" + KDF_CONTEXT + bytes([mac_size, 1]))
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

    Use as an async context manager or call open_lock() directly.
    A new instance should be created per operation — sessions are not
    re-used across calls since the lock terminates them after each command.
    """

    def __init__(self, address: str, uuid_bytes: bytes, identity_priv: Any) -> None:
        self._address      = address
        self._uuid_bytes   = uuid_bytes
        self._identity_priv = identity_priv

        self._rxq      = asyncio.Queue()
        self._slip_buf = bytearray()
        self._sid      = 0
        self._ta       = 1
        self._pl_key   = BASE_PL_KEY
        self._sig_key  = BASE_SIG_KEY

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
        await client.write_gatt_char(BLE_C2S_UUID, framed, response=False)

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

        raw     = resp["raw_data"]
        KB      = 8
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
            await client.start_notify(BLE_S2C_UUID, self._on_notify)

            try:
                await self._handshake(client)
            except asyncio.TimeoutError as exc:
                raise IseoConnectionError("Handshake timed out") from exc

            # Drain any pending frames (SESSION_FIN etc.)
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
