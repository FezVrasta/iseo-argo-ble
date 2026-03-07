import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import struct
from datetime import datetime, timezone

import pytest

from iseo_argo_ble.client import (
    _SBT_PREAMBLE,
    LogEntry,
    _crc8,
    _crc16,
    _csl_header,
    _csl_payload_dec,
    _csl_payload_enc,
    _parse_csl_header,
    _parse_sbt,
    _parse_tlv,
    _parse_tlv_list,
    _sbt_checksum,
    _slip_decode,
    _slip_encode,
    _tlv,
    battery_enum_to_pct,
    bcd_encode_pin,
    is_iseo_advertisement,
    parse_iseo_advertisement,
)


def test_is_iseo_advertisement():
    assert is_iseo_advertisement(["0000f001-0000-1000-8000-00805f9b34fb"]) is True
    assert is_iseo_advertisement(["0000f03f-0000-1000-8000-00805f9b34fb"]) is True
    assert is_iseo_advertisement(["0000f040-0000-1000-8000-00805f9b34fb"]) is False
    assert is_iseo_advertisement(["0000180f-0000-1000-8000-00805f9b34fb"]) is False
    assert is_iseo_advertisement(["random-uuid"]) is False

def test_parse_iseo_advertisement():
    # marker at index 0, state at index 3
    # state value: 0xE000 | battery(2 << 5) | door_closed(0x0800) = 0xE000 | 0x0040 | 0x0800 = 0xE840
    uuids = [
        "0000f001-0000-1000-8000-00805f9b34fb",
        "00001111-0000-1000-8000-00805f9b34fb",
        "00002222-0000-1000-8000-00805f9b34fb",
        "0000e840-0000-1000-8000-00805f9b34fb",
    ]
    state = parse_iseo_advertisement(uuids)
    assert state is not None
    assert state.door_closed is True
    assert state.battery_level == 2 # OK

    # Test open door, low battery (3)
    # state: 0xE000 | (3 << 5) = 0xE060
    uuids[3] = "0000e060-0000-1000-8000-00805f9b34fb"
    state = parse_iseo_advertisement(uuids)
    assert state.door_closed is False
    assert state.battery_level == 3 # LOW

    # Test invalid state prefix
    uuids[3] = "0000d000-0000-1000-8000-00805f9b34fb"
    assert parse_iseo_advertisement(uuids) is None

    # Test missing state (list too short)
    assert parse_iseo_advertisement(uuids[:3]) is None

def test_slip_encode_decode():
    data = b"\x01\x02\xc0\x03\xdb\x04"
    encoded = _slip_encode(data)
    # Starts and ends with 0xC0. 0xC0 -> 0xDB 0xDC, 0xDB -> 0xDB 0xDD
    assert encoded == b"\xc0\x01\x02\xdb\xdc\x03\xdb\xdd\x04\xc0"
    assert _slip_decode(encoded) == data

def test_slip_decode_errors():
    with pytest.raises(ValueError, match="SLIP ESC followed by END"):
        _slip_decode(b"\xdb\xc0")
    with pytest.raises(ValueError, match="Bad SLIP escape"):
        _slip_decode(b"\xdb\x01")
    with pytest.raises(ValueError, match="Incomplete SLIP escape"):
        _slip_decode(b"\xdb")

def test_crc8():
    assert _crc8(b"123456789") == 161
    data = b"hello"
    c1 = _crc8(data)
    assert isinstance(c1, int)
    assert 0 <= c1 <= 0xFF

def test_crc16():
    # Poly 0x8408
    assert _crc16(b"123456789") == 28561
    assert _crc16(b"hello") == 52034

def test_sbt_checksum():
    assert _sbt_checksum(b"\x01\x02\x03") == 6
    assert isinstance(_sbt_checksum(b"test"), int)

def test_tlv():
    assert _tlv(1, b"\x02\x03") == b"\x01\x02\x02\x03"
    data = b"\x01\x02\xaa\xbb\x02\x01\xcc"
    parsed = _parse_tlv(data)
    assert parsed == {1: b"\xaa\xbb", 2: b"\xcc"}

def test_parse_tlv_list():
    data = b"\x11\x01\xaa\x11\x01\xbb"
    parsed = _parse_tlv_list(data)
    assert parsed == [(17, b"\xaa"), (17, b"\xbb")]

def test_bcd_encode_pin():
    assert bcd_encode_pin("12345") == b"\xff\xff\xff\xff\xf1\x23\x45"
    assert bcd_encode_pin("12345678901234") == b"\x12\x34\x56\x78\x90\x12\x34"
    with pytest.raises(ValueError, match="PIN must contain only digits"):
        bcd_encode_pin("12a4")

def test_battery_enum_to_pct():
    assert battery_enum_to_pct(2) == 80 # BATTERY_LEVEL_OK
    assert battery_enum_to_pct(5) == 5  # BATTERY_LEVEL_CRITICAL
    assert battery_enum_to_pct(99) is None

def test_log_entry_decode():
    # 71 bytes
    # event_code (1), extra_desc (32), user_info (32), list_code (1), battery (1), ts (4)
    data = bytearray(71)
    data[0] = 42 # event_code
    data[1:6] = b"extra"
    data[33:37] = b"user"
    data[65] = 1 # list_code
    data[66] = 80 # battery
    ts = 1709550000 # 2024-03-04 11:00:00 UTC
    struct.pack_into(">I", data, 67, ts)

    entry = LogEntry._from_bytes(bytes(data))
    assert entry.event_code == 42
    assert entry.extra_description == "extra"
    assert entry.user_info == "user"
    assert entry.list_code == 1
    assert entry.battery == 80
    assert entry.timestamp == datetime.fromtimestamp(ts, tz=timezone.utc)

def test_csl_header():
    # ft=4, sid=123, pay_len=10, ta=5
    hdr = _csl_header(4, 123, 10, 5)
    assert len(hdr) == 8
    parsed = _parse_csl_header(hdr)
    assert parsed["frame_type"] == 4
    assert parsed["session_id"] == 123
    assert parsed["payload_len"] == 10
    assert parsed["ta_num"] == 5
    assert parsed["crc8_ok"] is True
    assert parsed["is_response"] is False

def test_csl_payload_enc_dec():
    key = b"K" * 16
    data = b"hello world!!"
    enc = _csl_payload_enc(data, key)
    assert len(enc) % 16 == 0
    dec = _csl_payload_dec(enc, key)
    assert dec == data

def test_parse_sbt_lock_resp():
    # ADDR_LOCK resp
    payload = b"\xaa\xbb"
    sbt_data = bytearray(13 + len(payload))
    struct.pack_into(">HHB", sbt_data, 0, _SBT_PREAMBLE, len(payload), 0)
    sbt_data[5] = 1 # ADDR_LOCK
    sbt_data[8] = 42 # opcode
    sbt_data[9] = 0 # status
    sbt_data[13:] = payload

    parsed = _parse_sbt(bytes(sbt_data))
    assert parsed["src"] == 1
    assert parsed["opcode"] == 42
    assert parsed["status"] == 0
    assert parsed["payload"] == payload

def test_tlv_user_bt():
    from iseo_argo_ble.client import UserSubType, _tlv_user_bt
    uuid = b"U" * 16
    pub = b"K" * 56
    tlv_data = _tlv_user_bt(uuid, pub, UserSubType.BT_GATEWAY)
    assert tlv_data.startswith(b"\x11") # outer tag 17
    parsed = _parse_tlv(tlv_data[2:])
    assert parsed[0] == b"\x11" # subtype
    assert parsed[1] == uuid
    assert parsed[32] == pub

def test_tlv_user_pin():
    from iseo_argo_ble.client import _tlv_user_pin
    uuid = b"P" * 16
    pin = "1234"
    tlv_data = _tlv_user_pin(uuid, pin, name="Test")
    assert tlv_data.startswith(b"\x12") # outer tag 18
    inner = _parse_tlv(tlv_data[2:])
    assert inner[1] == uuid[:7]
    assert inner[2] == b"Test"
    assert 18 in inner # PIN tag
