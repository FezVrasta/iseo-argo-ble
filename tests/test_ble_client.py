import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from iseo_argo_ble.client import (
    _C2S_UUID,
    _FT_DATA,
    _OP_TLV_INFO,
    _S2C_UUID,
    _SBT_STATUS_OK,
    BLE_SERVICE_UUID,
    OPEN_TYPE_NORMAL,
    OPEN_TYPE_PASSAGE_OFF,
    OPEN_TYPE_PASSAGE_ON,
    IseoClient,
    UserSubType,
    _csl_header,
    _parse_csl_header,
    _parse_tlv,
    _slip_encode,
)

_OTHER_SERVICE_UUID = "00001801-0000-1000-8000-00805f9b34fb"
_EXTRA_S2C_UUID = "00000003-0000-1000-8000-00805f9b34fb"
_EXTRA_C2S_UUID = "00000004-0000-1000-8000-00805f9b34fb"


@pytest.fixture
def identity():
    priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
    uuid_bytes = b"I" * 16
    return uuid_bytes, priv


@pytest.mark.asyncio
async def test_read_state_high_level(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)

    # Mock the internal protocol methods to avoid full emulation
    client._handshake = AsyncMock()

    # Mock _recv_sbt to return a successful TLV_INFO response
    # Tag 5: SystemState=0x0840 (door closed, battery OK), Tag 4: Caps=0x80, Tag 2: FW
    system_state = 0x0800 | (2 << 5)
    payload = bytes([5, 2]) + struct.pack(">H", system_state) + bytes([4, 1, 0x80]) + bytes([2, 8]) + b"X1R  123"

    client._recv_sbt = AsyncMock(return_value={"status": _SBT_STATUS_OK, "opcode": _OP_TLV_INFO, "payload": payload})
    client._send_sbt = AsyncMock()

    # Mock the connection context manager
    mock_bleak = MagicMock()
    mock_bleak.start_notify = AsyncMock()

    @patch("ble_client.BleakClient", return_value=mock_bleak)
    async def run_test(mock_bc):
        state = await client.read_state()
        return state

    # We need to mock _connected_client because it uses BleakClient
    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = mock_bleak
        state = await client.read_state()

    assert state.door_closed is True
    assert state.battery_level == 2
    assert state.firmware_info == "X1R  123"
    client._send_sbt.assert_called_once()


@pytest.mark.asyncio
async def test_open_lock_high_level(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)

    client._handshake = AsyncMock()
    client._recv_sbt = AsyncMock(return_value={"status": _SBT_STATUS_OK})
    client._send_sbt = AsyncMock()
    client._recv_csl = AsyncMock()  # for the election wait

    mock_bleak = MagicMock()
    mock_bleak.start_notify = AsyncMock()

    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = mock_bleak
        await client.open_lock()

    client._send_sbt.assert_called_once()
    args, kwargs = client._send_sbt.call_args
    assert args[1] == 43  # _OP_TLV_OPEN


def make_char(uuid, properties):
    char = MagicMock()
    char.uuid = uuid
    char.properties = properties
    return char


def make_service(uuid, characteristics):
    service = MagicMock()
    service.uuid = uuid
    service.characteristics = characteristics
    return service


def make_bleak(services):
    mock_bleak = MagicMock()
    mock_bleak.services = services
    mock_bleak.start_notify = AsyncMock()
    return mock_bleak


def resolve(identity, services):
    """Run characteristic resolution against a mocked GATT and return the picks."""
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._resolve_io_characteristics(make_bleak(services))
    return client._s2c_char, client._c2s_char


def test_resolve_io_prefers_default_characteristics(identity):
    s2c = make_char(_S2C_UUID, ["notify"])
    c2s = make_char(_C2S_UUID, ["write-without-response"])
    services = [make_service(BLE_SERVICE_UUID, [s2c, c2s])]

    assert resolve(identity, services) == (s2c, c2s)


def test_resolve_io_ignores_same_uuid_outside_iseo_service(identity):
    """Regression: a duplicate 0x0001 made bleak refuse to resolve the UUID."""
    decoy = make_char(_S2C_UUID, ["notify"])
    s2c = make_char(_S2C_UUID, ["notify"])
    c2s = make_char(_C2S_UUID, ["write-without-response"])
    services = [
        make_service(_OTHER_SERVICE_UUID, [decoy]),
        make_service(BLE_SERVICE_UUID.upper(), [s2c, c2s]),
    ]

    assert resolve(identity, services) == (s2c, c2s)


def test_resolve_io_picks_usable_duplicate_within_iseo_service(identity):
    unusable = make_char(_S2C_UUID, ["read"])
    s2c = make_char(_S2C_UUID, ["notify"])
    c2s = make_char(_C2S_UUID, ["write-without-response"])
    services = [make_service(BLE_SERVICE_UUID, [unusable, s2c, c2s])]

    assert resolve(identity, services) == (s2c, c2s)


def test_resolve_io_discovers_when_defaults_absent(identity):
    s2c = make_char(_EXTRA_S2C_UUID, ["notify"])
    c2s = make_char(_EXTRA_C2S_UUID, ["write"])
    services = [make_service(BLE_SERVICE_UUID, [s2c, c2s])]

    assert resolve(identity, services) == (s2c, c2s)


def test_resolve_io_keeps_defaults_without_iseo_service(identity):
    services = [make_service(_OTHER_SERVICE_UUID, [make_char(_S2C_UUID, ["notify"])])]

    assert resolve(identity, services) == (_S2C_UUID, _C2S_UUID)


def test_resolve_io_keeps_defaults_on_error(identity):
    mock_bleak = MagicMock()
    type(mock_bleak).services = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)

    client._resolve_io_characteristics(mock_bleak)

    assert (client._s2c_char, client._c2s_char) == (_S2C_UUID, _C2S_UUID)


def test_resolve_io_prefers_unacknowledged_write(identity):
    """A write-without-response char beats a write-only one with the same UUID."""
    s2c = make_char(_S2C_UUID, ["notify"])
    acknowledged = make_char(_C2S_UUID, ["write"])
    unacknowledged = make_char(_C2S_UUID, ["write", "write-without-response"])
    services = [make_service(BLE_SERVICE_UUID, [s2c, acknowledged, unacknowledged])]

    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._resolve_io_characteristics(make_bleak(services))

    assert client._c2s_char is unacknowledged
    assert client._c2s_response is False


def test_resolve_io_uses_acknowledged_write_when_only_option(identity):
    """Regression: BlueZ raised "Failed to initiate write" on a write-only char."""
    s2c = make_char(_S2C_UUID, ["notify"])
    c2s = make_char(_C2S_UUID, ["write"])
    services = [make_service(BLE_SERVICE_UUID, [s2c, c2s])]

    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._resolve_io_characteristics(make_bleak(services))

    assert client._c2s_char is c2s
    assert client._c2s_response is True


def test_resolve_io_pairs_within_one_service_instance(identity):
    """Both directions must come from the same ISEO service instance."""
    lone_notify = make_char(_S2C_UUID, ["notify"])
    s2c = make_char(_S2C_UUID, ["notify"])
    c2s = make_char(_C2S_UUID, ["write-without-response"])
    services = [
        make_service(BLE_SERVICE_UUID, [lone_notify]),
        make_service(BLE_SERVICE_UUID, [s2c, c2s]),
    ]

    assert resolve(identity, services) == (s2c, c2s)


@pytest.mark.asyncio
async def test_send_raw_matches_the_resolved_write_mode(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    c2s = make_char(_C2S_UUID, ["write"])
    services = [make_service(BLE_SERVICE_UUID, [make_char(_S2C_UUID, ["notify"]), c2s])]
    mock_bleak = make_bleak(services)
    mock_bleak.mtu_size = 517
    mock_bleak.write_gatt_char = AsyncMock()

    client._resolve_io_characteristics(mock_bleak)
    await client._send_raw(mock_bleak, b"hello")

    _args, kwargs = mock_bleak.write_gatt_char.call_args
    assert mock_bleak.write_gatt_char.call_args[0][0] is c2s
    assert kwargs["response"] is True


def make_writable_bleak(mtu):
    """Mock a connected client whose ISEO service exposes the default SLIP pair."""
    services = [
        make_service(
            BLE_SERVICE_UUID,
            [
                make_char(_S2C_UUID, ["notify"]),
                make_char(_C2S_UUID, ["write-without-response"]),
            ],
        )
    ]
    mock_bleak = make_bleak(services)
    mock_bleak.mtu_size = mtu
    mock_bleak.write_gatt_char = AsyncMock()
    return mock_bleak


@pytest.mark.asyncio
async def test_send_raw_splits_frames_over_the_link_size(identity):
    """Regression: BlueZ rejects an unacknowledged write longer than MTU-3."""
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    mock_bleak = make_writable_bleak(23)
    client._resolve_io_characteristics(mock_bleak)

    await client._send_raw(mock_bleak, b"\x01" * 100)

    sent = [call.args[1] for call in mock_bleak.write_gatt_char.call_args_list]
    assert all(len(chunk) <= 20 for chunk in sent)
    assert len(sent) > 1


@pytest.mark.asyncio
async def test_send_raw_uses_one_write_when_the_mtu_allows(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    mock_bleak = make_writable_bleak(517)
    client._resolve_io_characteristics(mock_bleak)

    await client._send_raw(mock_bleak, b"\x01" * 100)

    mock_bleak.write_gatt_char.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_raw_reassembles_to_the_original_frame(identity):
    """The chunks the lock receives must concatenate back into one SLIP frame."""
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    mock_bleak = make_writable_bleak(23)
    client._resolve_io_characteristics(mock_bleak)
    payload = bytes(range(200, 256)) * 3

    await client._send_raw(mock_bleak, payload)

    sent = b"".join(call.args[1] for call in mock_bleak.write_gatt_char.call_args_list)
    assert sent == _slip_encode(payload)


@pytest.mark.asyncio
async def test_send_raw_falls_back_when_the_mtu_is_unknown(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    mock_bleak = make_writable_bleak(None)
    type(mock_bleak).mtu_size = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    client._resolve_io_characteristics(mock_bleak)

    await client._send_raw(mock_bleak, b"\x01" * 100)

    sent = [call.args[1] for call in mock_bleak.write_gatt_char.call_args_list]
    assert all(len(chunk) <= 20 for chunk in sent)


@pytest.mark.asyncio
async def test_send_raw_trusts_the_characteristic_over_the_client_mtu(identity):
    """Regression: BleakClient.mtu_size is hardcoded to 23 on BlueZ."""
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    c2s = make_char(_C2S_UUID, ["write-without-response"])
    c2s.max_write_without_response_size = 182
    services = [make_service(BLE_SERVICE_UUID, [make_char(_S2C_UUID, ["notify"]), c2s])]
    mock_bleak = make_bleak(services)
    mock_bleak.mtu_size = 23
    mock_bleak.write_gatt_char = AsyncMock()

    client._resolve_io_characteristics(mock_bleak)
    await client._send_raw(mock_bleak, b"\x01" * 300)

    sent = [call.args[1] for call in mock_bleak.write_gatt_char.call_args_list]
    assert max(len(chunk) for chunk in sent) == 182


def test_parse_csl_header_rejects_a_runt_frame():
    """Regression: a short frame raised struct.error/IndexError out of _recv_csl."""
    with pytest.raises(ValueError):
        _parse_csl_header(b"\x01\x02\x03")


@pytest.mark.asyncio
async def test_recv_csl_skips_malformed_frames(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._rxq.put_nowait(b"\x01\x02\x03")
    client._rxq.put_nowait(_csl_header(_FT_DATA, 7, 0, 5))

    hdr = await client._recv_csl(timeout=1)

    assert hdr["session_id"] == 7
    assert hdr["ta_num"] == 5
    assert hdr["crc8_ok"] is True


@pytest.mark.asyncio
async def test_recv_csl_times_out_on_nothing_but_garbage(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._rxq.put_nowait(b"\x01\x02\x03")

    with pytest.raises(TimeoutError):
        await client._recv_csl(timeout=0.05)


@pytest.mark.asyncio
async def test_recv_csl_skips_frames_with_a_bad_header_crc(identity):
    """A corrupt header means payload_len can't be trusted to slice on."""
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    corrupt = bytearray(_csl_header(_FT_DATA, 1, 0, 2))
    corrupt[7] ^= 0xFF  # clobber the CRC8
    client._rxq.put_nowait(bytes(corrupt))
    client._rxq.put_nowait(_csl_header(_FT_DATA, 9, 0, 3))

    hdr = await client._recv_csl(timeout=1)

    assert hdr["session_id"] == 9
    assert hdr["crc8_ok"] is True


def _open_payload(client):
    """The TLVs of the single TLV_OPEN the client sent."""
    opcode, payload = client._send_sbt.call_args[0][1], client._send_sbt.call_args[0][2]
    assert opcode == 43  # _OP_TLV_OPEN
    return _parse_tlv(payload)


@pytest.mark.parametrize(
    ("open_type", "expected"),
    [
        pytest.param(OPEN_TYPE_NORMAL, 0, id="normal"),
        pytest.param(OPEN_TYPE_PASSAGE_ON, 5, id="passage-on"),
        pytest.param(OPEN_TYPE_PASSAGE_OFF, 6, id="passage-off"),
    ],
)
@pytest.mark.asyncio
async def test_open_lock_sends_the_requested_open_type(identity, open_type, expected):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._handshake = AsyncMock()
    client._recv_csl = AsyncMock()
    client._recv_sbt = AsyncMock(return_value={"status": _SBT_STATUS_OK})
    client._send_sbt = AsyncMock()

    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = make_bleak([])
        await client.open_lock(open_type=open_type)

    assert _open_payload(client)[48] == bytes([expected])


@pytest.mark.parametrize(
    ("open_type", "expected"),
    [
        pytest.param(OPEN_TYPE_NORMAL, 0, id="normal"),
        pytest.param(OPEN_TYPE_PASSAGE_ON, 5, id="passage-on"),
        pytest.param(OPEN_TYPE_PASSAGE_OFF, 6, id="passage-off"),
    ],
)
@pytest.mark.asyncio
async def test_gw_open_sends_the_requested_open_type(identity, open_type, expected):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv, subtype=UserSubType.BT_GATEWAY)
    client._handshake = AsyncMock()
    client._recv_csl = AsyncMock()
    client._recv_sbt = AsyncMock(return_value={"status": _SBT_STATUS_OK})
    client._send_sbt = AsyncMock()

    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = make_bleak([])
        await client.gw_open(open_type=open_type)

    payload = _open_payload(client)
    assert payload[48] == bytes([expected])
    assert payload[49] == b"\x03"  # ValidationMode stays CREDENTIAL_LESS


@pytest.mark.asyncio
async def test_open_lock_defaults_to_a_plain_open(identity):
    uuid_bytes, priv = identity
    client = IseoClient("AA:BB:CC:DD:EE:FF", uuid_bytes, priv)
    client._handshake = AsyncMock()
    client._recv_csl = AsyncMock()
    client._recv_sbt = AsyncMock(return_value={"status": _SBT_STATUS_OK})
    client._send_sbt = AsyncMock()

    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = make_bleak([])
        await client.open_lock()

    assert _open_payload(client)[48] == b"\x00"
