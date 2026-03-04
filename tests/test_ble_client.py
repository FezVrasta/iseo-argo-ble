import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../custom_components/iseo_argo_ble")))

import asyncio
import pytest
import struct
from unittest.mock import MagicMock, AsyncMock, patch
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from ble_client import (
    IseoClient,
    LockState,
    _OP_TLV_INFO,
    _SBT_STATUS_OK,
    _SBT_PREAMBLE,
    _ADDR_LOCK,
)

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
    payload = (
        bytes([5, 2]) + struct.pack(">H", system_state) +
        bytes([4, 1, 0x80]) +
        bytes([2, 8]) + b"X1R  123"
    )
    
    client._recv_sbt = AsyncMock(return_value={
        "status": _SBT_STATUS_OK,
        "opcode": _OP_TLV_INFO,
        "payload": payload
    })
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
    client._recv_csl = AsyncMock() # for the election wait
    
    mock_bleak = MagicMock()
    mock_bleak.start_notify = AsyncMock()
    
    with patch.object(IseoClient, "_connected_client") as mock_conn:
        mock_conn.return_value.__aenter__.return_value = mock_bleak
        await client.open_lock()
        
    client._send_sbt.assert_called_once()
    args, kwargs = client._send_sbt.call_args
    assert args[1] == 43 # _OP_TLV_OPEN
