# ISEO Argo BLE Lock — Protocol & Project Reference

Protocol documentation for the ISEO Argo BLE lock system (`iseo_reference/`).
This document is the canonical reference for everything in this repo.

---

## Project layout

```
iseo_ble/
├── iseo_cli.py                          CLI tool (scan / open / status / logs / identity)
├── iseo_identity.json                   CLI identity: UUID hex + priv_scalar hex
├── PROTOCOL.md                          ← this file
└── custom_components/iseo_argo_ble/
    ├── __init__.py                      HA integration entry-point (setup / unload)
    ├── manifest.json                    HA manifest (domain, deps, version)
    ├── const.py                         Shared constants (DOMAIN, CONF_* keys)
    ├── config_flow.py                   HA UI config flow (device picker → register)
    ├── lock.py                          HA LockEntity (unlock / poll state)
    └── ble_client.py                    ★ Standalone protocol module (no HA deps)
```

`ble_client.py` is the only file that speaks the wire protocol.
Everything else (CLI + HA) is a thin wrapper around it.

---

## Protocol stack

```
Application (TLV commands)
        ↕
  SBT command frame          preamble + addresses + opcode + payload + checksum
        ↕
  CSL session layer           AES-128-CBC encryption + CBC-MAC integrity
        ↕
  SLIP framing                byte-stuffing over BLE (0xC0 delimiters)
        ↕
  BLE GATT characteristic
        C2S  00000002-…  (phone → lock, write-without-response)
        S2C  00000001-…  (lock → phone, notify)
  Service UUID: 00001000-d102-11e1-9b23-00025b00a6a6
```

---

## BLE GATT

| Role | UUID | Direction |
|------|------|-----------|
| Service | `00001000-d102-11e1-9b23-00025b00a6a6` | — |
| S2C (notify) | `00000001-0000-1000-8000-00805f9b34fb` | lock → phone |
| C2S (write) | `00000002-0000-1000-8000-00805f9b34fb` | phone → lock |

ISEO locks advertise **16-bit service UUIDs** that encode device type, system
state, and protocol info (parsed by `DefaultSbtBtAdvertisingParser`):

| Short UUID | Meaning |
|------------|---------|
| `0xF001` | Device type = X1R_EVO |
| `0xE800` | System state (door closed, battery level, open modes) |
| `0xF040`, `0xF13E`, `0xC020` | Protocol info / state extension |

**Discovery filter:** `(short_uuid & 0xFFC0) == 0xF000` — any device advertising
a UUID in the range `0xF000–0xF03F` is an ISEO lock (`is_iseo_advertisement()`
in `ble_client.py`).

The GATT service (`BLE_SERVICE_UUID = 00001000-d102-11e1-9b23-00025b00a6a6`) is
**not** present in advertisements; it is only visible after a GATT connection.

---

## SLIP framing (`ble_client.py:_slip_encode / _slip_decode`)

Standard RFC 1055 SLIP:

| Symbol | Value |
|--------|-------|
| END | `0xC0` |
| ESC | `0xDB` |
| ESC_END | `0xDC` (follows ESC, represents `0xC0` in data) |
| ESC_ESC | `0xDD` (follows ESC, represents `0xDB` in data) |

Frames are delimited by `0xC0` at both start and end.
The notification handler accumulates chunks in `_slip_buf` and extracts complete
frames into `_rxq` (asyncio.Queue).

---

## CSL session layer (`ble_client.py:_encode_csl / _recv_csl`)

Every SLIP payload is a CSL frame:

```
[Header 8B][Encrypted payload N×16B][Signature S×16B + MAC 16B]
```

### Header (8 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Flags: `(frame_type & 7) << 5 \| (version & 7)` |
| 1 | 2 | Session ID (big-endian) |
| 3 | 2 | Payload length (bytes, big-endian) |
| 5 | 2 | Transaction number TA (big-endian) |
| 7 | 1 | CRC-8 of bytes 0–6 |

`version = 2`. TA increments by 1 with every sent frame.

### Frame types

| Value | Name |
|-------|------|
| 1 | SESSION_REQUEST |
| 2 | SESSION_HANDSHAKE |
| 4 | DATA |

### Payload encryption

The 16-byte-aligned plaintext block is:

```
[CRC16 2B][Len 2B][Salt 12B][Payload NB][Padding PB]
```

Encrypted with AES-128-CBC, key = `pl_key`, IV = zero.

### Signature / MAC

Covers `header + encrypted_payload`; padded to 16-byte boundary.
CBC-MAC computed with `sig_key` (last 16 bytes of AES-CBC output).
Appended as `[padding][MAC 16B]`.

---

## ECDH handshake (`ble_client.py:_handshake`)

Uses **SECP224R1** (224-bit). Public keys are 56 bytes (X‖Y, no 0x04 prefix).

### Step 1 — SESSION_REQUEST (phone → lock)

```
[CryptoSys 2B = 0x0011][LocalPubKey 56B][LocalRandom 8B]
```

### Step 2 — SESSION_HANDSHAKE (lock → phone)

```
[EncStep 16B][ServerPubKey 56B][ServerRandom 8B]
```

The phone derives shared secrets:
```
shared          = ECDH(local_priv, server_pub)
KDK             = CMAC(key=rnd_c‖rnd_s, data=shared)
shs_pl          = CMAC(KDK, LABEL‖0x00‖CONTEXT‖[32, 0])
shs_sig         = CMAC(KDK, LABEL‖0x00‖CONTEXT‖[32, 1])
step_plain      = SHS_decrypt(enc_step, shs_pl, shs_sig)
kb0             = step_plain[:8]
```

`SHS_decrypt(data, pl, sig) = AES_dec(pl, AES_dec(sig, data))`

### Step 3 — SESSION_HANDSHAKE (phone → lock)

```
SHS_encrypt(kb2‖kb0, shs_pl, shs_sig)
```

`kb2` = 8 random bytes chosen by the phone.

### Step 4 — SESSION_HANDSHAKE (lock → phone, confirmation)

Lock echoes `kb0‖kb2` encrypted. Phone verifies both halves.

### Data keys (derived after handshake)

```
final_key = kb0‖kb2        (16 bytes)
pl_key    = AES_enc(final_key, shs_pl)
sig_key   = AES_enc(final_key, shs_sig)
```

Session identity is bound to the **ECDH public key** — the lock identifies the
caller from which keypair performed the handshake, not from any UUID in the
SBT payload.

---

## SBT command frame (`ble_client.py:_build_sbt / _parse_sbt`)

Carried inside the CSL payload.

```
[Preamble 2B = 0xA66A][PayloadLen 2B][Reserved 1B][Src 1B][Dst 1B][Reserved 1B]
[Timestamp 4B (Unix, big-endian)][Opcode 1B][Payload NB][Checksum 1B]
```

- `Src/Dst`: App = 2, Lock = 1.
- Lock responses also include a `Status` byte immediately after `Opcode`:
  `[Opcode 1B][Status 1B][Reserved 4B][Payload NB][Checksum 1B]`
- Checksum: rotating-shift accumulator over all preceding bytes.
- Status `0` = OK; `3` = auth/permission error (most common failure).

---

## TLV encoding (`ble_client.py:_tlv / _parse_tlv`)

Simple 1-byte tag, 1-byte length, variable value. No nesting depth limit.

### SbtUserDataTlvCodec tag map

Used inside TLV_OPEN, TLV_LOGIN, and store-user commands.

The **outer tag** encodes the user type — the inner tags are only emitted when set:

| Outer tag | SbtUserType |
|-----------|-------------|
| 16 | RFID |
| 17 | BLUETOOTH ← used by this integration |
| 18 | PIN |
| 19 | INVITATION |
| 20 | FINGERPRINT |
| 21 | ACCOUNT |

| Inner tag | Name | Format | Notes |
|-----------|------|--------|-------|
| 0 | SubType | UINT8 | Optional sub-classification; omit for plain BT user |
| 1 | UUID | 16 bytes | Raw UUID (not string); **always present** |
| 2 | Description | UTF-8 string | Human-readable user name; optional |
| 3 | Options | UINT8 bitmask | See SbtUserOptions below; optional |
| 4 | CreationTs | UINT32 BE | Creation/last-modified Unix epoch; optional |
| 5 | ExtraPin | 7 bytes BCD | Login PIN packed right-aligned; omit if empty |
| 7 | ExtraPinOptions | — | PIN options; optional |
| 32 | PublicKey | 56 bytes | X‖Y of SECP224R1 public key; TLV_OPEN only |

`_tlv_user_bt(uuid, pub_key=None)` builds the Tag-17 wrapper.

### SbtUserOptions bitmask (Tag 3)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | VIP | VIP user (kept in "VIP mode") |
| 5 | masterLoginEnabled | "Allow Login" — grants access to admin commands |

Both bits must be set in the Argo app for a user to call TLV_LOGIN + READ_LOG.

### TLV_INFO response tag map (Tag 4 / Tag 5)

| Tag | Name | Format | Notes |
|-----|------|--------|-------|
| 4 | Capabilities | multi-byte, big-endian | Bit 7 of first byte = door status supported |
| 5 | SystemState | UINT16 BE | Bit 11 (`0x0800`) = door is closed |

---

## Opcodes reference

| Opcode | Constant | Direction | Description |
|--------|----------|-----------|-------------|
| 23 | `_OP_READ_LOG` | app→lock | READ_LOG_INFO — paginated access log |
| 29 | — | app→lock | OEM_LOGIN — password-based admin login (Argo app internal) |
| 32 | `_OP_TLV_INFO` | app→lock | **Dual use**: (a) empty payload → read state/capabilities; (b) SbtInfoClient payload → exchangeInfo, announces client FL |
| 41 | `_OP_TLV_LOGIN` | app→lock | TLV_LOGIN — identify as BT user for admin commands (requires prior exchangeInfo) |
| 43 | `_OP_TLV_OPEN` | app→lock | TLV_OPEN — open the lock |

### SbtInfoClient TLV payload (used in exchangeInfo)

| Inner tag | Name | Format | Notes |
|-----------|------|--------|-------|
| 1 | featureLevel | UINT16 BE | Client FL; app always sends FL_9 = `00 09` |
| 16 (0x10) | tzConfigRawData | raw bytes | Optional; omit if not cached |

Minimal `exchangeInfo` wire payload: `01 02 00 09` (4 bytes).

---

## SbtOpenType (Tag 48 in TLV_OPEN payload)

| Value | Name |
|-------|------|
| 0 | NORMAL |
| 1 | VIP_MODE_TOGGLE |
| 2 | PASSAGE_MODE_TOGGLE |
| 3 | VIP_MODE_ON |
| 4 | VIP_MODE_OFF |
| 5 | PASSAGE_MODE_ON |
| 6 | PASSAGE_MODE_OFF |

## SbtOpenValidationMode (Tag 49 in TLV_OPEN payload)

| Value | Name |
|-------|------|
| 0 | WHITELIST_CREDENTIAL |
| 1 | VIRTUAL_CREDENTIAL |
| 2 | WHITELIST_CARRIED_CREDENTIAL_BT_GW |
| 3 | CREDENTIAL_LESS |
| 4 | WHITELIST_CARRIED_CREDENTIAL_BT_READER |

---

## Operation flows

### open_lock()

```
BLE connect
  → SLIP/CSL ECDH handshake (3-way)
  → drain optional unsolicited CSL frame (2 s)
  → TLV_OPEN (op=43)
      Tag 48: OpenType = NORMAL (0x00)
      Tag 49: ValidationMode = WHITELIST_CREDENTIAL (0x00)
      Tag 17: BT user wrapper
          Tag 0:  type = 0x10
          Tag 1:  UUID (16B)
          Tag 32: public key (56B)   ← included for initial enrollment
  ← status=0 → success
BLE disconnect
```

Tag 32 (public key) is included on every call — the lock uses it to
enrol new keys and verify existing ones.

### read_state()

```
BLE connect
  → handshake
  → drain optional frame
  → TLV_INFO (op=32, no payload)
  ← response
      Tag 4: capabilities (check bit 7 for door sensor)
      Tag 5: system state (check bit 11 for door_closed)
BLE disconnect
```

Returns `LockState(door_closed=None)` if capability bit is absent.

### read_logs()

```
BLE connect
  → handshake
  → drain optional frame
  → exchangeInfo (op=32, payload=SbtInfoClient)
      Tag 1: featureLevel = FL_9 (0x0009 UINT16 BE) → wire: 01 02 00 09
  ← SbtInfoServer response (ignored; just confirms session is FL_9-capable)
  → TLV_LOGIN (op=41)
      Tag 17: BT user wrapper   ← outer tag encodes user type (BLUETOOTH)
          Tag 1: UUID (16B)     ← only field sent; no Tag 0, no Tag 32
  ← status=0 → proceed
  loop:
    → READ_LOG (op=23)
        [index UINT16 BE][page_size UINT16 BE]
    ← response
        [count UINT16 BE][more_flag UINT8][entries count×71B]
        status ∈ {7, 80} → EOF, stop
  return list[LogEntry]
BLE disconnect
```

### LogEntry wire format (71 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | event_code (UINT8) |
| 1 | 32 | extra_description (UTF-8, space-padded) |
| 33 | 32 | user_info (UTF-8, UUID or name) |
| 65 | 1 | list_code (UINT8) |
| 66 | 1 | battery % (UINT8) |
| 67 | 4 | timestamp (UINT32 BE, Unix epoch) |

---

## Identity file (`iseo_identity.json`)

```json
{
  "uuid": "8f96b3a8563c4878aa070b5168a85265",
  "priv_scalar": "0x1a2b3c..."
}
```

- `uuid`: 32 hex chars = 16 raw bytes. Registered in the Argo app by an admin.
- `priv_scalar`: Private key integer (SECP224R1). The corresponding public key
  (X‖Y, 56 bytes) is derived on the fly and sent in Tag 32 of TLV_OPEN.

The lock identifies callers by **ECDH public key** (matched during the
session handshake), not by the UUID in the payload.

---

## Reference files (`iseo_reference/`)

Key classes for cross-referencing the protocol:

| Class | What it contains |
|-------|-----------------|
| `SbtArgoDevice` | Top-level device; orchestrates TLV_OPEN → TLV_LOGIN flow |
| `SbtArgoTaskLoginBtUser` | Task that calls TLV_LOGIN (opcode 41) |
| `SbtArgoTaskLoginPassword` | Task that calls OEM_LOGIN (opcode 29, password) |
| `DefaultSbtClientFl3MasterCmdHandler` | FL3 handler: `performBtUserLogin()`, `openAdvWithWhitelistCred()` |
| `SbtUserDataTlvCodec` | Encodes/decodes the Tag-17 BT user TLV |
| `SbtUserOptions` | Bitmask constants (VIP=bit0, masterLoginEnabled=bit5) |
| `SbtUserExtraPin` | Optional login PIN (TLV tag 5); `EMPTY` sentinel |
| `SbtLogEntryCodec` | Decodes 71-byte log entries |
| `SbtOpenType` | Enum for Tag 48 values |
| `SbtOpenValidationMode` | Enum for Tag 49 values |
| `CslFrameCodec` / `CslFrameHeader` | CSL layer encode/decode |
| `SlipEncoder` / `SlipDecoder` | SLIP byte-stuffing |
| `SbtClientSendReceiveHelper` | SBT frame builder / parser |
