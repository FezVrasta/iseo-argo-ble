# ISEO Argo BLE Lock — Protocol & Project Reference

Protocol documentation for the ISEO Argo BLE lock system (`iseo_reference/`).
This document is the canonical reference for everything in this repo.

---

## Project layout

```
iseo_ble/
├── iseo_cli.py                          CLI tool (scan / open / gw-open / status / logs / identity / delete-user)
├── iseo_identity.json                   CLI identity: UUID hex + priv_scalar hex
├── PROTOCOL.md                          ← this file
└── custom_components/iseo_argo_ble/
    ├── __init__.py                      HA integration entry-point (setup / unload / actions)
    ├── manifest.json                    HA manifest (domain, deps, version)
    ├── const.py                         Shared constants (DOMAIN, CONF_* keys)
    ├── config_flow.py                   HA UI config flow (device picker → register wizard)
    ├── lock.py                          HA LockEntity (unlock / poll state / user-aware logging)
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

## Bluetooth Discovery

### MAC Address Prefix
ISEO devices use the OUI prefix **`00:15:42`** (assigned to Iseo Serrature s.p.a.).

### Advertisement Data (16-bit Service UUIDs)
ISEO locks encode real-time status and device information directly into the **16-bit Service UUIDs** list (Ad Type `0x03`). The app uses `DefaultSbtBtAdvertisingParser` to locate a "marker" UUID and then parses relative offsets.

**Marker UUID Filter:** `(uuid & 0xFFC0) == 0xF000`
Any device advertising a UUID in the range `0xF000` to `0xF03F` is considered an ISEO lock.

#### UUID Field Mapping (Offsets from Marker)
| Offset | Field | Description |
|--------|-------|-------------|
| 0 | **Device Type** | Encodes the hardware model (e.g., `0xF000` = LIBRA, `0xF002` = ARIES). |
| 2 | **Protocol Info** | Versioning and capability flags for the SBT protocol. |
| 3 | **System State** | Real-time status (prefix `0xE000`). See bit-packing below. |
| 4 | **Extended State** | Additional flags for newer hardware (e.g., relay status). |

### Device System State (Prefix `0xE000`)
The UUID at **Offset 3** (typically starting with `0xE`) is a bit-packed 16-bit integer representing the lock's current physical state:

| Bit | Name | Meaning |
|-----|------|---------|
| 15–12 | **Prefix** | Always `0xE` (`1110`). Used to identify the state field. |
| 11 | **Door Status** | `1` = Closed, `0` = Open (if sensor is present). |
| 10 | **Aux Battery** | `1` = Auxiliary battery is low. |
| 9 | **Invitation** | `1` = Invitation is pending/active. |
| 8 | **Passage (L)** | `1` = Passage mode (Light) is active. |
| 5–7 | **Battery** | Battery level: `0` (Critical) to `7` (Full). |
| 4 | **Privacy** | `1` = Privacy mode (DND) is active. |
| 3 | **Passage (N)** | `1` = Passage mode (Normal) is active. |
| 2 | **VIP Mode** | `1` = VIP mode is currently active. |
| 0–1 | **Op Mode** | `0` = Standard, `1` = Office, `2` = Timed. |

---

## BLE GATT

| Role | UUID | Direction |
|------|------|-----------|
| Service | `00001000-d102-11e1-9b23-00025b00a6a6` | — |
| S2C (notify) | `00000001-0000-1000-8000-00805f9b34fb` | lock → phone |
| C2S (write) | `00000002-0000-1000-8000-00805f9b34fb` | phone → lock |

The GATT service UUID is **not** present in advertisements; discovery must rely on the 16-bit Service UUIDs described above.

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

`version = 2`. TA **must start at 1** for every new session. Handshakes must start with `Session ID = 0`.

### Frame types (ftype)

| Value | Name | Description |
|-------|------|-------------|
| 1 | SESSION_REQUEST | Start of handshake |
| 2 | SESSION_HANDSHAKE | Handshake steps 2-4 |
| 3 | SESSION_FIN | Close session |
| 4 | DATA | Application payload (SBT) |
| 5 | ERROR | CSL-level error (e.g. invalid session or busy) |

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
- Status `0` = OK.

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
| 0 | SubType | UINT8 | **16=Smartphone, 17=Gateway** |
| 1 | UUID | 16 bytes | Raw UUID (not string); **always present** |
| 2 | Description | UTF-8 string | Human-readable user name; optional |
| 3 | Options | UINT8 bitmask | See SbtUserOptions below; optional |
| 4 | CreationTs | UINT32 BE | Creation/last-modified Unix epoch; optional |
| 5 | ExtraPin | 7 bytes BCD | Login PIN packed right-aligned; omit if empty |
| 7 | ExtraPinOptions | — | PIN options; optional |
| 12 | Permissions | UINT8 | bitmask for login/admin rights |
| 32 | PublicKey | 56 bytes | X‖Y of SECP224R1 public key; TLV_OPEN only |

### User SubTypes (Tag 0)

| Value | Name | Description |
|-------|------|-------------|
| 16 (0x10) | BT_SMARTPHONE | Standard phone user |
| 17 (0x11) | BT_GATEWAY | Remote access gateway (advanced protocol) |

### SbtUserOptions bitmask (Tag 3)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | VIP | VIP user (kept in "VIP mode") |
| 5 | masterLoginEnabled | "Allow Login" — grants access to admin commands |

Both bits must be set in the Argo app for a user to call TLV_LOGIN + READ_LOG.

---

## Opcodes reference

| Opcode | Constant | Direction | Description |
|--------|----------|-----------|-------------|
| 23 | `_OP_READ_LOG` | app→lock | READ_LOG_INFO — paginated access log |
| 32 | `_OP_TLV_INFO` | app→lock | Read state/capabilities or exchangeInfo |
| 33 | `_OP_TLV_READ_BT_USER`| app→lock | READ_BT_USER — read single user details |
| 36 | `_OP_TLV_READ_USER_BLOCK`| app→lock | READ_USER_BLOCK — paginated whitelist read |
| 38 | `_OP_TLV_STORE_USER_BLOCK`| app→lock | STORE_USER_BLOCK — register/update user |
| 40 | `_OP_TLV_ERASE_USER_BLOCK`| app→lock | ERASE_USER_BLOCK — remove user |
| 41 | `_OP_TLV_LOGIN` | app→lock | TLV_LOGIN — identify as BT user or OEM Login |
| 43 | `_OP_TLV_OPEN` | app→lock | TLV_OPEN — open the lock |
| 64 | `_OP_TLV_LOG_NOTIF_REGISTER` | app→lock | Enable gateway unread log tracking |
| 65 | `_OP_TLV_LOG_NOTIF_UNREGISTER` | app→lock | Disable gateway log tracking |
| 66 | `_OP_TLV_LOG_NOTIF_GET_UNREAD`| app→lock | Fetch unread log entries (Gateway only) |

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
| 3 | CREDENTIAL_LESS (Gateway Mode) |

---

## Master Mode & Registration

ISEO locks use a **Master Mode** for administrative tasks (storing/erasing users). This mode can be entered in two ways:
1.  **Master Password**: Sending a Master Login (Opcode 41) with the password string.
2.  **Master Card**: Physically scanning the Master Card. The lock enters a temporary Master Mode (LEDs blinking).

**The "Scan then Click" Workflow**:
Commands requiring Master Mode (like user registration) must be sent while the lock is in this state. The client should send the command, and if the card is scanned within the timeout window, the lock will process the command.

---

## Gateway Mode (BT_GATEWAY)

When Home Assistant identifies as a Gateway (subtype 17), it gains access to:

### Credential-less Opening (`gwOpen`)
- **Validation Mode**: 3 (`CREDENTIAL_LESS`)
- **Payload**: Includes **Tag 64** (UTF-8 string) which is the name of the remote user.
- **Audit Log**: The lock records this as "Opened by [Remote User] via [Gateway Name]".

### Unread Log Tracking (`gw_logs`)
- **Opcode 66**: Specifically fetches only the log entries that occurred since the last time this gateway UUID polled the lock.
- **Opcode 64**: Must be called once (in Master Mode) to enable this tracking for the UUID.

---

## Error Codes

### CSL Error Codes (Frame Type 5)
| Code | Meaning |
|------|---------|
| 1 | EC_SESSION_ERROR (Invalid Session ID or sequence) |
| 8 | EC_AUTH_ERROR (Handshake failed) |
| 10 | Protocol violation (e.g. TA started at 0) |

### SBT Status Codes (Command Result)
| Status | Meaning |
|--------|---------|
| 0 | OK |
| 3 | CMD_UNSUPPORTED (Invalid feature level) |
| 5 | MASTER_MODE_REQUIRED |
| 9 | NO_PERMISSION (Admin/Login rights missing) |
| 64 | USER_ID_NOT_FOUND |
| 87 | CMD_EC_DENIED |
| 89 | CMD_EC_AUTH_MISMATCH (Subtype or Key mismatch) |
