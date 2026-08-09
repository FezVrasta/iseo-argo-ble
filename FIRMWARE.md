# Firmware Delivery & Formats

How the ISEO Argo lock gets firmware, and the format of the images — reverse-engineered
from the ISEO Argo Android app (`com.iseo.android.argo`, v4.1.0).

## Delivery: bundled in the app, not downloaded

**Firmware is not fetched from any server.** Every firmware image ships **inside the
Argo app APK**, under `assets/argo/fw/`. New firmware reaches locks only when the user
**updates the Argo app** (Play Store / App Store). The app picks the correct image for
each connected component and flashes it over BLE:

- **Bluetooth (nRF) module** → **Nordic Secure DFU** (`no.nordicsemi.android.dfu`), using the `.zip` packages.
- **Main board / plates** → ISEO's own firmware-update protocol (`ArgoDeviceFirmwareUpdMgr` → `performUpdate`), using `.ifb` / `.bic` images.

There is no OTA/CDN/Firebase path for firmware; the app is the transport. (The app *is*
Flutter + Firebase, but Firebase is used for accounts/cloud sharing, not firmware.)

## Image formats

| Ext | Component | Format | Encrypted? |
|-----|-----------|--------|------------|
| `.zip` | Bluetooth module | Nordic Secure DFU package (`manifest.json` + `.bin` + `.dat`) | no (standard nRF DFU) |
| `.ifb` | Main board / electronics | ASCII header (`# firmware '#10008 MH15K 2.3.0' [T:0x03] [M:load:size:...]`) followed by a Base64 payload | payload is encrypted (high entropy) |
| `.bic` | Plate / reader | Binary component image | yes (encrypted) |

Only the `.ifb` **header** is human-readable (product id + version, e.g. `MH15K 2.3.0`);
the actual code is encrypted, so the images are not useful for static analysis.

## Integrity & signing — not user-modifiable

These images cannot be edited and re-flashed without ISEO's keys:

- **Bluetooth module (`.zip`)** — **signed** (Nordic Secure DFU). The `.dat` init
  packet is a `signed_command` carrying a SHA-256 hash of the firmware and a 64-byte
  ECDSA (P-256) signature, which the nRF bootloader verifies against a public key baked
  into the device. Modifying the `.bin` invalidates the hash/signature and the bootloader
  rejects it.
- **Main board (`.ifb`) / plates (`.bic`)** — **encrypted** (AES; `.ifb` header
  `[T : 0x03]`) and decrypted/authenticated on-device by the ISEO update protocol. Without
  the key the payload can't be read or meaningfully altered.

Practical consequence: there is no way for this project to patch or downgrade the lock
firmware. A firmware-level fix (e.g. for the polling-crash bug) can only come from ISEO
shipping a corrected build that is flashed through the official Argo app.

## Naming

8-character code `MH` + 6. The trailing group tends to denote the component/model line
(e.g. `...230` main board, `...3xx/5xx` plates; Bluetooth modules ship as `.zip`).

## Extracting the bundled firmware

```
# From the app XAPK/APK:
unzip ISEO+Argo_<ver>_*.xapk com.iseo.android.argo.apk
unzip com.iseo.android.argo.apk 'assets/argo/fw/*' -d out
# → out/assets/argo/fw/*.ifb|*.bic|*.zip
```

## Inventory (app v4.1.0 — 39 images)

| File | Size (B) | Component |
|------|---------:|-----------|
| `MH0YX314.bic` | 326864 | Plate / reader |
| `MH0Z4312.bic` | 257336 | Plate / reader |
| `MH0Z5312.bic` | 258000 | Plate / reader |
| `MH10L312.bic` | 281368 | Plate / reader |
| `MH128312.bic` | 258444 | Plate / reader |
| `MH129312.ifb` | 339502 | Main board / electronics |
| `MH12H120.ifb` | 58831 | Main board / electronics |
| `MH13C505.bic` | 236904 | Plate / reader |
| `MH13D503.bic` | 232768 | Plate / reader |
| `MH14J030.zip` | 180608 | Bluetooth module |
| `MH14K082.zip` | 102826 | Bluetooth module |
| `MH14U350.ifb` | 92907 | Main board / electronics |
| `MH14X350.ifb` | 120469 | Main board / electronics |
| `MH151350.ifb` | 93879 | Main board / electronics |
| `MH154350.ifb` | 97948 | Main board / electronics |
| `MH15F230.ifb` | 385366 | Main board / electronics |
| `MH15G230.ifb` | 389459 | Main board / electronics |
| `MH15J230.ifb` | 419765 | Main board / electronics |
| `MH15K230.ifb` | 484522 | Main board / electronics |
| `MH15L230.ifb` | 337638 | Main board / electronics |
| `MH15N350.ifb` | 83387 | Main board / electronics |
| `MH17J372.ifb` | 94743 | Main board / electronics |
| `MH17P200.ifb` | 398845 | Main board / electronics |
| `MH18U450.ifb` | 119316 | Main board / electronics |
| `MH18V230.ifb` | 455725 | Main board / electronics |
| `MH192430.ifb` | 114169 | Main board / electronics |
| `MH195230.ifb` | 468656 | Main board / electronics |
| `MH198420.ifb` | 113909 | Main board / electronics |
| `MH19B230.ifb` | 455335 | Main board / electronics |
| `MH1A0430.ifb` | 114538 | Main board / electronics |
| `MH1A6430.ifb` | 117759 | Main board / electronics |
| `MH1AB230.ifb` | 459793 | Main board / electronics |
| `MH1AE230.ifb` | 521292 | Main board / electronics |
| `MH1AP440.ifb` | 125500 | Main board / electronics |
| `MH1AV440.ifb` | 80328 | Main board / electronics |
| `MH1B1060.ifb` | 302284 | Main board / electronics |
| `MH1B3060.ifb` | 315690 | Main board / electronics |
| `MH1BJ512.bic` | 236216 | Plate / reader |
| `MH1C4230.ifb` | 490691 | Main board / electronics |
