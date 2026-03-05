# ISEO Argo BLE Lock Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange)](https://hacs.xyz)
[![Home Assistant](https://img.shields.io/badge/home--assistant-compatible-0A75AD)](https://www.home-assistant.io/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

A Home Assistant custom component and command-line utility for controlling ISEO smart locks via Bluetooth Low Energy (BLE). 

This integration makes Home Assistant behave as a native **ISEO ARGO Gateway**, providing a professional-grade implementation with specialized commands and real-time monitoring.

> [!IMPORTANT]
> 
> This project is **not affiliated with ISEO, Argo, or Home Assistant** and is **not an official product**. This is an independent implementation for interoperability with the Argo lock system. **Use at your own risk.** All trademarks and rights reserved to their respective owners.

## ✨ Features

- **🚀 Native Performance**: Uses specialized Gateway commands for fast response times and improved reliability.
- **🤫 Silent Operation**: Log polling is performed using specialized unread-log commands that do **not** trigger the lock's audible "beep."
- **👤 User Attribution**: Attributes remote operations to the specific Home Assistant user. Audit logs will show "Opened by [HA User] via Home Assistant."
- **🔓 Lock Control**: Remotely unlock your ISEO smart lock with real-time feedback.
- **📊 Full Audit Logs**: Access every log entry found on the lock, with automatic mapping to Home Assistant users.
- **🔐 Secure Authentication**: Uses EC cryptography (SECP224R1) for secure session establishment.
- **📡 Local Control**: Direct Bluetooth communication without any cloud dependencies or bridge hardware.

## 🚀 Quick Start

### Prerequisites

- Home Assistant with Bluetooth support.
- ISEO Smart lock (X1R Smart, Smart Series, etc.).
- Physical **Master Card** for the lock (required for setup).

### Installation via HACS (Recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=FezVrasta&repository=iseo-argo-ble&category=integration)

1. Click the button above, or open HACS → Integrations → ⋮ → Custom repositories and add `https://github.com/FezVrasta/iseo-argo-ble` with category **Integration**.
2. Find "ISEO Argo BLE Lock" in HACS and install it.
3. Restart Home Assistant.

## 🔧 Configuration

The integration uses a streamlined "Direct Master Registration" flow.

1. **Add Integration**: Go to Settings > Devices & Services > Add Integration and search for "ISEO Argo BLE Lock".
2. **Discovery**: Select your lock from the discovered Bluetooth devices.
3. **Register Gateway**: When prompted, click **Submit**, then scan your physical **Master Card** on the lock within 30 seconds. The lock will blink green once the card is read successfully.
4. **Fetch Users**: Click **Submit** again and scan the **Master Card** one more time within 30 seconds to download the lock's whitelist.
5. **Map Users**: Link your physical credentials (RFID tags, PINs, phones) to your Home Assistant user accounts.

## 👥 User Mapping

Once configured, you can use the **Configure** button on the integration page to refresh the user mapping. This allows you to:
- Link an RFID tag or PIN to a specific person in Home Assistant.
- See exactly who opened the door in the Home Assistant Logbook.
- Attribute remote openings via the Home Assistant UI to the specific HA user who clicked the button.

##  Entity Information

### Lock Entity

- **Domain**: `lock`
- **State**: `locked` / `unlocked`
- **Attributes**:
  - `door_state`: Open/closed status (requires hardware sensor)
  - `battery_level`: Battery percentage
  - `last_event`: The last recorded action (e.g., "Opened by Marco")

## ⚠️ Troubleshooting

**"No backend with an available connection slot"**
- The lock only supports one active connection. Ensure the Argo app is closed on your phone and no other device is connected to the lock.

**"Auth failed" during Master Card scan**
- Ensure you click **Submit** in Home Assistant **before** scanning the card. The lock must be expecting the command when the card is scanned.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- ISEO and Argo for creating the smart lock system.
- The Home Assistant community for the excellent integration platform.
- Contributors to the protocol documentation and implementation.

## ⚖️ Legal

This project is for educational and personal use only. The developers are not responsible for any damage or malfunction of your smart lock. Always ensure you have alternative access methods to your property.

### European Interoperability Rights

Under European Union law, particularly Article 6 of the EU Software Directive (2009/24/EC), the development of interoperable software solutions may be permitted when necessary to achieve interoperability with independently created programs. This project aims to provide interoperability with existing smart lock systems for legitimate use cases.

**Important**: This information is provided for general awareness only and does not constitute legal advice. Laws vary by jurisdiction and specific circumstances. Users should consult with qualified legal counsel regarding the applicability of interoperability provisions in their specific situation and jurisdiction.
