# ISEO Argo BLE Lock Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange)](https://hacs.xyz)
[![Home Assistant](https://img.shields.io/badge/home--assistant-compatible-0A75AD)](https://www.home-assistant.io/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

A Home Assistant custom component and command-line utility for controlling ISEO Argo X1R Smart locks via Bluetooth Low Energy (BLE). This integration allows you to lock/unlock your smart door lock, monitor door status, and access lock logs directly from Home Assistant.

> **⚠️ Important Disclaimer**
> 
> This project is **not affiliated with ISEO, Argo, or Home Assistant** and is **not an official product**. This is an independent implementation for interoperability with the Argo lock system. **Use at your own risk.** All trademarks and rights reserved to their respective owners.

## ✨ Features

- **🔓 Lock Control**: Remotely unlock your ISEO Argo X1R smart lock
- **📊 Status Monitoring**: Real-time door open/closed state detection
- **📱 Home Assistant Integration**: Native HA lock entity with status updates
- **🔍 Lock Logs**: Access and retrieve lock activity logs
- **🛠️ CLI Tool**: Standalone command-line utility for testing and debugging
- **🔐 Secure Authentication**: Uses EC cryptography (SECP224R1) for secure communication
- **📡 Bluetooth LE**: Local communication without cloud dependencies
- **🌐 Localization**: Available in English and Italian

## 🚀 Quick Start

### Prerequisites

- Home Assistant with Bluetooth support
- ISEO Argo X1R Smart lock (other models may work but are untested)
- Python 3.13+ (for CLI usage)

### Installation via HACS (Recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=FezVrasta&repository=iseo-argo-ble&category=integration)

1. Click the button above, or open HACS → Integrations → ⋮ → Custom repositories and add `https://github.com/FezVrasta/iseo-argo-ble` with category **Integration**
2. Find "ISEO Argo BLE Lock" in HACS and install it
3. Restart Home Assistant

### Manual Installation

1. Download the latest release
2. Copy the `custom_components/iseo_argo_ble` folder to your Home Assistant `custom_components` directory
3. Restart Home Assistant

## 🔧 Configuration

### Setting up the Lock in Argo App

Before configuring the Home Assistant integration, you need to register a new user in the official Argo app:

1. **Open the Argo app** on your mobile device
2. **Access lock settings**: Click on the door (not the "Open" button)
3. **Admin setup** (if needed): If no admin phone user is configured, scan the master card on the door
4. **Login**: Click on the "Login" button
5. **User management**: Navigate to "Users"
6. **Add new user**: Click the "+" button (top right)
7. **Select phone user**: Choose "Phone with ARGO UID"
8. **Configure user**: 
   - Enter a name (e.g., "Home Assistant")
   - Enter the Home Assistant UID (displayed during HA configuration)
   - Click "Save"
9. **Grant admin permissions** (optional, required for logs):
   - Click on the user you just created
   - Toggle on the "Login" option
   - Click "Done" in the top-right corner

### Home Assistant Configuration

1. **Add Integration**: Go to Settings > Devices & Services > Add Integration
2. **Search**: Look for "ISEO Argo BLE Lock"
3. **Discovery**: The integration will scan for nearby BLE devices
4. **Select Device**: Choose your lock from the list of discovered devices
5. **Authentication**: The system will generate a unique UUID and cryptographic keypair
6. **Pairing**: Follow the on-screen instructions to complete pairing
7. **Verification**: Test the lock functionality

## 🖥️ Command Line Usage

This project includes a standalone CLI tool for direct lock communication. See [CLI.md](CLI.md) for detailed usage instructions, examples, and command reference.

##  Entity Information

### Lock Entity

- **Domain**: `lock`
- **State**: `locked` / `unlocked`
- **Attributes**:
  - `door_state`: Open/closed status (if supported by hardware)
  - `battery_level`: Battery percentage (if available)
  - `last_update`: Timestamp of last status update

### Entity Features

- **Lock/Unlock**: Control lock state
- **Status Polling**: Automatic status updates every 30 seconds
- **Fallback Timeout**: Auto-relock after 5 seconds (when door sensor unavailable)

## ⚠️ Troubleshooting

### Common Issues

**Lock not discovered during setup**
- Ensure Bluetooth is enabled on your Home Assistant device
- Move closer to the lock during setup
- Check that the lock is powered and responsive

**Authentication failed**
- Verify the user was properly added in the Argo app
- Ensure the correct UUID was entered during setup
- Try generating a new identity if issues persist

**Logs not accessible**
- Verify the Home Assistant user has admin permissions in the Argo app
- Check that "Login" option is enabled for the HA user

### Debug Logging

Enable debug logging in Home Assistant:

```yaml
logger:
  default: warning
  logs:
    custom_components.iseo_argo_ble: debug
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! See [DEVELOPERS.md](DEVELOPERS.md) for detailed development setup, guidelines, and technical documentation.

## 🙏 Acknowledgments

- ISEO and Argo for creating the original smart lock system
- The Home Assistant community for the excellent integration platform
- Contributors to the protocol documentation and implementation

## ⚖️ Legal

This project is for educational and personal use only. The developers are not responsible for any damage or malfunction of your smart lock. Always ensure you have alternative access methods to your property.

### European Interoperability Rights

Under European Union law, particularly Article 6 of the EU Software Directive (2009/24/EC), the development of interoperable software solutions may be permitted when necessary to achieve interoperability with independently created programs. This project aims to provide interoperability with existing smart lock systems for legitimate use cases.

**Important**: This information is provided for general awareness only and does not constitute legal advice. Laws vary by jurisdiction and specific circumstances. Users should consult with qualified legal counsel regarding the applicability of interoperability provisions in their specific situation and jurisdiction.
