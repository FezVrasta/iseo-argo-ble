# Developer Documentation

This document contains technical information for developers working on the ISEO Argo BLE Lock Integration.

## 📂 Project Structure

```
iseo_ble/
├── iseo_cli.py                           # CLI tool
├── iseo_identity.json                    # CLI identity storage
├── PROTOCOL.md                          # Protocol documentation
├── CLI.md                               # CLI usage documentation
├── DEVELOPERS.md                        # Developer documentation
├── Pipfile                              # Python dependencies
└── custom_components/iseo_argo_ble/
    ├── __init__.py                      # HA integration entry
    ├── manifest.json                    # HA manifest
    ├── const.py                         # Constants
    ├── config_flow.py                   # HA configuration flow
    ├── lock.py                          # HA lock entity
    ├── ble_client.py                    # Core protocol implementation
    └── translations/
        ├── en.json                      # English translations
        └── it.json                      # Italian translations
```

## 🔨 Development Setup

### Setting up Development Environment

```bash
git clone <repository-url>
cd iseo_ble
pip install pipenv
pipenv install --dev
```

### Protocol Documentation

The communication protocol implementation is documented for interoperability. See [`PROTOCOL.md`](PROTOCOL.md) for detailed technical documentation including:

- BLE service and characteristic UUIDs
- TLV message format specifications
- Authentication and encryption details
- Command reference

### Testing

```bash
# Test CLI functionality
pipenv run python iseo_cli.py --debug scan

# Test lock communication
pipenv run python iseo_cli.py --debug status <lock-address>
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines

1. Follow Python PEP 8 style guidelines
2. Add tests for new functionality
3. Update documentation as needed
4. Test with actual hardware when possible

## 🏗️ Architecture Overview

### Core Components

- **`ble_client.py`**: Core protocol implementation, no Home Assistant dependencies
- **`lock.py`**: Home Assistant lock entity implementation
- **`config_flow.py`**: Home Assistant configuration flow
- **`iseo_cli.py`**: Standalone CLI tool for testing and development

### Protocol Stack

The integration implements a multi-layer protocol stack:

1. **Application Layer**: TLV commands (open, status, logs)
2. **SBT Command Frame**: Structured command format with checksums
3. **CSL Session Layer**: AES-128-CBC encryption with authentication
4. **SLIP Framing**: Byte-stuffing over BLE characteristics
5. **BLE GATT**: Bluetooth Low Energy communication

### Authentication Flow

The system uses ECDH key exchange with SECP224R1 elliptic curve cryptography:

1. **SESSION_REQUEST**: Client sends public key + random
2. **SESSION_HANDSHAKE**: Server responds with encrypted challenge
3. **SESSION_HANDSHAKE**: Client proves key possession
4. **DATA**: Encrypted command/response exchange

## 🧪 Testing Guidelines

### Hardware Testing

- Test with actual ISEO Argo X1R hardware when possible
- Verify BLE connectivity across different environments
- Test authentication flows with various user permissions

### Integration Testing

- Test Home Assistant entity state changes
- Verify configuration flow with device discovery
- Test error handling and recovery scenarios

### CLI Testing

- Test all CLI commands with debug logging enabled
- Verify identity management functionality
- Test connection timeouts and error conditions

## 📋 Code Style

### Python Guidelines

- Follow PEP 8 for code formatting
- Use type hints for function signatures
- Add docstrings for public functions and classes
- Use meaningful variable and function names

### Home Assistant Specific

- Follow HA development guidelines for custom components
- Use proper entity state management
- Implement proper error handling and logging
- Follow HA naming conventions for entities and services

## 🐛 Debugging

### Common Development Issues

**BLE Connection Problems**
- Check Bluetooth adapter capabilities
- Verify proper GATT characteristic access
- Monitor BLE advertising and connection states

**Authentication Failures**
- Verify ECDH key generation and exchange
- Check cryptographic parameter consistency
- Monitor session handshake message flow

**Protocol Errors**
- Enable debug logging for detailed protocol traces
- Verify TLV message formatting
- Check SBT frame structure and checksums

### Debug Logging

Enable comprehensive debug logging during development:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🔧 Development Tools

### Recommended Tools

- **VS Code**: IDE with Python and Home Assistant extensions
- **Wireshark**: For BLE packet capture and analysis
- **nRF Connect**: Mobile app for BLE device inspection
- **Home Assistant Core**: For integration testing

### Useful Scripts

```bash
# Run CLI with debug output
pipenv run python iseo_cli.py --debug scan

# Test specific lock operations
pipenv run python iseo_cli.py --debug status <address>
pipenv run python iseo_cli.py --debug open <address>

# Generate new test identities
pipenv run python iseo_cli.py new-identity
```

## 📚 Additional Resources

- [Home Assistant Developer Documentation](https://developers.home-assistant.io/)
- [BLE Development Guide](https://developer.bluetooth.org/)
- [Python asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
- [Cryptography Library Documentation](https://cryptography.io/)