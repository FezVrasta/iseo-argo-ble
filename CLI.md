# Command Line Usage

The project includes a standalone CLI tool for direct lock communication:

```bash
# Install dependencies
pip install pipenv
pipenv install

# Available commands
pipenv run python iseo_cli.py scan                    # List nearby BLE devices
pipenv run python iseo_cli.py open <address>          # Unlock the lock
pipenv run python iseo_cli.py status <address>        # Check door status
pipenv run python iseo_cli.py logs <address>          # Retrieve lock logs
pipenv run python iseo_cli.py identity               # Show current identity
pipenv run python iseo_cli.py new-identity           # Generate new identity

# Global options
--identity <path>      # Custom identity file location
--timeout <seconds>    # BLE connection timeout (default: 20s)
--debug               # Enable debug logging
```

## CLI Identity Management

The CLI tool maintains a persistent identity in `iseo_identity.json` containing:
- **UUID**: Unique identifier for the client
- **Private Key**: EC private key for authentication

## Examples

### Basic Usage

```bash
# Scan for nearby BLE devices
pipenv run python iseo_cli.py scan

# Check lock status
pipenv run python iseo_cli.py status AA:BB:CC:DD:EE:FF

# Unlock the door
pipenv run python iseo_cli.py open AA:BB:CC:DD:EE:FF

# Retrieve lock logs (requires admin permissions)
pipenv run python iseo_cli.py logs AA:BB:CC:DD:EE:FF
```

### Debug Mode

```bash
# Enable debug logging for troubleshooting
pipenv run python iseo_cli.py --debug scan
pipenv run python iseo_cli.py --debug status AA:BB:CC:DD:EE:FF
```

### Custom Identity File

```bash
# Use a different identity file
pipenv run python iseo_cli.py --identity /path/to/custom_identity.json open AA:BB:CC:DD:EE:FF

# Create a new identity
pipenv run python iseo_cli.py new-identity
```

### Extended Timeout

```bash
# Use longer timeout for slow connections
pipenv run python iseo_cli.py --timeout 30 open AA:BB:CC:DD:EE:FF
```

## CLI Output Examples

### Scan Output
```
Found 5 BLE device(s):
  AA:BB:CC:DD:EE:FF  RSSI: -45 dBm  Name: "ISEO_X1R_123456"
  11:22:33:44:55:66  RSSI: -67 dBm  Name: "Unknown Device"
  ...
```

### Status Output
```
Lock Status: LOCKED
Door Status: CLOSED
Battery: 85%
Last Update: 2026-03-01 10:30:45
```

### Identity Output
```
Current Identity:
  UUID: 8f96b3a8-563c-4878-aa07-0b5168a85265
  Public Key: 04a1b2c3d4e5f6...
```