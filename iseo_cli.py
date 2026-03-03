#!/usr/bin/env python3
"""
ISEO Argo BLE Lock — command-line utility.

Manages a persistent identity (UUID + keypair) stored in iseo_identity.json
and lets you talk to the lock without Home Assistant.

Commands
--------
  scan                        List nearby BLE devices (sorted by RSSI).
  open    [address]           Send TLV_OPEN — opens the lock.
  gw-open [address]           Send TLV_OPEN (Gateway mode) — credential-less opening.
  status  [address]           Read TLV_INFO — show door open/closed state.
  logs    [address]           Fetch access log entries.
  gw-logs [address]           Fetch unread Gateway log entries (opcode 66).
  gw-register-logs [address]  Enable log notifications for this Gateway (opcode 64).
  users   [address]           List all enrolled users (requires admin rights).
  identity                    Show the current identity UUID.
  new-identity                Generate a new UUID + keypair and save it.
  register-gateway [address]  Register identity as a Gateway (requires master password).
  register-pin     [address]  Register/Update a PIN user (requires master password).
  erase-identity   [address]  Remove current identity from lock whitelist.
  delete-user      [address]  Remove specific user by UUID (requires admin rights).

Global options
--------------
  --identity PATH             Identity file (default: iseo_identity.json
                              next to this script).
  --subtype {smartphone,gateway}
                              User subtype (default: smartphone).
  --timeout SECONDS           BLE connect timeout (default: 20).
  --debug                     Enable debug logging.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid as uuid_module
from pathlib import Path
from typing import TYPE_CHECKING

# ble_client.py lives inside the component folder and has no HA dependencies.
sys.path.insert(0, str(Path(__file__).resolve().parent / "custom_components" / "iseo_argo_ble"))
from ble_client import (
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    MasterAuthError,
    UserSubType,
    is_iseo_advertisement,
)  # noqa: E402

if TYPE_CHECKING:
    pass

from bleak import BleakScanner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

_DEFAULT_IDENTITY = Path(__file__).resolve().parent / "iseo_identity.json"


# ── Identity helpers ──────────────────────────────────────────────────────────


def _load_identity(path: Path) -> tuple[bytes, object, str | None]:
    """Return (uuid_bytes, priv_key, address) from the identity file."""
    if not path.exists():
        sys.exit(f"Identity file not found: {path}\nRun  iseo_cli.py new-identity  to create one.")
    data = json.loads(path.read_text())
    uuid_bytes = bytes.fromhex(data["uuid"])
    priv_int = int(data["priv_scalar"], 16)
    priv = ec.derive_private_key(priv_int, ec.SECP224R1(), default_backend())
    address = data.get("address")
    return uuid_bytes, priv, address


def _save_identity(path: Path, uuid_bytes: bytes, priv: object, address: str | None = None) -> None:
    # Use the concrete class for type checking to satisfy mypy
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise TypeError("Expected EllipticCurvePrivateKey")
    # Some cryptography versions/backends might not expose private_numbers()
    # directly on the interface, but our SECP224R1 keys always have it.
    priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
    data = {"uuid": uuid_bytes.hex(), "priv_scalar": hex(priv_int)}
    if address:
        data["address"] = address
    path.write_text(json.dumps(data, indent=2) + "\n")


def _get_effective_address(args: argparse.Namespace, uuid_bytes: bytes, priv: object, stored_address: str | None) -> str:
    """Resolve address from args or storage, and update storage if needed."""
    address = args.address or stored_address
    if not address:
        sys.exit("Error: No lock address provided and none stored in identity file.")
    if args.address and args.address != stored_address:
        _save_identity(args.identity, uuid_bytes, priv, address)
    return address


# ── Commands ──────────────────────────────────────────────────────────────────


async def cmd_scan(_args: argparse.Namespace) -> None:
    """Scan for nearby ISEO BLE locks and print them sorted by RSSI."""
    print("Scanning for ISEO locks (5 s) …")
    devices = await BleakScanner.discover(timeout=5.0, return_adv=True)

    rows = []
    for _addr, (dev, adv) in devices.items():
        if not is_iseo_advertisement(list(adv.service_uuids)):
            continue
        rows.append((adv.rssi or -999, dev.address, dev.name or "Unknown"))

    if not rows:
        print("No ISEO locks found nearby.")
        return

    rows.sort(key=lambda r: r[0], reverse=True)
    print(f"\n{'RSSI':>6}  {'Address':>17}  Name")
    print("-" * 50)
    for rssi, addr, name in rows:
        print(f"{rssi:>6} dBm  {addr}  {name}")


async def cmd_open(args: argparse.Namespace) -> None:
    """Open the lock."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )
    print(f"Connecting to {address} …")
    try:
        await client.open_lock(connect_timeout=args.timeout)
    except IseoAuthError as exc:
        sys.exit(
            f"Auth failed: {exc}\n"
            "Make sure the UUID is registered in the Argo app with the correct subtype."
        )
    except IseoConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")
    print("Lock opened.")


async def cmd_gw_open(args: argparse.Namespace) -> None:
    """Open the lock using Gateway remote opening mode."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=UserSubType.BT_GATEWAY,
    )
    print(f"Connecting to {address} as Gateway …")
    try:
        await client.gw_open(remote_user_name=args.user, connect_timeout=args.timeout)
    except IseoAuthError as exc:
        sys.exit(f"Auth failed: {exc}\nMake sure the UUID is registered as an ARGO GATEWAY in the app.")
    except Exception as exc:
        sys.exit(f"Error: {exc}")
    print(f"Lock opened (remote user: {args.user}).")


async def cmd_gw_logs(args: argparse.Namespace) -> None:
    """Fetch unread access log entries for this Gateway."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=UserSubType.BT_GATEWAY,
    )
    print(f"Connecting to {address} to fetch unread Gateway logs …")
    try:
        entries = await client.gw_read_unread_logs(connect_timeout=args.timeout)
    except Exception as exc:
        sys.exit(f"Error: {exc}")

    if not entries:
        print("No new log entries.")
        return

    print(f"Fetched {len(entries)} new log entries:")
    for entry in entries:
        print(
            f"[{entry.timestamp.isoformat()}] Code={entry.event_code:02d} "
            f"User={entry.user_info:<16} Desc={entry.extra_description}"
        )


async def cmd_gw_register_log_notif(args: argparse.Namespace) -> None:
    """Register Gateway for log notifications (opcode 64)."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=UserSubType.BT_GATEWAY,
    )
    print(f"Connecting to {address} to register for log notifications …")
    try:
        await client.gw_register_log_notif(
            master_password=args.password,
            connect_timeout=args.timeout,
        )
    except MasterAuthError as exc:
        sys.exit(f"Master login failed: {exc}. Check your admin password.")
    except Exception as exc:
        sys.exit(f"Registration failed: {exc}")

    print("Success! Gateway registered for real-time log notifications.")


async def cmd_register_gateway(args: argparse.Namespace) -> None:
    """Register the current identity as an Argo Gateway on the lock."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=UserSubType.BT_GATEWAY,
    )

    print(f"Connecting to {address} to register Gateway …")
    if not args.password:
        print("\nIMPORTANT: To register a Gateway, the lock must be in Master Mode.")
        input("1. Press Enter now.\n2. Within 30 seconds, scan your Master Card on the lock: ")

    try:
        await client.register_user(
            master_password=args.password,
            name=args.name,
            connect_timeout=args.timeout,
        )
    except MasterAuthError as exc:
        sys.exit(f"Master login failed: {exc}. Check your admin password.")
    except Exception as exc:
        sys.exit(f"Registration failed: {exc}")

    print(f"Success! Identity {uuid_bytes.hex().upper()} registered as Gateway '{args.name}'.")
    print("You can now use:  iseo_cli.py gw-open")


async def cmd_register_pin(args: argparse.Namespace) -> None:
    """Register or update a PIN user on the lock."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )

    pin_uuid = args.uuid
    if not pin_uuid:
        # PIN users in Argo use a shortened 7-byte UUID.
        import secrets
        pin_uuid = secrets.token_hex(7)
        print(f"Generated new 7-byte UUID for PIN user: {pin_uuid.upper()}")
    elif len(pin_uuid) > 14:
        pin_uuid = pin_uuid[:14]
        print(f"Truncated UUID to 7 bytes (14 hex chars): {pin_uuid.upper()}")

    print(f"Connecting to {address} to register PIN …")
    try:
        await client.register_pin_user(
            pin_uuid_bytes=bytes.fromhex(pin_uuid),
            pin=args.pin,
            name=args.name or "New PIN User",
            master_password=args.password,
            connect_timeout=args.timeout,
            skip_login=args.master,
        )
    except IseoAuthError as exc:
        if "Master Mode Required" in str(exc) and not args.master and not args.password:
            print("\nError: The lock requires Master Mode for this operation.")
            print("1. Scan your physical Master Card on the lock (LEDs will blink).")
            input("2. Press Enter once the card is scanned to retry: ")

            # Retry with skip_login=True (Master Mode)
            await client.register_pin_user(
                pin_uuid_bytes=bytes.fromhex(pin_uuid),
                pin=args.pin,
                name=args.name,
                master_password=args.password,
                connect_timeout=args.timeout,
                skip_login=True,
            )
        else:
            sys.exit(f"Registration failed: {exc}")
    except Exception as exc:
        sys.exit(f"Registration failed: {exc}")

    print(f"Success! PIN user '{args.name or pin_uuid.upper()}' registered with UUID {pin_uuid.upper()}.")


async def cmd_erase_identity(args: argparse.Namespace) -> None:
    """Remove the current identity from the lock's whitelist."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )
    print(f"Connecting to {address} to erase identity …")
    try:
        await client.erase_user(connect_timeout=args.timeout)
    except Exception as exc:
        sys.exit(f"Erase failed: {exc}")

    print(f"Success! Identity {uuid_bytes.hex().upper()} removed from lock.")


async def cmd_delete_user(args: argparse.Namespace) -> None:
    """Remove a specific user from the lock's whitelist (interactive)."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )

    target_uuid_hex = args.uuid
    target_type = args.user_type
    target_subtype = args.user_subtype

    if not target_uuid_hex:
        print(f"Connecting to {address} to fetch users …")
        try:
            users = await client.read_users(connect_timeout=args.timeout)
        except Exception as exc:
            sys.exit(f"Failed to fetch users: {exc}")

        print("\nRegistered Users:")
        for i, u in enumerate(users, 1):
            if u.user_type == 17:
                st_label = "Gateway" if u.inner_subtype == 17 else "Phone"
            elif u.user_type == 18:
                st_label = "PIN"
            elif u.user_type == 16:
                st_label = "RFID"
            else:
                st_label = f"Type {u.user_type}"
            print(f" {i:2}. {u.name or '<no name>':<16} {st_label:<10} UUID={u.uuid_hex.upper()}")

        try:
            choice = input(f"\nSelect a user to delete (1-{len(users)}, or Enter to cancel): ").strip()
            if not choice:
                print("Cancelled.")
                return
            idx = int(choice) - 1
            if idx < 0 or idx >= len(users):
                print("Invalid selection.")
                return

            selected = users[idx]
            target_uuid_hex = selected.uuid_hex
            target_type = selected.user_type
            target_subtype = selected.inner_subtype or 16
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return

    # Final confirmation
    print(f"\nTarget UUID: {target_uuid_hex.upper()}")
    confirm = input("Are you SURE you want to remove this user from the lock? (type 'yes' to confirm): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    print("\nIMPORTANT: To delete a user, the lock must be in Master Mode.")
    input("1. Press Enter now.\n2. Within 30 seconds, scan your Master Card on the lock: ")

    print("Deleting user …")
    try:
        await client.erase_user_by_uuid(
            uuid_bytes=bytes.fromhex(target_uuid_hex),
            user_type=target_type,
            subtype=target_subtype,
            connect_timeout=args.timeout,
        )
    except Exception as exc:
        sys.exit(f"Delete failed: {exc}")

    print(f"Success! User {target_uuid_hex.upper()} removed from lock.")


async def cmd_status(args: argparse.Namespace) -> None:
    """Read the door open/closed state from the lock."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )
    print(f"Connecting to {address} …")
    try:
        state = await client.read_state(connect_timeout=args.timeout)
    except IseoAuthError as exc:
        sys.exit(f"Auth failed: {exc}")
    except IseoConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")

    if state.door_closed is None:
        print("Door status: NOT SUPPORTED (Door Status Advice not enabled on this lock)")
    elif state.door_closed:
        print("Door status: CLOSED (locked)")
    else:
        print("Door status: OPEN (unlatched)")


async def cmd_logs(args: argparse.Namespace) -> None:
    """Fetch and print access log entries from the lock."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )
    print(f"Connecting to {address} …")
    if args.master:
        print("\nIMPORTANT: You chose --master mode. Ensure the Master Card is scanned.")
        input("Press Enter when ready: ")

    try:
        entries = await client.read_logs(
            start=args.start,
            max_entries=args.count,
            connect_timeout=args.timeout,
            skip_login=args.master,
        )
    except IseoAuthError as exc:
        sys.exit(f"Auth failed: {exc}")
    except IseoConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")

    if not entries:
        print("No log entries found.")
        return

    print(f"\n{'#':>4}  {'Timestamp (UTC)':>22}  {'Ev':>3}  {'Bat':>3}  {'User / UUID':<36}  Extra")
    print("-" * 100)
    for i, e in enumerate(entries):
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{args.start + i:>4}  {ts:>22}  {e.event_code:>3}  {e.battery:>3}%"
            f"  {e.user_info:<36}  {e.extra_description}"
        )
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} shown.")


_USER_TYPE_LABELS: dict[int, str] = {
    16: "RFID",
    17: "Bluetooth",
    18: "PIN",
    19: "Invitation",
    20: "Fingerprint",
    21: "Account",
}


async def cmd_users(args: argparse.Namespace) -> None:
    """Fetch and print all enrolled users from the lock whitelist."""
    uuid_bytes, priv, stored_address = _load_identity(args.identity)
    address = _get_effective_address(args, uuid_bytes, priv, stored_address)

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=args.subtype,
    )
    print(f"Connecting to {address} …")
    if args.master:
        print("\nIMPORTANT: You chose --master mode. Ensure the Master Card is scanned.")
        input("Press Enter when ready: ")

    try:
        users = await client.read_users(
            connect_timeout=args.timeout,
            skip_login=args.master,
        )
    except IseoAuthError as exc:
        sys.exit(f"Auth failed: {exc}")
    except IseoConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")

    if not users:
        print("No users found.")
        return

    # Optional filter by type
    if args.type:
        wanted = {t.lower() for t in args.type}
        users = [u for u in users if _USER_TYPE_LABELS.get(u.user_type, "").lower() in wanted]
        if not users:
            print("No users match the requested type(s).")
            return

    print(f"\n{'#':>4}  {'Type':<12}  {'UUID':<36}  Name")
    print("-" * 80)
    for i, u in enumerate(users, start=1):
        type_label = _USER_TYPE_LABELS.get(u.user_type, f"Type{u.user_type}")
        name = u.name or "(no name)"
        print(f"{i:>4}  {type_label:<12}  {u.uuid_hex:<36}  {name}")

    print(f"\n{len(users)} user{'s' if len(users) != 1 else ''} shown.")


def cmd_identity(args: argparse.Namespace) -> None:
    """Print the UUID stored in the identity file."""
    uuid_bytes, _, address = _load_identity(args.identity)
    print(f"UUID:    {uuid_bytes.hex().upper()}")
    if address:
        print(f"Address: {address}")
    print(f"File:    {args.identity}")


def cmd_new_identity(args: argparse.Namespace) -> None:
    """Generate a fresh identity and save it."""
    if args.identity.exists():
        answer = input(f"Identity file {args.identity} already exists. Overwrite? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
    uuid_bytes = uuid_module.uuid4().bytes
    _save_identity(args.identity, uuid_bytes, priv)

    print(f"New identity saved to {args.identity}")
    print()
    print("Register this UUID in the Argo app before opening the lock:")
    print()
    print(f"  {uuid_bytes.hex().upper()}")
    print()
    print("Then run:  iseo_cli.py open <address>")


# ── Entry point ───────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iseo_cli.py",
        description="ISEO Argo BLE Lock — command-line utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--identity",
        metavar="PATH",
        type=Path,
        default=_DEFAULT_IDENTITY,
        help=f"Identity file (default: {_DEFAULT_IDENTITY.name})",
    )

    def subtype_type(val: str) -> int:
        if val.lower() == "smartphone":
            return UserSubType.BT_SMARTPHONE
        if val.lower() == "gateway":
            return UserSubType.BT_GATEWAY
        try:
            return int(val, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid subtype: {val}") from exc

    parser.add_argument(
        "--subtype",
        type=subtype_type,
        default=UserSubType.BT_SMARTPHONE,
        help="User subtype: smartphone, gateway, or raw integer (default: smartphone)",
    )
    parser.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=20.0,
        help="BLE connect timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    sub.add_parser("scan", help="List nearby BLE devices sorted by RSSI")

    p_open = sub.add_parser("open", help="Open the lock")
    p_open.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")

    p_gw_open = sub.add_parser("gw-open", help="Open the lock (Gateway mode)")
    p_gw_open.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_gw_open.add_argument(
        "--user",
        metavar="NAME",
        default="Home Assistant",
        help="Remote user name to show in lock logs (default: Home Assistant)",
    )

    p_status = sub.add_parser("status", help="Read door open/closed state")
    p_status.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")

    p_logs = sub.add_parser("logs", help="Fetch access log entries")
    p_logs.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_logs.add_argument(
        "--start",
        metavar="N",
        type=int,
        default=0,
        help="Index of first entry to fetch (default: 0)",
    )
    p_logs.add_argument(
        "--count",
        metavar="N",
        type=int,
        default=200,
        help="Maximum number of entries to fetch (default: 200)",
    )
    p_logs.add_argument("--master", action="store_true", help="Skip login (assume lock is in Master Mode via card)")

    p_gw_logs = sub.add_parser("gw-logs", help="Fetch unread Gateway log entries")
    p_gw_logs.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")

    p_gw_reg_logs = sub.add_parser("gw-register-logs", help="Register for log notifications")
    p_gw_reg_logs.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_gw_reg_logs.add_argument("--password", help="Lock master password")

    p_users = sub.add_parser("users", help="List enrolled users (requires admin rights)")
    p_users.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_users.add_argument(
        "--type",
        metavar="TYPE",
        nargs="+",
        help="Filter by user type: bluetooth rfid pin invitation fingerprint account",
    )
    p_users.add_argument("--master", action="store_true", help="Skip login (assume lock is in Master Mode via card)")

    sub.add_parser("identity", help="Show the current identity UUID")
    sub.add_parser("new-identity", help="Generate a new UUID + keypair")

    p_reg_gw = sub.add_parser("register-gateway", help="Register current identity as Gateway")
    p_reg_gw.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_reg_gw.add_argument("--password", help="Lock master password (optional if Master Card is scanned first)")
    p_reg_gw.add_argument("--name", default="Home Assistant", help="Name for the gateway user")

    p_reg_pin = sub.add_parser("register-pin", help="Register/Update a PIN user")
    p_reg_pin.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_reg_pin.add_argument("pin", metavar="PIN", help="4-14 digit PIN code")
    p_reg_pin.add_argument("--name", help="Name for the PIN user")
    p_reg_pin.add_argument("--uuid", help="32-char hex UUID (generated if omitted)")
    p_reg_pin.add_argument("--password", help="Lock master password")
    p_reg_pin.add_argument("--master", action="store_true", help="Skip login (assume lock is in Master Mode via card)")

    p_erase = sub.add_parser("erase-identity", help="Remove current identity from lock")
    p_erase.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_erase.add_argument("--password", help="Lock master password (optional if Master Card is scanned first)")

    p_del_user = sub.add_parser("delete-user", help="Remove specific user (interactive if no UUID)")
    p_del_user.add_argument("address", metavar="ADDRESS", nargs="?", help="Lock BLE address")
    p_del_user.add_argument("--uuid", help="32-char hex UUID to delete (omit for interactive list)")
    p_del_user.add_argument(
        "--user-type",
        type=int,
        default=17,
        help="Type of the user to delete (16=RFID, 17=Bluetooth, 18=PIN)",
    )
    p_del_user.add_argument(
        "--user-subtype",
        type=int,
        default=UserSubType.BT_SMARTPHONE,
        help="Subtype of the user to delete (16=Phone, 17=Gateway). Only for BT users.",
    )
    p_del_user.add_argument("--password", help="Lock master password (optional if Master Card is scanned first)")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s  %(name)s  %(message)s",
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    async_cmds = {
        "scan": cmd_scan,
        "open": cmd_open,
        "gw-open": cmd_gw_open,
        "gw-logs": cmd_gw_logs,
        "gw-register-logs": cmd_gw_register_log_notif,
        "status": cmd_status,
        "logs": cmd_logs,
        "users": cmd_users,
        "register-gateway": cmd_register_gateway,
        "register-pin": cmd_register_pin,
        "erase-identity": cmd_erase_identity,
        "delete-user": cmd_delete_user,
    }
    sync_cmds = {"identity": cmd_identity, "new-identity": cmd_new_identity}

    if args.command in async_cmds:
        asyncio.run(async_cmds[args.command](args))
    else:
        sync_cmds[args.command](args)


if __name__ == "__main__":
    main()
