#!/usr/bin/env python3
"""
ISEO Argo BLE Lock — command-line utility.

Manages a persistent identity (UUID + keypair) stored in iseo_identity.json
and lets you talk to the lock without Home Assistant.

Commands
--------
  scan                        List nearby BLE devices (sorted by RSSI).
  open    <address>           Send TLV_OPEN — opens the lock.
  status  <address>           Read TLV_INFO — show door open/closed state.
  logs    <address>           Fetch access log entries.
  users   <address>           List all enrolled users (requires admin rights).
  identity                    Show the current identity UUID.
  new-identity                Generate a new UUID + keypair and save it.

Global options
--------------
  --identity PATH             Identity file (default: iseo_identity.json
                              next to this script).
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

# ble_client.py lives inside the component folder and has no HA dependencies.
sys.path.insert(0, str(Path(__file__).resolve().parent / "custom_components" / "iseo_argo_ble"))
from ble_client import IseoAuthError, IseoClient, IseoConnectionError, LogEntry, UserEntry, is_iseo_advertisement  # noqa: E402

from bleak import BleakScanner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP224R1,
    derive_private_key,
    generate_private_key,
)

_DEFAULT_IDENTITY = Path(__file__).resolve().parent / "iseo_identity.json"


# ── Identity helpers ──────────────────────────────────────────────────────────

def _load_identity(path: Path) -> tuple[bytes, object]:
    """Return (uuid_bytes, priv_key) from the identity file."""
    if not path.exists():
        sys.exit(
            f"Identity file not found: {path}\n"
            "Run  iseo_cli.py new-identity  to create one."
        )
    data = json.loads(path.read_text())
    uuid_bytes = bytes.fromhex(data["uuid"])
    priv_int   = int(data["priv_scalar"], 16)
    priv       = derive_private_key(priv_int, SECP224R1(), default_backend())
    return uuid_bytes, priv


def _save_identity(path: Path, uuid_bytes: bytes, priv: object) -> None:
    priv_int = priv.private_numbers().private_value
    path.write_text(
        json.dumps({"uuid": uuid_bytes.hex(), "priv_scalar": hex(priv_int)}, indent=2)
        + "\n"
    )


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
    """Open the lock at the given address."""
    uuid_bytes, priv = _load_identity(args.identity)
    client = IseoClient(
        address       = args.address,
        uuid_bytes    = uuid_bytes,
        identity_priv = priv,
    )
    print(f"Connecting to {args.address} …")
    try:
        await client.open_lock(connect_timeout=args.timeout)
    except IseoAuthError as exc:
        sys.exit(
            f"Auth failed: {exc}\n"
            "Make sure the UUID is registered in the Argo app."
        )
    except IseoConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")
    print("Lock opened.")


async def cmd_status(args: argparse.Namespace) -> None:
    """Read the door open/closed state from the lock."""
    uuid_bytes, priv = _load_identity(args.identity)
    client = IseoClient(
        address       = args.address,
        uuid_bytes    = uuid_bytes,
        identity_priv = priv,
    )
    print(f"Connecting to {args.address} …")
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
    uuid_bytes, priv = _load_identity(args.identity)
    client = IseoClient(
        address       = args.address,
        uuid_bytes    = uuid_bytes,
        identity_priv = priv,
    )
    print(f"Connecting to {args.address} …")
    try:
        entries = await client.read_logs(
            start           = args.start,
            max_entries     = args.count,
            connect_timeout = args.timeout,
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
    uuid_bytes, priv = _load_identity(args.identity)
    client = IseoClient(
        address       = args.address,
        uuid_bytes    = uuid_bytes,
        identity_priv = priv,
    )
    print(f"Connecting to {args.address} …")
    try:
        users = await client.read_users(connect_timeout=args.timeout)
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
        name       = u.name or "(no name)"
        print(f"{i:>4}  {type_label:<12}  {u.uuid_hex:<36}  {name}")

    print(f"\n{len(users)} user{'s' if len(users) != 1 else ''} shown.")


def cmd_identity(args: argparse.Namespace) -> None:
    """Print the UUID stored in the identity file."""
    uuid_bytes, _ = _load_identity(args.identity)
    print(f"UUID: {uuid_bytes.hex().upper()}")
    print(f"File: {args.identity}")


def cmd_new_identity(args: argparse.Namespace) -> None:
    """Generate a fresh identity and save it."""
    if args.identity.exists():
        answer = input(
            f"Identity file {args.identity} already exists. Overwrite? [y/N] "
        ).strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    priv       = generate_private_key(SECP224R1(), default_backend())
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
    p_open.add_argument("address", metavar="ADDRESS", help="Lock BLE address")

    p_status = sub.add_parser("status", help="Read door open/closed state")
    p_status.add_argument("address", metavar="ADDRESS", help="Lock BLE address")

    p_logs = sub.add_parser("logs", help="Fetch access log entries")
    p_logs.add_argument("address", metavar="ADDRESS", help="Lock BLE address")
    p_logs.add_argument(
        "--start", metavar="N", type=int, default=0,
        help="Index of first entry to fetch (default: 0)",
    )
    p_logs.add_argument(
        "--count", metavar="N", type=int, default=200,
        help="Maximum number of entries to fetch (default: 200)",
    )

    p_users = sub.add_parser("users", help="List enrolled users (requires admin rights)")
    p_users.add_argument("address", metavar="ADDRESS", help="Lock BLE address")
    p_users.add_argument(
        "--type", metavar="TYPE", nargs="+",
        help="Filter by user type: bluetooth rfid pin invitation fingerprint account",
    )

    sub.add_parser("identity", help="Show the current identity UUID")
    sub.add_parser("new-identity", help="Generate a new UUID + keypair")

    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s  %(name)s  %(message)s",
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    async_cmds = {"scan": cmd_scan, "open": cmd_open, "status": cmd_status, "logs": cmd_logs, "users": cmd_users}
    sync_cmds  = {"identity": cmd_identity, "new-identity": cmd_new_identity}

    if args.command in async_cmds:
        asyncio.run(async_cmds[args.command](args))
    else:
        sync_cmds[args.command](args)


if __name__ == "__main__":
    main()
