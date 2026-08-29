import argparse
from getpass import getpass
from pathlib import Path

from .vault import Vault


VAULT_PATH = Path.home() / ".py-vault" / "vault.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="py-vault",
        description="Manage encrypted local secrets.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="py-vault 0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    init_parser = subparsers.add_parser(
        "init",
        help="Create a new encrypted vault.",
    )
    init_parser.set_defaults(func=handle_init)

    set_parser = subparsers.add_parser(
        "set",
        help="Create or update a vault value.",
    )
    set_parser.add_argument(
        "key",
        help="Secret name, for example: github.token",
    )
    set_parser.add_argument(
        "value",
        help="Secret value to encrypt and store.",
    )
    set_parser.set_defaults(func=handle_set)

    get_parser = subparsers.add_parser(
        "get",
        help="Read a vault value.",
    )
    get_parser.add_argument(
        "key",
        help="Secret name to retrieve.",
    )
    get_parser.set_defaults(func=handle_get)

    args = parser.parse_args()
    return args.func(args)


def handle_init(args: argparse.Namespace) -> int:
    if VAULT_PATH.exists():
        print(f"Vault already exists: {VAULT_PATH}")
        return 1

    password = getpass("Create a master password: ")
    confirm_password = getpass("Confirm master password: ")

    if not password:
        print("Master password cannot be empty.")
        return 1

    if password != confirm_password:
        print("Passwords do not match.")
        return 1

    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)

    Vault.create(VAULT_PATH, password)

    print(f"Vault created: {VAULT_PATH}")
    return 0


def handle_set(args: argparse.Namespace) -> int:
    if not VAULT_PATH.exists():
        print("No vault found. Run: py-vault init")
        return 1

    password = getpass("Master password: ")

    try:
        vault = Vault.open(VAULT_PATH, password)
    except ValueError:
        print("Incorrect master password.")
        return 1

    vault.data[args.key] = args.value
    vault.save()

    print(f"Saved secret: {args.key}")
    return 0


def handle_get(args: argparse.Namespace) -> int:
    if not VAULT_PATH.exists():
        print("No vault found. Run: py-vault init")
        return 1

    password = getpass("Master password: ")

    try:
        vault = Vault.open(VAULT_PATH, password)
    except ValueError:
        print("Incorrect master password.")
        return 1

    if args.key not in vault.data:
        print(f"Secret not found: {args.key}")
        return 1

    print(vault.data[args.key])
    return 0