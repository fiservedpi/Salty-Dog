import argparse


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

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a vault")
    init_parser.set_defaults(func=handle_init)

    args = parser.parse_args()
    return args.func(args)


def handle_init(args: argparse.Namespace) -> int:
    print("Vault initialization goes here.")
    return 0
