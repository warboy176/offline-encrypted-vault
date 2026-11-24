import argparse
import getpass
import os
import sys

from vault import Vault, WrongPassphrase

DEFAULT_DB = "vault.db"
PASSPHRASE_ENV_VAR = "VAULT_PASSPHRASE"


def get_passphrase(args):
    if args.passphrase:
        return args.passphrase
    env = os.environ.get(PASSPHRASE_ENV_VAR)
    if env:
        return env
    if not sys.stdin.isatty():
        print(f"error: no passphrase given (use --passphrase or set {PASSPHRASE_ENV_VAR})", file=sys.stderr)
        sys.exit(1)
    return getpass.getpass("Vault passphrase: ")


def open_vault(args):
    try:
        return Vault(db_path=args.db, passphrase=get_passphrase(args))
    except WrongPassphrase as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_add(args):
    with open_vault(args) as vault:
        for path in args.files:
            vault.add_file(path)
            print(f"added {os.path.basename(path)}")


def cmd_list(args):
    with open_vault(args) as vault:
        entries = vault.list_files()
        if not entries:
            print("(vault is empty)")
            return
        for _id, name, size in entries:
            print(f"{_id}\t{name}\t{size} bytes")


def cmd_extract(args):
    with open_vault(args) as vault:
        vault.extract_file(args.identifier, args.output)
        print(f"extracted {args.identifier!r} -> {args.output}")


def cmd_remove(args):
    with open_vault(args) as vault:
        vault.remove_file(args.identifier)
        print(f"removed {args.identifier!r}")


def cmd_gui(args):
    try:
        from ui import launch
    except ImportError as e:
        print(f"error: GUI requires tkinter, which isn't installed ({e})", file=sys.stderr)
        sys.exit(1)
    launch(db_path=args.db, passphrase=get_passphrase(args))


def build_parser():
    parser = argparse.ArgumentParser(prog="main.py", description="SmartVault: offline encrypted file vault")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"path to the vault database file (default: {DEFAULT_DB})")
    parser.add_argument("--passphrase", default=None, help="vault passphrase (prefer the VAULT_PASSPHRASE env var)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="encrypt files into the vault")
    p_add.add_argument("files", nargs="+")
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="list files stored in the vault")
    p_list.set_defaults(func=cmd_list)

    p_extract = sub.add_parser("extract", help="decrypt a file out of the vault")
    p_extract.add_argument("identifier", help="file name or numeric id")
    p_extract.add_argument("output", help="path to write the decrypted file to")
    p_extract.set_defaults(func=cmd_extract)

    p_remove = sub.add_parser("remove", help="delete a file from the vault")
    p_remove.add_argument("identifier", help="file name or numeric id")
    p_remove.set_defaults(func=cmd_remove)

    p_gui = sub.add_parser("gui", help="launch the desktop window (needs tkinter)")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
