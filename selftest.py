"""End-to-end selftest for SmartVault. No network, no LLM calls. Exits non-zero on failure."""
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from vault import Vault, WrongPassphrase

PASSPHRASE = "correct-horse-battery-staple-9000"
WRONG_PASSPHRASE = "definitely-the-wrong-one"


def check(name, condition):
    if not condition:
        print(f"FAIL: {name}")
        sys.exit(1)
    print(f"ok: {name}")


def main():
    tmp = tempfile.mkdtemp(prefix="smartvault_selftest_")
    try:
        db_path = os.path.join(tmp, "vault.db")

        secret_text = os.path.join(tmp, "diary.txt")
        with open(secret_text, "w") as f:
            f.write("the machine god remembers everything I feed it.")

        secret_binary = os.path.join(tmp, "photo.bin")
        binary_payload = secrets.token_bytes(4096)
        with open(secret_binary, "wb") as f:
            f.write(binary_payload)

        # 1. Add files, list, extract, and confirm byte-for-byte round trip.
        vault = Vault(db_path=db_path, passphrase=PASSPHRASE)
        vault.add_file(secret_text)
        vault.add_file(secret_binary)

        entries = vault.list_files()
        check("two files listed after adding", len(entries) == 2)
        names = {name for _id, name, _size in entries}
        check("file names recovered correctly", names == {"diary.txt", "photo.bin"})

        out_text = os.path.join(tmp, "out_diary.txt")
        vault.extract_file("diary.txt", out_text)
        with open(out_text) as f:
            check("text file round-trips byte-for-byte", f.read() == "the machine god remembers everything I feed it.")

        out_binary = os.path.join(tmp, "out_photo.bin")
        vault.extract_file("photo.bin", out_binary)
        with open(out_binary, "rb") as f:
            check("binary file round-trips byte-for-byte", f.read() == binary_payload)
        vault.close()

        # 2. Confirm nothing readable sits in the raw database: not names, not contents.
        with open(db_path, "rb") as f:
            raw = f.read()
        check("plaintext file name is not stored on disk", b"diary.txt" not in raw and b"photo.bin" not in raw)
        check("plaintext file content is not stored on disk", b"machine god" not in raw)
        check("raw binary payload is not stored on disk", binary_payload not in raw)

        # 3. Reopen the vault in a fresh process-equivalent instance with the SAME
        #    passphrase. This is the check that catches the "re-keys itself on every
        #    restart and locks itself out" bug: if the salt weren't persisted, this
        #    decrypt would fail.
        vault2 = Vault(db_path=db_path, passphrase=PASSPHRASE)
        out_text2 = os.path.join(tmp, "out_diary2.txt")
        vault2.extract_file("diary.txt", out_text2)
        with open(out_text2) as f:
            check("reopening with the same passphrase still decrypts", f.read() == "the machine god remembers everything I feed it.")

        # 4. Wrong passphrase on an existing vault must be rejected, not silently accepted.
        try:
            Vault(db_path=db_path, passphrase=WRONG_PASSPHRASE)
            check("wrong passphrase is rejected", False)
        except WrongPassphrase:
            check("wrong passphrase is rejected", True)

        # 5. Tamper detection: flipping a stored ciphertext byte must break decryption
        #    instead of silently returning corrupted data.
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT id, data_ct FROM files WHERE id = (SELECT MIN(id) FROM files)").fetchone()
        row_id, data_ct = row
        tampered = bytearray(data_ct)
        tampered[0] ^= 0xFF
        conn.execute("UPDATE files SET data_ct = ? WHERE id = ?", (bytes(tampered), row_id))
        conn.commit()
        conn.close()
        try:
            vault2.extract_file(row_id, os.path.join(tmp, "tampered_out"))
            check("tampered ciphertext is rejected", False)
        except Exception:
            check("tampered ciphertext is rejected", True)

        # 6. Remove the untouched file and confirm it's gone.
        vault2.remove_file("photo.bin")
        remaining = {name for _id, name, _size in vault2.list_files()}
        check("remove_file deletes the entry", "photo.bin" not in remaining)
        vault2.close()

        # 7. Drive the actual CLI end to end, the same way a real user would.
        cli_db = os.path.join(tmp, "cli_vault.db")
        cli_file = os.path.join(tmp, "cli_secret.txt")
        with open(cli_file, "w") as f:
            f.write("cli round trip")
        env = dict(os.environ, VAULT_PASSPHRASE=PASSPHRASE)
        here = os.path.dirname(os.path.abspath(__file__))

        def run_cli(*args):
            return subprocess.run(
                [sys.executable, "main.py", "--db", cli_db, *args],
                cwd=here, env=env, capture_output=True, text=True, timeout=60,
            )

        r = run_cli("add", cli_file)
        check("CLI add exits 0", r.returncode == 0)

        r = run_cli("list")
        check("CLI list shows the added file", r.returncode == 0 and "cli_secret.txt" in r.stdout)

        cli_out = os.path.join(tmp, "cli_out.txt")
        r = run_cli("extract", "cli_secret.txt", cli_out)
        check("CLI extract exits 0", r.returncode == 0)
        with open(cli_out) as f:
            check("CLI extract round-trips content", f.read() == "cli round trip")

        r = run_cli("remove", "cli_secret.txt")
        check("CLI remove exits 0", r.returncode == 0)
        r = run_cli("list")
        check("CLI list is empty after remove", "(vault is empty)" in r.stdout)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("SELFTEST PASS")


if __name__ == "__main__":
    main()
