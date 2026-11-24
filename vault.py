import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from utils import generate_salt, derive_key

APP_NAME = "SmartVault"
CHECK_PLAINTEXT = b"SMARTVAULT-OK"


class WrongPassphrase(Exception):
    pass


class Vault:
    """A local, offline, passphrase-encrypted file vault backed by SQLite.

    Every value that could identify what's inside (file names, file bytes) is
    stored only as AES-256-GCM ciphertext. The passphrase never touches disk;
    only a salt (to re-derive the key) and a one-block "is this the right
    passphrase" check live in the database.
    """

    def __init__(self, db_path="vault.db", passphrase=None):
        if not passphrase:
            raise ValueError("passphrase is required")

        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_ct BLOB NOT NULL, name_iv BLOB NOT NULL, name_tag BLOB NOT NULL,
                data_ct BLOB NOT NULL, data_iv BLOB NOT NULL, data_tag BLOB NOT NULL,
                size INTEGER NOT NULL
            )"""
        )
        self.conn.commit()

        # The salt is generated once and persisted, so the *same* passphrase
        # always re-derives the *same* key across restarts. Without this, the
        # vault would re-key itself every time it opened and lock itself out
        # of its own files.
        salt = self._get_meta("salt")
        if salt is None:
            salt = generate_salt()
            self._set_meta("salt", salt)
        self.key = derive_key(passphrase, salt)

        check = self._get_meta("check")
        if check is None:
            iv, ct, tag = self._encrypt(CHECK_PLAINTEXT)
            self._set_meta("check", iv + tag + ct)
        else:
            iv, tag, ct = check[:12], check[12:28], check[28:]
            try:
                plaintext = self._decrypt(iv, ct, tag)
            except Exception:
                raise WrongPassphrase("incorrect passphrase for this vault")
            if plaintext != CHECK_PLAINTEXT:
                raise WrongPassphrase("incorrect passphrase for this vault")

    def _get_meta(self, key):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set_meta(self, key, value):
        self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        self.conn.commit()

    def _encrypt(self, data: bytes):
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    def _decrypt(self, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        decryptor = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def add_file(self, file_path: str) -> int:
        """Encrypt a file from disk into the vault. Returns the new entry's id."""
        with open(file_path, "rb") as f:
            data = f.read()
        name = os.path.basename(file_path)

        name_iv, name_ct, name_tag = self._encrypt(name.encode("utf-8"))
        data_iv, data_ct, data_tag = self._encrypt(data)

        cursor = self.conn.execute(
            "INSERT INTO files (name_ct, name_iv, name_tag, data_ct, data_iv, data_tag, size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name_ct, name_iv, name_tag, data_ct, data_iv, data_tag, len(data)),
        )
        self.conn.commit()
        return cursor.lastrowid

    def _decrypt_name(self, row) -> str:
        _id, name_ct, name_iv, name_tag = row
        return self._decrypt(name_iv, name_ct, name_tag).decode("utf-8")

    def list_files(self):
        """Return [(id, name, size), ...] for every file in the vault."""
        rows = self.conn.execute("SELECT id, name_ct, name_iv, name_tag, size FROM files ORDER BY id").fetchall()
        result = []
        for row in rows:
            _id, name_ct, name_iv, name_tag, size = row
            name = self._decrypt(name_iv, name_ct, name_tag).decode("utf-8")
            result.append((_id, name, size))
        return result

    def _find(self, identifier):
        """Resolve an entry by numeric id or by (decrypted) file name."""
        rows = self.conn.execute(
            "SELECT id, name_ct, name_iv, name_tag, data_ct, data_iv, data_tag FROM files"
        ).fetchall()
        for row in rows:
            _id, name_ct, name_iv, name_tag, data_ct, data_iv, data_tag = row
            if str(identifier) == str(_id):
                return row
            name = self._decrypt(name_iv, name_ct, name_tag).decode("utf-8")
            if name == identifier:
                return row
        return None

    def extract_file(self, identifier, output_path: str):
        """Decrypt a vault entry (by name or id) to output_path."""
        row = self._find(identifier)
        if row is None:
            raise FileNotFoundError(f"{identifier!r} not found in vault")
        _id, name_ct, name_iv, name_tag, data_ct, data_iv, data_tag = row
        plaintext = self._decrypt(data_iv, data_ct, data_tag)
        with open(output_path, "wb") as f:
            f.write(plaintext)

    def remove_file(self, identifier):
        row = self._find(identifier)
        if row is None:
            raise FileNotFoundError(f"{identifier!r} not found in vault")
        self.conn.execute("DELETE FROM files WHERE id=?", (row[0],))
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
