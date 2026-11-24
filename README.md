<img src="cover.png" alt="offline-encrypted-vault" width="100%">

# offline-encrypted-vault

**An Instagram creator sold a "free, offline, no-cloud encrypted vault" to subscribers only — here's the same thing, actually open, with the one bug that would have silently locked people out of their own files fixed.**

The post (mobile_hacker0) pitched a "Smart Vault" app: encrypts your files and photos, hides them from others, no internet, no account, no cloud, no AI, no ads — gated behind a follower paywall. The idea is sound and doesn't need a gate. This is a small CLI (plus an optional desktop window) that does exactly that: AES-256-GCM encryption, a passphrase you choose, and a SQLite file that sits on your disk and nowhere else.

## What it does

- Encrypts files into a single local SQLite database using AES-256-GCM, keyed by a passphrase you choose (PBKDF2-HMAC-SHA256, 200,000 iterations).
- Encrypts the **file names too**, not just the contents — opening the database file directly shows nobody anything.
- Detects tampering: any bit flipped in the stored ciphertext makes decryption fail loudly instead of returning silently corrupted data.
- Persists the salt it derives your key from, so the same passphrase keeps working after you close and reopen the vault.
- Runs fully offline. No account, no email, no cloud sync, no telemetry, no AI calls, no ads.

## Run it

```
pip install -r requirements.txt

export VAULT_PASSPHRASE="pick something long"
python3 main.py add ~/Documents/secret.pdf
python3 main.py list
python3 main.py extract secret.pdf ~/Desktop/secret.pdf
python3 main.py remove secret.pdf
```

Optional desktop window (needs `tkinter`, which ships with most desktop Python installs but not every sandboxed one):

```
python3 main.py gui
```

Run the proof it works:

```
python3 selftest.py
```

## What it is not

- Not a mobile app. This is a desktop CLI with an optional Tk window, not an iOS/Android build.
- Not a vault for protecting against someone with root/admin on your machine while it's unlocked — the passphrase derives a key held in process memory while running.
- Not audited cryptography research. It uses a standard, well-reviewed library (`cryptography`/OpenSSL) correctly, but it hasn't had a third-party security audit.
- Not a backup tool. There's no redundancy, sync, or recovery if you forget your passphrase — there is no "forgot password" link, by design.

## The honest limits

- Lose the passphrase, lose the files. There is no recovery mechanism, because a recovery mechanism would be a backdoor.
- The vault file itself is not hidden or disguised — it's a visibly-named SQLite file. Anyone can see *a* vault exists; they just can't read what's in it without the passphrase.
- PBKDF2 at 200,000 iterations is solid, not exotic. It won't stop a well-funded attacker with your vault file and unlimited time; it will stop casual snooping, a stolen laptop, or a synced-folder leak.
- The GUI is untested on this machine because this sandbox has no `tkinter` installed — the CLI is what `selftest.py` actually exercises end to end.

## How it fits together

| File | Purpose |
|---|---|
| `vault.py` | Core `Vault` class: AES-256-GCM encryption, PBKDF2 key derivation, persisted salt, encrypted names, tamper detection. |
| `utils.py` | Salt generation and key derivation helpers. |
| `main.py` | Command-line entry point: `add`, `list`, `extract`, `remove`, `gui`. |
| `ui.py` | Optional Tk desktop window over the same `Vault` class. |
| `selftest.py` | End-to-end proof: round-trips files, confirms nothing plaintext hits disk, confirms passphrase persistence, rejects wrong passphrases and tampered ciphertext, drives the real CLI. |
| `requirements.txt` | The one dependency: `cryptography`. |

Built by Warboy. Free, and it stays free.
