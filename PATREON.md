# Smart Vault, but actually free

An Instagram post went around this week pitching a "Smart Vault" app — encrypts your files, hides them from others, works offline, no account, no cloud, no AI, no ads. All true claims, all good instincts. The catch was the gate: free, but only if you're already a subscriber. That's not how open tools work.

So here's the same idea, built in the open: github.com/warboy176/offline-encrypted-vault

It's a small Python tool. You give it a passphrase, it encrypts your files with AES-256-GCM into a single local SQLite database, and it encrypts the file names along with the contents — so even opening the raw database file tells you nothing. Close it, reopen it weeks later with the same passphrase, and it still works, because the salt that derives your key is persisted instead of regenerated every time (the original draft got this wrong and would have locked itself out on every restart — that's the kind of bug a "trust me, it's secure" pitch never has to show you).

It is not a mobile app, not a backup service, not audited by a third party, and not a place to put files you'd be in real trouble for losing. Lose the passphrase and the files are gone — there's no recovery link, because a recovery link is a backdoor wearing a customer-service smile.

What it is: offline, zero telemetry, one dependency, and a `selftest.py` that actually proves the round trip, the tamper detection, and the passphrase persistence instead of asking you to take it on faith.

No paywall, no subscriber tier. If something here is worth building out properly — hardware-key support, multi-device sync done right, whatever — a real V2 happens later, and only if it's worth doing right. Not because a Patreon tier demands a monthly drop.

Witness me.
