# rust_pwd_manager

A tiny command-line tool for managing credentials, developed in Rust.

## Master passphrase and key protection

The data-encryption key is randomly generated and stored only as an authenticated,
XChaCha20-Poly1305-wrapped value. Argon2id derives the wrapping key from a master
passphrase; the key file stores the salt and KDF parameters, not the passphrase or
plaintext data key.

The first `add` prompts for a new master passphrase twice (at least 12 characters).
Later `find`, `add`, `update`, and `import` commands prompt for it without echoing it.
`list` and `delete` do not need the passphrase because account names are stored as
plaintext keys.

Existing base64 key files are upgraded in place the first time a command unlocks them.
The upgrade preserves the existing data key, so it does not require re-encrypting the
vault. Enter a new master passphrase twice during that first unlock. Do not delete or
replace the key file: the vault cannot be decrypted without its wrapped data key.

For non-interactive use, pass `--master-passphrase-file PATH` to commands that unlock a
key. The file must be protected from other users; it contains the master passphrase in
plaintext, so prefer an interactive prompt when possible. Never pass the master
passphrase as a command-line argument.

Example:

```sh
pwd_manager find outlook --reveal
```

The command prompts for the master passphrase. Without `--reveal`, secret values remain
redacted in the output.

## Importing a legacy JSON vault

Back up the legacy JSON file, key file, and (for older vaults) nonce file before importing.
The import keeps the same data key and writes new whole-document encrypted records into a
separate redb vault. It refuses to overwrite accounts already present in the destination;
the batch is committed atomically, so a conflict or invalid legacy record imports nothing.

For a legacy JSON vault that used a shared `nonce.txt`:

```sh
pwd_manager import \
  --legacy-input ./data/output/credentials.json \
  --legacy-nonce-file ./data/input/nonce.txt \
  --key-file ./data/input/key.txt \
  --output ./data/output/vault.redb
```

For a newer legacy JSON vault whose encrypted fields each contain their own nonce, omit
`--legacy-nonce-file`. On first use, a raw base64 key file is upgraded in place to the
passphrase-wrapped format without changing the data key. Use `--master-passphrase-file PATH`
for non-interactive use; the file must be owner-only and contains the passphrase in plaintext.
Keep the backups until you have verified the imported accounts with `find`.
