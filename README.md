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
