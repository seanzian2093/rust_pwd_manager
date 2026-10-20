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

To copy only one selected secret to the system clipboard without printing it:

```sh
pwd_manager find outlook --copy-password
pwd_manager find outlook --copy-answer 1
pwd_manager find outlook --copy-sub-password 1
```

Answer and sub-credential indices are 1-based. Clipboard contents may be visible to
clipboard managers or other applications and are not automatically cleared.
The `scripts/demo_find_options.sh` script demonstrates redacted output, `--reveal`, and
each clipboard option. Run it as a command (do not `source` it); for example:

```sh
scripts/demo_find_options.sh outlook copy-answer 1
```

## Exporting credentials

Export writes all decrypted credentials to a new plaintext JSON file. The destination must
not already exist; on Unix it is created with owner-only permissions (`0600`). Treat the
file as a plaintext backup containing every secret and store or remove it accordingly.

```sh
pwd_manager export \
  --input ./data/output/vault.redb \
  --output ./data/output/credentials-export.json
```

The export command prompts for the master passphrase. Use `--master-passphrase-file PATH`
for non-interactive use, with the same precautions as other passphrase files. This plaintext
export is not an input to the legacy-only `import` command.
Run `scripts/export_cred.sh ./data/output/credentials-export.json` for a script example.
The destination must be new; the script refuses to overwrite an existing file.

## Plaintext lifetime

Credential fields are zeroized when their values are dropped, decrypted byte buffers and
temporary serialized output buffers are zeroized when released, and `Debug` output redacts
credential values. This is best-effort memory hygiene, not a guarantee that every copy is
removed: Rust libraries, the allocator, operating system, terminal output, clipboard
services, and explicit plaintext exports can retain or copy data. Avoid `--reveal` unless
you intend to expose secrets in stdout.

## Vault backup, restore, and compaction

Create a backup at a new path with `backup`. The backup contains the encrypted vault, not
the key file or master passphrase:

```sh
pwd_manager backup \
  --input ./data/output/vault.redb \
  --output ./backups/vault-2026-10-20.redb
```

Run backup and restore only when no other process is accessing the vault.

Back up the wrapped key file separately using a trusted, protected location. The vault
backup alone is not recoverable without the matching key file and master passphrase; storing
all of them together removes much of the benefit of encryption. Backups should be stored on
a separate device or otherwise protected from loss of the original.

Restore copies a verified vault backup to a **new** path. It refuses to overwrite an
existing destination:

```sh
pwd_manager restore \
  --input ./backups/vault-2026-10-20.redb \
  --output ./data/output/vault-restored.redb
```

Use the matching key and passphrase with `find` against the restored file to verify it.
After verification, switch to it by stopping other vault users and carefully replacing the
active file yourself, keeping the original and backup until the restored vault is confirmed.

redb is copy-on-write, so the vault file can grow as credentials are changed or deleted.
Compact the vault during a maintenance window, with no other process using it:

```sh
pwd_manager maintenance compact --input ./data/output/vault.redb
```

Compaction preserves records but rewrites the database and may take time. Create a backup
before compacting if the data is important.
The `scripts/demo_vault_maintenance.sh` script demonstrates backup, restore, and compaction
in sequence. It leaves the backup and restored vault in place:

```sh
scripts/demo_vault_maintenance.sh
```

Optionally pass explicit backup and restored-vault paths. Override `VAULT_FILE` to use a
different source vault or `PWD_MANAGER_BIN` to select another CLI executable.

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
