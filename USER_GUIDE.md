# Password Manager User Guide

This guide covers day-to-day use of the `pwd_manager` command-line application. It assumes
you already have a trusted copy of the executable available in your terminal as
`pwd_manager`. Replace example account names and file paths with your own.

## Contents

- [Quick start](#quick-start)
- [Where your data is stored](#where-your-data-is-stored)
- [Master passphrase and key file](#master-passphrase-and-key-file)
- [Adding credentials](#adding-credentials)
- [Finding credentials](#finding-credentials)
- [Updating and deleting credentials](#updating-and-deleting-credentials)
- [Listing accounts](#listing-accounts)
- [Importing a legacy vault](#importing-a-legacy-vault)
- [Exporting credentials](#exporting-credentials)
- [Backing up and restoring](#backing-up-and-restoring)
- [Compacting the vault](#compacting-the-vault)
- [Using the included scripts](#using-the-included-scripts)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)

## Quick start

Run these commands from a terminal where `pwd_manager` is available:

```sh
pwd_manager --help
pwd_manager add example-service --user-name my-login
pwd_manager list
pwd_manager find example-service
```

On the first `add`, the app prompts for the account password and then asks you to choose
and confirm a master passphrase. The master passphrase must be at least 12 characters.
Prompts do not echo passphrase or password input. Store the master passphrase somewhere
safe: forgetting it can make the vault unrecoverable.

`find` redacts secrets by default. Use a clipboard option for routine retrieval; use
`--reveal` only when you specifically want secret values printed to the terminal.

## Where your data is stored

By default, the app uses:

| File | Default path | Contents |
| --- | --- | --- |
| Vault | `data/output/vault.redb` | Encrypted credential records and plaintext account-name keys |
| Key file | `data/input/key.txt` | The data-encryption key wrapped using your master passphrase |

The vault and key are separate. Protect both from loss. The account names used by `list`
are not encrypted, so anyone who can read the vault file may learn which services you use.

Most commands accept `--input` or `--output` to choose another vault path. Commands that
unlock the vault also accept `--key-file`. Use the same vault and matching key file for
every operation on a given vault.

## Master passphrase and key file

The first command that creates a key file asks for a new master passphrase twice. Later
commands that read encrypted records ask for it once. The passphrase is used to derive a
key that unlocks the wrapped data key; it is not stored in the vault or key file.

The app never asks you to pass the master passphrase as a command-line argument. For
automation, `--master-passphrase-file PATH` reads it from a file. That file contains the
passphrase in plaintext. Create and protect it using a trusted editor and restrict access
to your account:

```sh
chmod 600 ./data/input/master_passphrase.txt
```

On Unix-like systems, the app checks secret-file permissions and may tighten a file that is
readable by other users. Prefer the interactive prompt whenever practical. Never put
passphrases or passwords directly in command arguments: they can be recorded in shell
history or visible to other local processes.

Back up the key file separately from the vault. Keep a recoverable copy of your master
passphrase separate as well. A vault backup without the matching key file and passphrase
cannot be unlocked; storing all recovery material together weakens the protection.

Older installations may have a raw base64 key file. The first unlock upgrades it in place
to the wrapped format without changing the data key. Keep a backup of the old key and do
not delete or replace the key file.

## Adding credentials

### Add an account with an interactive password prompt

```sh
pwd_manager add example-service --user-name my-login
```

When you run this in a terminal, the app prompts for the account password without echoing
it. If you provide neither `--password-file` nor `--password-stdin`, password input is
interactive when a terminal is attached and read from standard input when input is piped.

### Add a password from a protected file

Use a file containing the password on one line. The app removes one final newline when it
reads the file:

```sh
pwd_manager add example-service \
  --user-name my-login \
  --password-file ./private/service-password.txt
```

The password file should be private to your user. Do not use `--password-file` together
with `--password-stdin`.

### Add security questions and sub-credentials

These values are read from files rather than command arguments, to avoid exposing secrets
in shell history and process listings.

Security-question file format: one `QUESTION=ANSWER` pair per line. Sub-credential file
format: one `NAME=PASSWORD` pair per line. Blank lines and lines beginning with `#` are
ignored. Protect both files with owner-only permissions and remove them when no longer
needed:

```text
# security-questions.txt
First school?=Example School
Favorite teacher?=Example Answer
```

```text
# sub-credentials.txt
mail=mail-account-password
api=api-token
```

Then add the credential:

```sh
pwd_manager add example-service \
  --user-name my-login \
  --password-file ./private/service-password.txt \
  --sec-file ./private/security-questions.txt \
  --sub-file ./private/sub-credentials.txt
```

The parser splits each entry at the first `=` and trims surrounding whitespace from the
name/question and value. Do not add `--sec` or `--sub` values on the command line.

## Finding credentials

### Safe default output

```sh
pwd_manager find example-service
```

The username and labels are shown, while passwords and answers are redacted. Add
`--json` for JSON output; secrets remain redacted unless `--reveal` is also present.

### Reveal secrets in output

```sh
pwd_manager find example-service --reveal
pwd_manager find example-service --json --reveal
```

Revealed secrets go to standard output. They may remain in terminal scrollback or be
captured by logs, pipes, or redirected files. Avoid this mode on shared terminals and do
not redirect its output to an unprotected file.

### Copy one secret to the clipboard

```sh
pwd_manager find example-service --copy-password
pwd_manager find example-service --copy-answer 1
pwd_manager find example-service --copy-sub-password 1
```

Question and sub-credential indices start at `1`; check the redacted output to identify
the order. Clipboard options are mutually exclusive with each other, `--json`, and
`--reveal`. Clipboard contents may be visible to clipboard managers or other applications,
and this app does not clear the clipboard automatically. Clear it yourself after pasting.

### Use a different vault or key

```sh
pwd_manager find example-service \
  --input ./backups/vault-copy.redb \
  --key-file ./private/key.txt
```

## Updating and deleting credentials

### Update fields

Unspecified fields remain unchanged. For example:

```sh
pwd_manager update example-service --user-name new-login
```

To change the password, use an interactive prompt (or stdin when piped):

```sh
pwd_manager update example-service --set-password
```

Or read it from a protected file:

```sh
pwd_manager update example-service --password-file ./private/new-password.txt
```

To replace security questions or sub-credentials, provide the corresponding files:

```sh
pwd_manager update example-service \
  --sec-file ./private/security-questions.txt \
  --sub-file ./private/sub-credentials.txt
```

The current update behavior replaces each list only when the supplied file contains at
least one entry; an empty file does not clear an existing list. Use the same vault/key
options as for `find` if you are not using the defaults.

### Delete an account

```sh
pwd_manager delete example-service
```

Deletion removes the record from the vault. Because the storage is copy-on-write, deleting
or updating records may not immediately shrink the vault file; see
[Compacting the vault](#compacting-the-vault).

## Listing accounts

```sh
pwd_manager list
```

This prints account names only and does not require the master passphrase. Names are stored
as plaintext keys and normalized to lowercase in the listing. Use `--input PATH` for a
non-default vault.

## Importing a legacy vault

`import` is specifically for the app's older per-field encrypted JSON format; it is not
for JSON files produced by the current `export` command.

For a legacy JSON file where each encrypted field contains its own nonce:

```sh
pwd_manager import \
  --legacy-input ./old-data/credentials.json \
  --key-file ./private/legacy-key.txt \
  --output ./data/output/vault.redb
```

For the oldest legacy format, which used a separate shared nonce file, also provide
`--legacy-nonce-file`:

```sh
pwd_manager import \
  --legacy-input ./old-data/credentials.json \
  --legacy-nonce-file ./old-data/nonce.txt \
  --key-file ./private/legacy-key.txt \
  --output ./data/output/vault.redb
```

The importer uses the legacy data key and encrypts records into the new vault. It refuses
to overwrite accounts already in the destination and writes the import as one batch. If
the old shared nonce is missing, that oldest format cannot be decrypted; a new or guessed
nonce will not work. Back up the legacy JSON, key, and nonce (if applicable) before
importing, then verify accounts with `find`.

## Exporting credentials

Export creates a plaintext JSON file containing **all** credentials. Treat it like an
unencrypted secret backup. The destination is required and must not already exist. On
Unix-like systems, the file is created with owner-only permissions (`0600`):

```sh
pwd_manager export \
  --input ./data/output/vault.redb \
  --output ./private/credentials-export.json
```

Create the `./private` directory first if it does not exist.

The command asks for the master passphrase. Use `--master-passphrase-file PATH` only for
automation and keep that file protected. Store or remove the export securely when you are
finished. The legacy `import` command does not import this plaintext export format.

## Backing up and restoring

Run backup and restore when no other process is accessing the vault. Backups and restored
vaults are encrypted redb files, created at a new destination with owner-only permissions.
Existing destination files are never overwritten.

### Make a backup

```sh
pwd_manager backup \
  --input ./data/output/vault.redb \
  --output ./backups/vault-2026-10-20.redb
```

Store backups somewhere separate from the original device when possible. Back up the
matching key file and preserve the master passphrase separately. A backup is not verified
until you have restored it and confirmed that it unlocks.

### Restore to a new file

```sh
pwd_manager restore \
  --input ./backups/vault-2026-10-20.redb \
  --output ./data/output/vault-restored.redb
```

Verify the restored file using the matching key and passphrase:

```sh
pwd_manager list --input ./data/output/vault-restored.redb
pwd_manager find example-service --input ./data/output/vault-restored.redb
```

Keep the original vault and backup until you have confirmed the restored file. To make it
the active vault, stop other vault users first and update your normal `--input`/`--output`
path or carefully replace the active file yourself. Do not overwrite the only copy.

## Compacting the vault

redb is copy-on-write, so the vault can grow as records are changed or deleted. Compaction
may reclaim unused space:

```sh
pwd_manager maintenance compact --input ./data/output/vault.redb
```

Run compaction when no other process is accessing the vault. It rewrites the database and
may take time. Make a backup first if the data is important. Compaction preserves the
stored records; it does not unlock or decrypt them.

## Using the included scripts

The scripts in `scripts/` are optional examples; they expect to be run as commands from
the repository directory, not sourced into your interactive shell. They default to the
debug executable at `./target/debug/pwd_manager`, the vault at
`./data/output/vault.redb`, and the key at `./data/input/key.txt`.

For scripts that unlock the vault, the default passphrase file is
`./data/input/master_passphrase.txt`. Set `MASTER_PASSPHRASE_FILE` if it is elsewhere.
That file contains the passphrase in plaintext and should be owner-only. The find demo
accepts an account and mode:

```sh
scripts/demo_find_options.sh example-service
scripts/demo_find_options.sh example-service copy-password
scripts/demo_find_options.sh example-service copy-answer 1
scripts/demo_find_options.sh example-service reveal
```

`reveal` prints secrets to stdout. Clipboard modes have the same exposure considerations
as the command-line options.

Export demo:

```sh
mkdir -p ./private
scripts/export_cred.sh ./private/credentials-export.json
```

Backup, restore, and compact demo:

```sh
scripts/demo_vault_maintenance.sh
```

This leaves a backup and restored vault in place and compacts the configured source vault.
Review [Backing up and restoring](#backing-up-and-restoring) and
[Compacting the vault](#compacting-the-vault) before running it. You can pass explicit
backup/restored paths or set `VAULT_FILE` and `PWD_MANAGER_BIN`.

## Command reference

Run `pwd_manager COMMAND --help` for options and defaults. Common options:

| Option | Used by | Purpose |
| --- | --- | --- |
| `--input PATH` | `find`, `list`, `delete`, `update`, `export`, `backup`, `maintenance compact` | Select an existing vault |
| `--output PATH` | `add`, `import`, `export`, `backup`, `restore` | Select a destination vault/file |
| `--key-file PATH` | `add`, `find`, `update`, `import`, `export` | Select the wrapped key file |
| `--master-passphrase-file PATH` | `add`, `find`, `update`, `import`, `export` | Read passphrase from a protected file |
| `--password-file PATH` | `add`, `update` | Read a password from a file |
| `--sec-file PATH` | `add`, `update` | Read security questions and answers |
| `--sub-file PATH` | `add`, `update` | Read sub-credential names and passwords |

`add`, `find`, `update`, and `import` use `--output` as the destination vault for `add`
and `import`, or `--input` as the source vault for `find` and `update`. Export, backup,
and restore require an explicit `--output`. See the examples above and command-specific
help for complete usage.

## Troubleshooting

| Message or symptom | What to check |
| --- | --- |
| Account not found | Check spelling, the selected `--input` vault, and whether an import completed. Account lookup is case-insensitive. |
| Wrong key or corrupted data | Confirm the key file belongs to this vault and that the vault was not damaged. Restore from a known-good backup if needed. |
| Master passphrase rejected | Retry carefully. The passphrase cannot be recovered by the app. If forgotten, restore will not help unless you also have the correct passphrase/key material. |
| Key file does not exist | Find the original key or a separate backup of it. Do not create a new key for an existing vault. |
| Destination already exists | Choose a new path. Export, backup, and restore deliberately refuse to overwrite files. |
| Clipboard utility unavailable | On macOS, check `pbcopy`; on Linux, install/configure `wl-copy`, `xclip`, or `xsel`; on Windows, check `clip`. |
| Vault cannot be opened or compacted | Close other processes using the vault and retry. Do not delete the vault or key file to clear a lock error. |
| Import fails with a missing nonce | The oldest legacy format requires its exact original shared nonce. Search the original machine or backups; it cannot be reconstructed. |

The app cannot recover a forgotten master passphrase or recreate a lost data key. Preserve
separate, tested backups of the encrypted vault and matching key/passphrase recovery
material.
