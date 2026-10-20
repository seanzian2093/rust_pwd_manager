//! Single-file key/value store for encrypted credential documents.
//!
//! Each credential is stored as one opaque encrypted blob keyed by its
//! normalized account name. redb provides the single-file, no-sidecar,
//! transactional storage; the opacity comes from `encrypt_credential` /
//! `decrypt_credential` in [`crate`].

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::{UpstreamError, ensure_owner_only};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("credentials");

fn existing_database(path: &Path) -> Result<Database, UpstreamError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(UpstreamError::Other(format!(
            "Not a valid vault file: {}",
            path.display()
        )));
    }
    ensure_owner_only(path)?;
    Database::open(path).map_err(|e| UpstreamError::Store(e.into()))
}

fn copy_database_to_new_file(source: &Path, destination: &Path) -> Result<(), UpstreamError> {
    let _database = existing_database(source)?;
    if destination.exists() {
        return Err(UpstreamError::Other(format!(
            "Destination already exists: {}",
            destination.display()
        )));
    }
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut source_file = File::open(source)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut destination_file = options.open(destination)?;

    let copy_result =
        io::copy(&mut source_file, &mut destination_file).and_then(|_| destination_file.sync_all());
    if let Err(copy_error) = copy_result {
        drop(destination_file);
        return match fs::remove_file(destination) {
            Ok(()) => Err(UpstreamError::IO(copy_error)),
            Err(cleanup_error) => Err(UpstreamError::Other(format!(
                "Copy failed: {}; could not remove incomplete file {}: {}",
                copy_error,
                destination.display(),
                cleanup_error
            ))),
        };
    }

    Ok(())
}

pub struct Store {
    db: Database,
}

fn open_db_file(path: &Path) -> Result<File, UpstreamError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        ensure_owner_only(path)?;
    }

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    opts.mode(0o600);

    Ok(opts.open(path)?)
}

impl Store {
    /// Opens the vault file, creating it (and its parent directory) if missing.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, UpstreamError> {
        let file = open_db_file(path.as_ref())?;
        let db = Database::builder()
            .create_file(file)
            .map_err(|e| UpstreamError::Store(e.into()))?;
        Ok(Store { db })
    }

    /// Creates an owner-only copy of an existing vault without overwriting files.
    pub fn backup<P: AsRef<Path>, Q: AsRef<Path>>(
        source: P,
        destination: Q,
    ) -> Result<(), UpstreamError> {
        copy_database_to_new_file(source.as_ref(), destination.as_ref())
    }

    /// Restores an owner-only copy of a vault to a new destination.
    pub fn restore<P: AsRef<Path>, Q: AsRef<Path>>(
        source: P,
        destination: Q,
    ) -> Result<(), UpstreamError> {
        copy_database_to_new_file(source.as_ref(), destination.as_ref())
    }

    /// Compacts an existing vault, returning whether redb performed compaction.
    pub fn compact<P: AsRef<Path>>(path: P) -> Result<bool, UpstreamError> {
        let mut database = existing_database(path.as_ref())?;
        database
            .compact()
            .map_err(|e| UpstreamError::Store(e.into()))
    }

    /// Inserts or replaces the envelope for `account_key`.
    pub fn put(&self, account_key: &str, envelope: &[u8]) -> Result<(), UpstreamError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| UpstreamError::Store(e.into()))?;
            table
                .insert(account_key, envelope)
                .map_err(|e| UpstreamError::Store(e.into()))?;
        }
        txn.commit().map_err(|e| UpstreamError::Store(e.into()))?;
        Ok(())
    }

    /// Inserts a batch only if none of its account keys already exist.
    ///
    /// All records commit together, so an import cannot leave a partially
    /// written vault if an account conflicts or a storage operation fails.
    pub fn insert_many(&self, entries: &[(String, Vec<u8>)]) -> Result<(), UpstreamError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| UpstreamError::Store(e.into()))?;

            for (account_key, _) in entries {
                if table
                    .get(account_key.as_str())
                    .map_err(|e| UpstreamError::Store(e.into()))?
                    .is_some()
                {
                    return Err(UpstreamError::Other(format!(
                        "Account already exists in destination vault: {}",
                        account_key
                    )));
                }
            }

            for (account_key, envelope) in entries {
                table
                    .insert(account_key.as_str(), envelope.as_slice())
                    .map_err(|e| UpstreamError::Store(e.into()))?;
            }
        }
        txn.commit().map_err(|e| UpstreamError::Store(e.into()))?;
        Ok(())
    }

    /// Returns the raw envelope bytes for `account_key`, if present.
    pub fn get(&self, account_key: &str) -> Result<Option<Vec<u8>>, UpstreamError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        let table = match txn.open_table(TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(UpstreamError::Store(e.into())),
        };
        let value = table
            .get(account_key)
            .map_err(|e| UpstreamError::Store(e.into()))?;
        Ok(value.map(|guard| guard.value().to_vec()))
    }

    /// Returns every account key and envelope from one read transaction.
    pub fn get_all(&self) -> Result<Vec<(String, Vec<u8>)>, UpstreamError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        let table = match txn.open_table(TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(UpstreamError::Store(e.into())),
        };

        let mut entries = Vec::new();
        for entry in table.iter().map_err(|e| UpstreamError::Store(e.into()))? {
            let (key, value) = entry.map_err(|e| UpstreamError::Store(e.into()))?;
            entries.push((key.value().to_string(), value.value().to_vec()));
        }
        Ok(entries)
    }

    /// Removes `account_key`, returning whether it was present.
    pub fn remove(&self, account_key: &str) -> Result<bool, UpstreamError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        let removed;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| UpstreamError::Store(e.into()))?;
            removed = table
                .remove(account_key)
                .map_err(|e| UpstreamError::Store(e.into()))?
                .is_some();
        }
        txn.commit().map_err(|e| UpstreamError::Store(e.into()))?;
        Ok(removed)
    }

    /// Lists every account key currently stored (plaintext, as discussed - not encrypted).
    pub fn list_keys(&self) -> Result<Vec<String>, UpstreamError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| UpstreamError::Store(e.into()))?;
        let table = match txn.open_table(TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(UpstreamError::Store(e.into())),
        };

        let mut keys = Vec::new();
        for entry in table.iter().map_err(|e| UpstreamError::Store(e.into()))? {
            let (k, _) = entry.map_err(|e| UpstreamError::Store(e.into()))?;
            keys.push(k.value().to_string());
        }
        Ok(keys)
    }
}
