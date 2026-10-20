//! Single-file key/value store for encrypted credential documents.
//!
//! Each credential is stored as one opaque encrypted blob keyed by its
//! normalized account name. redb provides the single-file, no-sidecar,
//! transactional storage; the opacity comes from `encrypt_credential` /
//! `decrypt_credential` in [`crate`].

use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::{UpstreamError, ensure_owner_only};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("credentials");

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
