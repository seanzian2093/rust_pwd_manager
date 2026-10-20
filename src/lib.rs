// #![allow(unused)]
pub mod cli;
pub mod secret_input;
pub mod store;

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub type MyResult = Result<(), UpstreamError>;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};

use base64::{Engine as _, engine::general_purpose};
use zeroize::{Zeroize, Zeroizing};

/// XChaCha20-Poly1305 nonce size; prefixed to every ciphertext.
const NONCE_LEN: usize = 24;
const WRAPPED_KEY_MAGIC: &str = "PWD_MANAGER_WRAPPED_KEY_V1\n";
const KEY_FILE_VERSION: u32 = 1;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_SALT_LEN: usize = 16;
const DATA_KEY_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct WrappedKeyHeader {
    format_version: u32,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct WrappedKeyFile {
    header: WrappedKeyHeader,
    wrapped_key: String,
}

#[derive(Debug)]
pub enum UpstreamError {
    Encryption(chacha20poly1305::Error),
    IO(io::Error),
    Store(redb::Error),
    Other(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Encryption(_) => {
                write!(f, "decryption failed: wrong key or corrupted data")
            }
            UpstreamError::IO(e) => write!(f, "{}", e),
            UpstreamError::Store(e) => write!(f, "{}", e),
            UpstreamError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for UpstreamError {}

// We need to get rid of map_err so we need to impl From
impl From<io::Error> for UpstreamError {
    fn from(err: io::Error) -> Self {
        UpstreamError::IO(err)
    }
}

impl From<chacha20poly1305::Error> for UpstreamError {
    fn from(err: chacha20poly1305::Error) -> Self {
        UpstreamError::Encryption(err)
    }
}

impl From<redb::Error> for UpstreamError {
    fn from(err: redb::Error) -> Self {
        UpstreamError::Store(err)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub account_name: String,
    pub user_name: String,
    pub password: String,
    pub security_questions: Vec<SecurityQuestion>,
    pub sub_credentials: Vec<SubCredential>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubCredential {
    pub cred_name: String,
    pub password: String,
}

/// Creates a file holding secret material with owner-only permissions.
///
/// Uses `create_new` so an existing key is never silently overwritten.
fn write_new_secret_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), UpstreamError> {
    use std::io::Write;

    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut f = opts.open(path_ref)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Restricts an existing secret file to owner-only access, warning if it was readable by others.
///
/// Needed because `OpenOptions::mode` applies only at creation, so files written by
/// earlier versions keep their original permissions.
#[cfg(unix)]
pub(crate) fn ensure_owner_only<P: AsRef<Path>>(path: P) -> Result<(), UpstreamError> {
    let path_ref = path.as_ref();
    let perms = fs::metadata(path_ref)?.permissions();

    if perms.mode() & 0o077 != 0 {
        eprintln!(
            "warning: {} was accessible to other users (mode {:o}); tightening to 600",
            path_ref.display(),
            perms.mode() & 0o777
        );
        fs::set_permissions(path_ref, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn ensure_owner_only<P: AsRef<Path>>(_path: P) -> Result<(), UpstreamError> {
    Ok(())
}

fn key_from_bytes(bytes: &[u8]) -> Result<Key, UpstreamError> {
    if bytes.len() != DATA_KEY_LEN {
        return Err(UpstreamError::Other(format!(
            "Decoded key length {} != {}",
            bytes.len(),
            DATA_KEY_LEN
        )));
    }
    Key::try_from_iter(bytes.iter().copied())
        .map_err(|e| UpstreamError::Other(format!("Invalid data key: {}", e)))
}

fn derive_wrapping_key(
    passphrase: &str,
    header: &WrappedKeyHeader,
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>, UpstreamError> {
    if header.format_version != KEY_FILE_VERSION
        || header.kdf != "argon2id"
        || header.memory_kib != ARGON2_MEMORY_KIB
        || header.iterations != ARGON2_ITERATIONS
        || header.parallelism != ARGON2_PARALLELISM
    {
        return Err(UpstreamError::Other(
            "Unsupported wrapped-key format or Argon2 parameters".to_string(),
        ));
    }

    let salt = general_purpose::STANDARD
        .decode(&header.salt)
        .map_err(|e| UpstreamError::Other(format!("Invalid key-file salt: {}", e)))?;
    if salt.len() != ARGON2_SALT_LEN {
        return Err(UpstreamError::Other(format!(
            "Invalid key-file salt length: {}",
            salt.len()
        )));
    }

    let params = argon2::Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DATA_KEY_LEN),
    )
    .map_err(|e| UpstreamError::Other(format!("Invalid Argon2 parameters: {}", e)))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut wrapping_key = Zeroizing::new([0; DATA_KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut *wrapping_key)
        .map_err(|e| UpstreamError::Other(format!("Argon2 key derivation failed: {}", e)))?;
    Ok(wrapping_key)
}

fn new_wrapped_key_file(key: &Key, passphrase: &str) -> Result<Vec<u8>, UpstreamError> {
    if passphrase.chars().count() < 12 {
        return Err(UpstreamError::Other(
            "New master passphrase must be at least 12 characters".to_string(),
        ));
    }
    let random = XNonce::try_generate()
        .map_err(|e| UpstreamError::Other(format!("Salt generation error: {}", e)))?;
    let header = WrappedKeyHeader {
        format_version: KEY_FILE_VERSION,
        kdf: "argon2id".to_string(),
        memory_kib: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
        salt: general_purpose::STANDARD.encode(&random.as_slice()[..ARGON2_SALT_LEN]),
    };

    let wrapping_key = derive_wrapping_key(passphrase, &header)?;
    let aad = serde_json::to_vec(&header)
        .map_err(|e| UpstreamError::Other(format!("Key header serialization failed: {}", e)))?;
    let mut wrapping_key = Key::try_from_iter(wrapping_key.iter().copied())
        .map_err(|e| UpstreamError::Other(format!("Invalid derived wrapping key: {}", e)))?;
    let encrypted = encrypt_envelope(&wrapping_key, &aad, key.as_slice());
    wrapping_key.as_mut_slice().zeroize();
    let wrapped_key = encrypted?;

    let key_file = WrappedKeyFile {
        header,
        wrapped_key: general_purpose::STANDARD.encode(wrapped_key),
    };
    let mut contents = WRAPPED_KEY_MAGIC.as_bytes().to_vec();
    serde_json::to_writer(&mut contents, &key_file)
        .map_err(|e| UpstreamError::Other(format!("Key file serialization failed: {}", e)))?;
    contents.push(b'\n');
    Ok(contents)
}

fn unlock_wrapped_key(contents: &str, passphrase: &str) -> Result<Key, UpstreamError> {
    let payload = contents
        .strip_prefix(WRAPPED_KEY_MAGIC)
        .ok_or_else(|| UpstreamError::Other("Key file is not an Argon2-wrapped key".to_string()))?;
    let key_file: WrappedKeyFile = serde_json::from_str(payload)
        .map_err(|e| UpstreamError::Other(format!("Invalid wrapped-key file: {}", e)))?;
    let wrapping_key = derive_wrapping_key(passphrase, &key_file.header)?;
    let aad = serde_json::to_vec(&key_file.header)
        .map_err(|e| UpstreamError::Other(format!("Key header serialization failed: {}", e)))?;
    let envelope = general_purpose::STANDARD
        .decode(&key_file.wrapped_key)
        .map_err(|e| UpstreamError::Other(format!("Invalid wrapped data key: {}", e)))?;
    let mut wrapping_key = Key::try_from_iter(wrapping_key.iter().copied())
        .map_err(|e| UpstreamError::Other(format!("Invalid derived wrapping key: {}", e)))?;
    let decrypted = decrypt_envelope(&wrapping_key, &aad, &envelope);
    wrapping_key.as_mut_slice().zeroize();
    let data_key = decrypted?;
    key_from_bytes(&data_key)
}

fn replace_secret_file<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<(), UpstreamError> {
    use std::io::Write;

    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(contents)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| UpstreamError::IO(e.error))?;
    Ok(())
}

fn lock_key_file<P: AsRef<Path>>(path: P) -> Result<File, UpstreamError> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let mut lock_path = PathBuf::from(path);
    let mut lock_name = lock_path
        .file_name()
        .ok_or_else(|| UpstreamError::Other("Key file path has no filename".to_string()))?
        .to_os_string();
    lock_name.push(".lock");
    lock_path.set_file_name(lock_name);

    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);

    let lock = options.open(&lock_path)?;
    ensure_owner_only(&lock_path)?;
    lock.lock()?;
    Ok(lock)
}

/// Returns whether using this key path requires first-time passphrase confirmation.
/// Legacy base64 key files are upgraded in place on first successful unlock.
pub fn key_file_requires_confirmation<P: AsRef<Path>>(path: P) -> Result<bool, UpstreamError> {
    let path = path.as_ref();
    let _lock = lock_key_file(path)?;
    if !path.exists() {
        return Ok(true);
    }
    ensure_owner_only(path)?;
    let contents = fs::read_to_string(path)?;
    Ok(!contents.starts_with(WRAPPED_KEY_MAGIC))
}

fn unlock_or_upgrade_key<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    ensure_owner_only(path_ref)?;
    let contents = fs::read_to_string(path_ref)?;
    if contents.starts_with(WRAPPED_KEY_MAGIC) {
        return unlock_wrapped_key(&contents, passphrase);
    }

    let key_bytes = general_purpose::STANDARD
        .decode(contents.trim())
        .map_err(|e| UpstreamError::Other(format!("Invalid legacy key file: {}", e)))?;
    let key = key_from_bytes(&key_bytes)?;
    let wrapped_contents = new_wrapped_key_file(&key, passphrase)?;

    // Do not replace a key file changed by another process while this one was
    // deriving the wrapper. Unlock the winner's file instead.
    if fs::read(path_ref)? != contents.as_bytes() {
        return unlock_or_upgrade_key(path_ref, passphrase);
    }
    replace_secret_file(path_ref, &wrapped_contents)?;
    Ok(key)
}

pub fn load_key_from<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    let _lock = lock_key_file(path_ref)?;
    if path_ref.exists() {
        unlock_or_upgrade_key(path_ref, passphrase)
    } else {
        Err(UpstreamError::Other(format!(
            "{} does not exist",
            path_ref.display()
        )))
    }
}

pub fn load_or_create_key<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    let _lock = lock_key_file(path_ref)?;
    if path_ref.exists() {
        unlock_or_upgrade_key(path_ref, passphrase)
    } else {
        let key = Key::try_generate().map_err(|e| UpstreamError::Other(format!("{}", e)))?;
        let contents = new_wrapped_key_file(&key, passphrase)?;
        match write_new_secret_file(path_ref, &contents) {
            Ok(()) => Ok(key),
            Err(UpstreamError::IO(e)) if e.kind() == ErrorKind::AlreadyExists => {
                unlock_or_upgrade_key(path_ref, passphrase)
            }
            Err(e) => Err(e),
        }
    }
}

/// Encrypts `plaintext` under a freshly generated nonce, binding `aad` into the
/// authentication tag without encrypting it. Returns `nonce || ciphertext || tag`.
fn encrypt_envelope(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    let nonce = XNonce::try_generate()
        .map_err(|e| UpstreamError::Other(format!("Nonce generation error: {}", e)))?;

    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )?;

    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(nonce.as_slice());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Inverse of [`encrypt_envelope`]. `aad` must match what was passed to encrypt,
/// or authentication fails.
fn decrypt_envelope(key: &Key, aad: &[u8], envelope: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    if envelope.len() <= NONCE_LEN {
        return Err(UpstreamError::Other(format!(
            "Ciphertext too short: {} bytes (expected more than {})",
            envelope.len(),
            NONCE_LEN
        )));
    }

    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let nonce = XNonce::try_from_iter(nonce_bytes.iter().copied())
        .map_err(|e| UpstreamError::Other(format!("Invalid nonce prefix: {}", e)))?;

    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext,
            aad,
        },
    )?;
    Ok(plaintext)
}

/// Encrypts under a freshly generated nonce, returning base64 of `nonce || ciphertext || tag`.
pub fn encrypt_text(key: &Key, plaintext: &[u8]) -> Result<String, UpstreamError> {
    let envelope = encrypt_envelope(key, b"", plaintext)?;
    Ok(general_purpose::STANDARD.encode(envelope))
}

pub fn decrypt_text(key: &Key, b64_s: &str) -> Result<String, UpstreamError> {
    let envelope = general_purpose::STANDARD
        .decode(b64_s)
        .map_err(|e| UpstreamError::Other(format!("B64 decode error: {}", e)))?;

    let plaintext = decrypt_envelope(key, b"", &envelope)?;
    let plaintext = String::from_utf8(plaintext)
        .map_err(|e| UpstreamError::Other(format!("from_utf8 error: {}", e)))?;

    Ok(plaintext)
}

/// Encrypts the whole credential as one CBOR document, binding `account_key` as AAD
/// so a ciphertext copied to a different account fails authentication.
pub fn encrypt_credential(
    key: &Key,
    account_key: &str,
    cred: &Credential,
) -> Result<Vec<u8>, UpstreamError> {
    let mut plaintext = Vec::new();
    ciborium::into_writer(cred, &mut plaintext)
        .map_err(|e| UpstreamError::Other(format!("CBOR encode error: {}", e)))?;

    encrypt_envelope(key, account_key.as_bytes(), &plaintext)
}

/// Inverse of [`encrypt_credential`].
pub fn decrypt_credential(
    key: &Key,
    account_key: &str,
    envelope: &[u8],
) -> Result<Credential, UpstreamError> {
    let plaintext = decrypt_envelope(key, account_key.as_bytes(), envelope)?;
    ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| UpstreamError::Other(format!("CBOR decode error: {}", e)))
}

// ---------- legacy per-field format (read-only, used by `import_legacy_json`) ----------

fn legacy_decrypt_text(
    key: &Key,
    ciphertext_b64: &str,
    fixed_nonce: Option<&XNonce>,
) -> Result<String, UpstreamError> {
    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| UpstreamError::Other(format!("Invalid legacy ciphertext: {}", e)))?;

    if ciphertext.len() > NONCE_LEN
        && let Ok(plaintext) = decrypt_envelope(key, b"", &ciphertext)
    {
        return String::from_utf8(plaintext).map_err(|e| {
            UpstreamError::Other(format!("Legacy plaintext is not valid UTF-8: {}", e))
        });
    }

    if let Some(nonce) = fixed_nonce {
        let cipher = XChaCha20Poly1305::new(key);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            UpstreamError::Other(
                "Legacy ciphertext could not be decrypted; check the key and legacy nonce"
                    .to_string(),
            )
        })?;
        return String::from_utf8(plaintext).map_err(|e| {
            UpstreamError::Other(format!("Legacy plaintext is not valid UTF-8: {}", e))
        });
    }

    Err(UpstreamError::Other(
        "Legacy ciphertext could not be decrypted; provide --legacy-nonce-file for an older JSON vault"
            .to_string(),
    ))
}

fn legacy_decrypt_security_question(
    key: &Key,
    q: &SecurityQuestion,
    fixed_nonce: Option<&XNonce>,
) -> Result<SecurityQuestion, UpstreamError> {
    let answer = legacy_decrypt_text(key, &q.answer, fixed_nonce)?;

    Ok(SecurityQuestion {
        question: q.question.clone(),
        answer,
    })
}

fn legacy_decrypt_sub_credential(
    key: &Key,
    s: &SubCredential,
    fixed_nonce: Option<&XNonce>,
) -> Result<SubCredential, UpstreamError> {
    let password = legacy_decrypt_text(key, &s.password, fixed_nonce)?;

    Ok(SubCredential {
        cred_name: s.cred_name.clone(),
        password,
    })
}

/// Decrypts a credential stored in the old per-field JSON format.
fn legacy_decrypt_cred(
    key: &Key,
    cred: &Credential,
    fixed_nonce: Option<&XNonce>,
) -> Result<Credential, UpstreamError> {
    let user_name = legacy_decrypt_text(key, &cred.user_name, fixed_nonce)?;
    let password = legacy_decrypt_text(key, &cred.password, fixed_nonce)?;

    let security_questions = cred
        .security_questions
        .iter()
        .map(|q| legacy_decrypt_security_question(key, q, fixed_nonce))
        .collect::<Result<Vec<_>, _>>()?;

    let sub_credentials = cred
        .sub_credentials
        .iter()
        .map(|s| legacy_decrypt_sub_credential(key, s, fixed_nonce))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Credential {
        account_name: cred.account_name.clone(),
        user_name,
        password,
        security_questions,
        sub_credentials,
    })
}

fn norm_key(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Reads the old per-field-encrypted JSON store. Only used by [`import_legacy_json`].
fn legacy_read_map_from_json<P: AsRef<Path>>(
    path: P,
) -> Result<BTreeMap<String, Credential>, UpstreamError> {
    ensure_owner_only(&path)?;
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    serde_json::from_reader::<_, BTreeMap<String, Credential>>(reader)
        .map_err(|e| UpstreamError::Other(format!("Error reading legacy JSON: {}", e)))
}

// Upsert (add or replace) a credential under its normalized account name key
pub fn upsert_credential<P: AsRef<Path>>(
    vault_path: P,
    key: &Key,
    cred: &Credential,
) -> Result<(), UpstreamError> {
    let account_key = norm_key(&cred.account_name);
    let envelope = encrypt_credential(key, &account_key, cred)?;
    store::Store::open(vault_path)?.put(&account_key, &envelope)
}

// Delete a credential by account name (case-insensitive)
pub fn delete_credential<P: AsRef<Path>>(
    vault_path: P,
    account: &str,
) -> Result<(), UpstreamError> {
    let account_key = norm_key(account);
    if store::Store::open(vault_path)?.remove(&account_key)? {
        Ok(())
    } else {
        Err(UpstreamError::Other(format!(
            "No credential found for account: {}",
            account
        )))
    }
}

// Optional: partial update helper if you want field-wise updates
pub fn update_credential<P: AsRef<Path>>(
    vault_path: P,
    key: &Key,
    account: &str,
    f: impl FnOnce(&mut Credential) -> Result<(), UpstreamError>,
) -> Result<(), UpstreamError> {
    let store = store::Store::open(vault_path)?;
    let account_key = norm_key(account);

    let envelope = store.get(&account_key)?.ok_or_else(|| {
        UpstreamError::Other(format!("No credential found for account: {}", account))
    })?;
    let mut cred = decrypt_credential(key, &account_key, &envelope)?;

    f(&mut cred)?;

    let new_envelope = encrypt_credential(key, &account_key, &cred)?;
    store.put(&account_key, &new_envelope)
}

// Case-insensitive find + decrypt
pub fn find_and_decrypt<P: AsRef<Path>>(
    account: &str,
    key: &Key,
    vault_path: P,
) -> Result<Credential, UpstreamError> {
    let account_key = norm_key(account);
    let envelope = store::Store::open(vault_path)?
        .get(&account_key)?
        .ok_or_else(|| {
            UpstreamError::Other(format!("No credential found for account: {}", account))
        })?;

    decrypt_credential(key, &account_key, &envelope)
}

/// Lists every stored account name's normalized key (plaintext; see `Store::list_keys`).
pub fn list_accounts<P: AsRef<Path>>(vault_path: P) -> Result<Vec<String>, UpstreamError> {
    store::Store::open(vault_path)?.list_keys()
}

/// Exports every credential as plaintext JSON to a new owner-only file.
///
/// Existing destination files are never overwritten. All records are decrypted
/// and serialized before the destination is created.
pub fn export_credentials<P: AsRef<Path>, Q: AsRef<Path>>(
    vault_path: P,
    key: &Key,
    output_path: Q,
) -> Result<usize, UpstreamError> {
    use std::io::Write;

    let vault_path = vault_path.as_ref();
    if !vault_path.exists() {
        return Err(UpstreamError::Other(format!(
            "Vault file does not exist: {}",
            vault_path.display()
        )));
    }

    let entries = store::Store::open(vault_path)?.get_all()?;
    let mut credentials = BTreeMap::new();
    for (account, envelope) in entries {
        let credential = decrypt_credential(key, &account, &envelope)?;
        credentials.insert(account, credential);
    }

    let serialized = serde_json::to_vec_pretty(&credentials)
        .map_err(|e| UpstreamError::Other(format!("Failed to serialize export JSON: {}", e)))?;

    let output_path = output_path.as_ref();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(output_path)?;

    let write_result = file.write_all(&serialized).and_then(|()| file.sync_all());
    if let Err(write_error) = write_result {
        drop(file);
        return match fs::remove_file(output_path) {
            Ok(()) => Err(UpstreamError::IO(write_error)),
            Err(cleanup_error) => Err(UpstreamError::Other(format!(
                "Export failed: {}; could not remove incomplete plaintext file {}: {}",
                write_error,
                output_path.display(),
                cleanup_error
            ))),
        };
    }

    Ok(credentials.len())
}

/// Decrypts every entry in the old per-field JSON store and re-encrypts it as a
/// whole document into the redb vault. Returns the number of credentials imported.
pub fn import_legacy_json<P: AsRef<Path>, Q: AsRef<Path>>(
    legacy_json_path: P,
    key: &Key,
    vault_path: Q,
) -> Result<usize, UpstreamError> {
    import_legacy_json_with_nonce(legacy_json_path, key, None::<&Path>, vault_path)
}

/// Imports an older legacy JSON store whose per-field ciphertexts use a
/// shared, separately stored XChaCha20 nonce.
pub fn import_legacy_json_with_nonce<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
    legacy_json_path: P,
    key: &Key,
    nonce_path: Option<R>,
    vault_path: Q,
) -> Result<usize, UpstreamError> {
    let legacy_path = legacy_json_path.as_ref();
    let vault_path = vault_path.as_ref();
    let legacy_canonical = legacy_path.canonicalize()?;
    if vault_path.exists() && legacy_canonical == vault_path.canonicalize()? {
        return Err(UpstreamError::Other(
            "Legacy JSON input and destination vault must be different files".to_string(),
        ));
    }

    let legacy_map = legacy_read_map_from_json(legacy_json_path)?;
    let fixed_nonce = match nonce_path {
        Some(path) => {
            ensure_owner_only(&path)?;
            let encoded = fs::read_to_string(path)?;
            let bytes = general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|e| UpstreamError::Other(format!("Invalid legacy nonce file: {}", e)))?;
            if bytes.len() != NONCE_LEN {
                return Err(UpstreamError::Other(format!(
                    "Legacy nonce must be {} bytes, got {}",
                    NONCE_LEN,
                    bytes.len()
                )));
            }
            Some(
                XNonce::try_from_iter(bytes)
                    .map_err(|e| UpstreamError::Other(format!("Invalid legacy nonce: {}", e)))?,
            )
        }
        None => None,
    };

    let mut seen = std::collections::BTreeSet::new();
    let mut entries = Vec::with_capacity(legacy_map.len());
    for (account_key, legacy_cred) in legacy_map {
        let normalized_key = norm_key(&legacy_cred.account_name);
        if legacy_cred.account_name.trim().is_empty() || account_key != normalized_key {
            return Err(UpstreamError::Other(format!(
                "Legacy account key {:?} does not match account name {:?}",
                account_key, legacy_cred.account_name
            )));
        }
        if !seen.insert(normalized_key.clone()) {
            return Err(UpstreamError::Other(format!(
                "Multiple legacy records normalize to account key: {}",
                normalized_key
            )));
        }
        let plain = legacy_decrypt_cred(key, &legacy_cred, fixed_nonce.as_ref()).map_err(|e| {
            UpstreamError::Other(format!(
                "Failed to decrypt legacy account '{}': {}",
                normalized_key, e
            ))
        })?;
        let envelope = encrypt_credential(key, &normalized_key, &plain)?;
        entries.push((normalized_key, envelope));
    }

    if entries.is_empty() {
        return Ok(0);
    }

    store::Store::open(vault_path)?.insert_many(&entries)?;
    Ok(entries.len())
}
