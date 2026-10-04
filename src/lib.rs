// #![allow(unused)]
pub mod cli;
pub mod secret_input;

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::{self, ErrorKind},
    // for .mode(0o600)
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub type MyResult = Result<(), UpstreamError>;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};

use base64::{Engine as _, engine::general_purpose};

/// XChaCha20-Poly1305 nonce size; prefixed to every ciphertext.
const NONCE_LEN: usize = 24;

#[derive(Debug)]
pub enum UpstreamError {
    Encryption(chacha20poly1305::Error),
    IO(io::Error),
    Other(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Encryption(_) => {
                write!(f, "decryption failed: wrong key or corrupted data")
            }
            UpstreamError::IO(e) => write!(f, "{}", e),
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

pub fn load_key_b64_from<P: AsRef<Path>>(path: P) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
        ensure_owner_only(path_ref)?;
        let b64 = fs::read_to_string(path_ref)?;
        let key_bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("Base64 decode error: {}", e)))?;
        if key_bytes.len() != 32 {
            return Err(UpstreamError::Other(format!(
                "Decoded key length {} != 32",
                key_bytes.len()
            )));
        }
        let key_ref = Key::try_from_iter(key_bytes)
            .map_err(|e| UpstreamError::Other(format!("Key::try_from_iter error: {}", e)))?;
        Ok(key_ref)
    } else {
        Err(UpstreamError::Other(format!(
            "{} does not exist",
            path_ref.display()
        )))
    }
}

pub fn load_or_create_key_b64_from<P: AsRef<Path>>(path: P) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
        ensure_owner_only(path_ref)?;
        let b64 = fs::read_to_string(path_ref)?;
        let key_bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("Base64 decode error: {}", e)))?;
        if key_bytes.len() != 32 {
            return Err(UpstreamError::Other(format!(
                "Decoded key length {} != 32",
                key_bytes.len()
            )));
        }
        let key_ref = Key::try_from_iter(key_bytes)
            .map_err(|e| UpstreamError::Other(format!("Key::try_from_iter error: {}", e)))?;
        Ok(key_ref)
    } else {
        let key = Key::try_generate().map_err(|e| UpstreamError::Other(format!("{}", e)))?;
        let b64 = general_purpose::STANDARD.encode(key);
        write_new_secret_file(path_ref, b64.as_bytes())?;
        Ok(key)
    }
}

/// Encrypts under a freshly generated nonce, returning base64 of `nonce || ciphertext || tag`.
pub fn encrypt_text(key: &Key, plaintext: &[u8]) -> Result<String, UpstreamError> {
    let nonce = XNonce::try_generate()
        .map_err(|e| UpstreamError::Other(format!("Nonce generation error: {}", e)))?;

    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(nonce.as_slice());
    envelope.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(&envelope))
}

pub fn decrypt_text(key: &Key, b64_s: &str) -> Result<String, UpstreamError> {
    let envelope = general_purpose::STANDARD
        .decode(b64_s)
        .map_err(|e| UpstreamError::Other(format!("B64 decode error: {}", e)))?;

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
    let plaintext = cipher.decrypt(&nonce, ciphertext)?;
    let plaintext = String::from_utf8(plaintext)
        .map_err(|e| UpstreamError::Other(format!("from_utf8 error: {}", e)))?;

    Ok(plaintext)
}

pub fn encrypt_cred(key: &Key, cred: &Credential) -> Result<Credential, UpstreamError> {
    let user_name = encrypt_text(key, cred.user_name.as_bytes())?;
    let password = encrypt_text(key, cred.password.as_bytes())?;

    let security_questions = cred
        .security_questions
        .iter()
        .map(|q| encrypt_security_question(key, q))
        .collect::<Result<Vec<_>, _>>()?;

    let sub_credentials = cred
        .sub_credentials
        .iter()
        .map(|s| encrypt_sub_credential(key, s))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Credential {
        account_name: cred.account_name.clone(),
        user_name,
        password,
        security_questions,
        sub_credentials,
    })
}

pub fn encrypt_security_question(
    key: &Key,
    q: &SecurityQuestion,
) -> Result<SecurityQuestion, UpstreamError> {
    let answer = encrypt_text(key, q.answer.as_bytes())?;

    Ok(SecurityQuestion {
        question: q.question.clone(),
        answer,
    })
}

pub fn decrypt_security_question(
    key: &Key,
    q: &SecurityQuestion,
) -> Result<SecurityQuestion, UpstreamError> {
    let answer = decrypt_text(key, &q.answer)?;

    Ok(SecurityQuestion {
        question: q.question.clone(),
        answer,
    })
}

pub fn encrypt_sub_credential(
    key: &Key,
    s: &SubCredential,
) -> Result<SubCredential, UpstreamError> {
    let password = encrypt_text(key, s.password.as_bytes())?;

    Ok(SubCredential {
        cred_name: s.cred_name.clone(),
        password,
    })
}

pub fn decrypt_sub_credential(
    key: &Key,
    s: &SubCredential,
) -> Result<SubCredential, UpstreamError> {
    let password = decrypt_text(key, &s.password)?;

    Ok(SubCredential {
        cred_name: s.cred_name.clone(),
        password,
    })
}

pub fn decrypt_cred(key: &Key, cred: &Credential) -> Result<Credential, UpstreamError> {
    let user_name = decrypt_text(key, &cred.user_name)?;
    let password = decrypt_text(key, &cred.password)?;

    let security_questions = cred
        .security_questions
        .iter()
        .map(|q| decrypt_security_question(key, q))
        .collect::<Result<Vec<_>, _>>()?;

    let sub_credentials = cred
        .sub_credentials
        .iter()
        .map(|s| decrypt_sub_credential(key, s))
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

fn read_map_from_json<P: AsRef<Path>>(
    path: P,
) -> Result<BTreeMap<String, Credential>, UpstreamError> {
    match fs::File::open(&path) {
        Ok(file) => {
            let reader = io::BufReader::new(file);
            let map = serde_json::from_reader::<_, BTreeMap<String, Credential>>(reader)
                .map_err(|e| UpstreamError::Other(format!("Error reading from file: {}", e)))?;
            Ok(map)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(err) => Err(err.into()),
    }
}

fn write_map_to_json<P: AsRef<Path>>(
    creds: &BTreeMap<String, Credential>,
    path: P,
) -> Result<(), UpstreamError> {
    if let Some(parent) = path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        // avoid "" on relative file in CWD
        fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;

    // `mode` only applies when creating, so re-assert it for a pre-existing file.
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;

    let writer = io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, creds)
        .map_err(|e| UpstreamError::Other(format!("Error writing to file: {}", e)))?;
    Ok(())
}

// Upsert (add or replace) a credential under its normalized account name key
pub fn upsert_credential<P: AsRef<Path>>(
    path: P,
    new_cred: Credential,
) -> Result<(), UpstreamError> {
    let mut map = read_map_from_json(&path)?;

    // Keep struct.account_name consistent with the key for clarity
    // (If you prefer, you can strip it from the struct entirely.)
    let key = norm_key(&new_cred.account_name);

    map.insert(key, new_cred);
    write_map_to_json(&map, &path)
}

// Delete a credential by account name (case-insensitive)
pub fn delete_credential<P: AsRef<Path>>(path: P, account: &str) -> Result<(), UpstreamError> {
    let mut map = read_map_from_json(&path)?;
    let k = norm_key(account);
    if map.remove(&k).is_some() {
        write_map_to_json(&map, &path)
    } else {
        Err(UpstreamError::Other(format!(
            "No credential found for account: {}",
            account
        )))
    }
}

// Optional: partial update helper if you want field-wise updates
pub fn update_credential<P: AsRef<Path>>(
    path: P,
    account: &str,
    f: impl FnOnce(&mut Credential) -> Result<(), UpstreamError>,
) -> Result<(), UpstreamError> {
    let mut map = read_map_from_json(&path)?;
    let k = norm_key(account);
    let Some(c) = map.get_mut(&k) else {
        return Err(UpstreamError::Other(format!(
            "No credential found for account: {}",
            account
        )));
    };
    f(c)?;
    write_map_to_json(&map, &path)
}

// Map-based find (case-insensitive) + decrypt
pub fn find_and_decrypt<P: AsRef<Path>, Q: AsRef<Path>>(
    account: &str,
    key_file_path: P,
    creds_json_path: Q,
) -> Result<Credential, UpstreamError> {
    let key = load_key_b64_from(key_file_path)?;

    let map = read_map_from_json(&creds_json_path)?;
    let k = norm_key(account);
    let enc = map.get(&k).ok_or_else(|| {
        UpstreamError::Other(format!("No credential found for account: {}", account))
    })?;

    decrypt_cred(&key, enc)
}
