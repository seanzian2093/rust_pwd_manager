// #![allow(unused)]
pub mod cli;

use std::{
    fmt,
    io::{self, ErrorKind},
    fs::{self, OpenOptions},
    path::Path,
    // for .mode(0o600)
    os::unix::fs::OpenOptionsExt,
};
use serde::{Deserialize, Serialize};

pub type MyResult = Result<(), UpstreamError>;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305,
    Key,
    XNonce,
};

use base64::{engine::general_purpose, Engine as _};

const KEY_BIN_PATH: &str = "data/input/key.bin";
const KEY_TXT_PATH: &str = "data/input/key.txt";
const NONCE_TXT_PATH: &str = "data/input/nonce.txt";

#[derive(Debug)]
pub enum UpstreamError {
    Encryption(chacha20poly1305::Error),
    IO(io::Error),
    Other(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for UpstreamError { }

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
    pub sub_credentials: Vec<SubCredential>
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

pub fn load_or_create_key() -> Result<Key, UpstreamError> {
    if Path::new(KEY_BIN_PATH).exists() {
        // Read previously saved key
        let key_bytes = fs::read(KEY_BIN_PATH)?;
        if key_bytes.len() != 32 {
            return Err(UpstreamError::Other(format!(
                "Key in {} has wrong length: {} (expected 32)",
                KEY_BIN_PATH,
                key_bytes.len()
            )));
        }

        let key_ref = Key::try_from_iter(key_bytes)
            .map_err(|e| UpstreamError::Other(format!("{}", e)))?;
        Ok(key_ref)
    } else {
        // Generate a new key once
        let key = XChaCha20Poly1305::generate_key()
            .map_err(|e| UpstreamError::Other(format!("{}", e)))?;

        // Save with restrictive perms on Unix (0600). On non-Unix, fallback to fs::write.
        #[cfg(unix)]
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .create_new(true) // avoid overwriting an existing key
                .write(true)
                .mode(0o600)
                .open(KEY_BIN_PATH)?;
            f.write_all(key.as_slice())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(KEY_BIN_PATH, key.as_slice())?;
        }

        Ok(key)
    }
}

pub fn load_or_create_key_b64() -> Result<Key, UpstreamError> {
    if Path::new(KEY_TXT_PATH).exists() {
        let b64 = fs::read_to_string(KEY_TXT_PATH)?;
        let key_bytes = general_purpose::STANDARD.decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("Base64 decode error: '{}' - {}", KEY_TXT_PATH, e)))?;
        if key_bytes.len() != 32 {
            return Err(UpstreamError::Other(format!(
                "Decoded key: '{}' - length {} != 32",
                KEY_TXT_PATH,
                key_bytes.len()
            )));
        }

        let key_ref = Key::try_from_iter(key_bytes)
            .map_err(|e| UpstreamError::Other(format!("Error when try converting bytes to Key:'{}' - {}", KEY_TXT_PATH, e)))?;
        Ok(key_ref)
    } else {
        let key = XChaCha20Poly1305::generate_key()
            .map_err(|e| UpstreamError::Other(format!("Error when trying to generate new key: {}", e)))?;
        let b64 = general_purpose::STANDARD.encode(key);
        fs::write(KEY_TXT_PATH, b64)?;
        Ok(key)
    }
}

pub fn load_key_b64_from<P: AsRef<Path>>(path: P) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
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
        Err(UpstreamError::Other(format!("{} does not exist", path_ref.display())))
    }
}

pub fn load_or_create_key_b64_from<P: AsRef<Path>>(path: P) -> Result<Key, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
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
        let key = XChaCha20Poly1305::generate_key()
            .map_err(|e| UpstreamError::Other(format!("{}", e)))?;
        let b64 = general_purpose::STANDARD.encode(key);
        if let Some(parent) = path_ref.parent() { fs::create_dir_all(parent)?; }
        fs::write(path_ref, b64)?;
        Ok(key)
    }
}


pub fn load_nonce_b64_from<P: AsRef<Path>>(path: P) -> Result<XNonce, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
        let b64 = fs::read_to_string(path_ref)?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;

        if nonce_bytes.len() != 24 {
            return Err(UpstreamError::Other(format!(
                "Decoded nonce length {} != 24",
                nonce_bytes.len()
            )));
        }

        let nonce = XNonce::try_from_iter(nonce_bytes)
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;
        Ok(nonce)
    } else {
        Err(UpstreamError::Other(format!("{} does not exist", path_ref.display())))
    }
}

pub fn load_or_create_nonce_b64_from<P: AsRef<Path>>(path: P) -> Result<XNonce, UpstreamError> {
    let path_ref = path.as_ref();
    if path_ref.exists() {
        let b64 = fs::read_to_string(path_ref)?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;

        if nonce_bytes.len() != 24 {
            return Err(UpstreamError::Other(format!(
                "Decoded nonce length {} != 24",
                nonce_bytes.len()
            )));
        }

        let nonce = XNonce::try_from_iter(nonce_bytes)
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;
        Ok(nonce)
    } else {
        let nonce = XChaCha20Poly1305::generate_nonce()
            .map_err(|e| UpstreamError::Other(format!("{}", e)))?;
        let b64 = general_purpose::STANDARD.encode(nonce);
        if let Some(parent) = path_ref.parent() { fs::create_dir_all(parent)?; }
        fs::write(path_ref, b64)?;
        Ok(nonce)
    }
}

pub fn load_or_create_nonce_b64() -> Result<XNonce, UpstreamError> {
    if Path::new(NONCE_TXT_PATH).exists() {
        let b64 = fs::read_to_string(NONCE_TXT_PATH)?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;

        if nonce_bytes.len() != 24 {
            return Err(UpstreamError::Other(format!(
                "Decoded nonce length {} != 24",
                nonce_bytes.len()
            )));
        }

        let nonce = XNonce::try_from_iter(nonce_bytes)
            .map_err(|e| UpstreamError::Other(format!("base64 decode error: {}", e)))?;
        Ok(nonce)
    } else {
        let nonce = XChaCha20Poly1305::generate_nonce()
            .map_err(|e| UpstreamError::Other(format!("{}", e)))?;

        let b64 = general_purpose::STANDARD.encode(nonce);
        fs::write(NONCE_TXT_PATH, b64)?;
        Ok(nonce)
    }
}

pub fn encrypt_text(key: &Key, nonce: &XNonce, plaintext: &[u8]) -> Result<String, UpstreamError> {
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    let b64_s= general_purpose::STANDARD.encode(&ciphertext);
    Ok(b64_s)

}

pub fn decrypt_text(key: &Key, nonce: &XNonce, hex_s: &str) -> Result<String, UpstreamError> {
    let ciphertext = general_purpose::STANDARD.decode(hex_s)
        .map_err(|e| UpstreamError::Other(format!("B64 decode error: {}", e)))?;

    let cipher = XChaCha20Poly1305::new(&key);
    let plaintext= cipher.decrypt(&nonce, ciphertext.as_ref())?;
    let plaintext= String::from_utf8(plaintext)
        .map_err(|e| UpstreamError::Other(format!("from_utf8 error: {}", e)))?;

    Ok(plaintext)
}

pub fn encrypt_cred(key: &Key, nonce: &XNonce, cred: &Credential) -> Result<Credential, UpstreamError> {
    let user_name = encrypt_text(key, nonce, cred.user_name.as_bytes())?;
    let password = encrypt_text(key, nonce, cred.password.as_bytes())?;

    let security_questions = cred.security_questions
        .iter()
        .map(|q| encrypt_security_question(&key, &nonce, q).unwrap())
        .collect::<Vec<_>>();

    let sub_credentials= cred.sub_credentials
        .iter()
        .map(|s| encrypt_sub_credential(&key, &nonce, s).unwrap())
        .collect::<Vec<_>>();

    Ok(Credential {
        account_name: cred.account_name.clone(),
        user_name,
        password,
        security_questions,
        sub_credentials
    })
}

pub fn encrypt_security_question(key: &Key, nonce: &XNonce, q: &SecurityQuestion) -> Result<SecurityQuestion, UpstreamError> {
    let answer= encrypt_text(key, nonce, q.answer.as_bytes())?;

    Ok(SecurityQuestion {
        question: q.question.clone(),
        answer,
    })
}

pub fn decrypt_security_question(key: &Key, nonce: &XNonce, q: &SecurityQuestion) -> Result<SecurityQuestion, UpstreamError> {
    let answer= decrypt_text(key, nonce, &q.answer)?;

    Ok(SecurityQuestion {
        question: q.question.clone(),
        answer,
    })
}

pub fn encrypt_sub_credential(key: &Key, nonce: &XNonce, s: &SubCredential) -> Result<SubCredential, UpstreamError> {
    let password= encrypt_text(key, nonce, s.password.as_bytes())?;

    Ok(SubCredential{
        cred_name: s.cred_name.clone(),
        password,
    })
}

pub fn decrypt_sub_credential(key: &Key, nonce: &XNonce, s: &SubCredential) -> Result<SubCredential, UpstreamError> {
    let password= decrypt_text(key, nonce, &s.password)?;

    Ok(SubCredential{
        cred_name: s.cred_name.clone(),
        password,
    })
}

pub fn decrypt_cred(key: &Key, nonce: &XNonce, cred: &Credential) -> Result<Credential, UpstreamError> {

    let user_name = decrypt_text(key, nonce, &cred.user_name)?;
    let password = decrypt_text(key, nonce, &cred.password)?;

    let security_questions = cred.security_questions
        .iter()
        .map(|q| decrypt_security_question(key, &nonce, q))
        .collect::<Result<Vec<_>, _>>()?;

    let sub_credentials= cred.sub_credentials
        .iter()
        .map(|s| decrypt_sub_credential(&key, &nonce, s))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Credential {
        account_name: cred.account_name.clone(),
        user_name,
        password,
        security_questions,
        sub_credentials
    })
}

pub fn read_from_json<P: AsRef<Path>>(path: P) -> Result<Credential, UpstreamError> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let cred: Credential = serde_json::from_reader(reader)
        .map_err(|e| UpstreamError::Other(format!("{}", e)))?;

    Ok(cred)
}

pub fn write_to_json<T: Serialize, P: AsRef<Path>>(obj: T, path: P) -> Result<(), UpstreamError> {
    let parent_path = path.as_ref().parent().expect("Unable to get parent path");
    fs::create_dir_all(parent_path)?;
    let file = fs::File::create(path)?;
    let writer = io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &obj)
        .map_err(|e| UpstreamError::Other(format!("{}", e)))?;

    Ok(())
}

fn read_vec_from_json<P: AsRef<Path>>(path: P) -> Result<Vec<Credential>, UpstreamError> {
    match fs::File::open(&path) {
        Ok(file) => {
            let reader = io::BufReader::new(file);
            let creds: Vec<Credential> = serde_json::from_reader(reader)
                .map_err(|e| UpstreamError::Other(format!("{}", e)))?;
            Ok(creds)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

fn write_vec_to_json<P: AsRef<Path>>(creds: &Vec<Credential>, path: P) -> Result<(), UpstreamError> {
    let parent_path = path.as_ref().parent().expect("Unable to get parent path");
    fs::create_dir_all(parent_path)?;

    // Use restrictive permissions for secrets (Unix only)
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;

    let writer = io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, creds)
        .map_err(|e| UpstreamError::Other(format!("{}", e)))?;

    Ok(())
}

pub fn append_credential<P: AsRef<Path>>(path: P, new_cred: Credential) -> Result<(), UpstreamError> {
    let mut creds = read_vec_from_json(&path)?;

    // case-sensitive
    // if let Some(pos) = creds.iter().position(|c| c.account_name == new_cred.account_name) {

    // case-insensitive
    if let Some(pos) = creds.iter().position(|c| c.account_name.eq_ignore_ascii_case(&new_cred.account_name)) {
        // Replace the existing entry at the same index
        creds[pos] = new_cred;
    } else {
        // No existing entry; append
        creds.push(new_cred);
    }

    write_vec_to_json(&creds, &path)
}

pub fn find_and_decrypt<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
    account: &str,
    key_file_path: P,
    nonce_file_path: R,
    creds_json_path: Q,
) -> Result<Credential, UpstreamError> {
    // Load key and nonce - not create new ones; loaded key and nonce must match
    let key = load_key_b64_from(key_file_path)?;
    let nonce = load_nonce_b64_from(nonce_file_path)?; // uses NONCE_TXT_PATH internally

    let creds = read_vec_from_json(&creds_json_path)?;

    // Find target (case-insensitive, consistent with append_credential)
    let enc = creds
        .iter()
        .find(|c| c.account_name.eq_ignore_ascii_case(account))
        .ok_or_else(|| UpstreamError::Other(format!(
            "No credential found for account: {}",
            account
        )))?;

    decrypt_cred(&key, &nonce, enc)
}
