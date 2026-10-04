use std::path::PathBuf;

use pwd_manager::*;
use tempfile::TempDir;

/// Each test gets its own directory so nothing is shared across parallel runs.
fn temp_env() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let key_path = dir.path().join("key.txt");
    let creds_path = dir.path().join("credentials.json");
    (dir, key_path, creds_path)
}

fn sample_credential2() -> Credential {
    Credential {
        account_name: "RustRover".to_string(),
        user_name: "sean_z".to_string(),
        password: "password".to_string(),
        security_questions: vec![
            SecurityQuestion {
                question: "what is your name".to_string(),
                answer: "Sean Z".to_string(),
            },
            SecurityQuestion {
                question: "what do you live".to_string(),
                answer: "Canada".to_string(),
            },
        ],
        sub_credentials: vec![
            SubCredential {
                cred_name: "sub_cred1".to_string(),
                password: "password1".to_string(),
            },
            SubCredential {
                cred_name: "sub_cred2".to_string(),
                password: "password2".to_string(),
            },
        ],
    }
}

fn sample_credential() -> Credential {
    Credential {
        account_name: "RustRover".into(),
        user_name: "sean_z".into(),
        password: "password".into(),
        security_questions: vec![],
        sub_credentials: vec![],
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.decode(s).expect("valid base64")
}

// ---------- key handling ----------

#[test]
fn test_key_is_created_then_reloaded_unchanged() -> MyResult {
    let (_dir, key_path, _) = temp_env();

    let created = load_or_create_key_b64_from(&key_path)?;
    let reloaded = load_or_create_key_b64_from(&key_path)?;
    assert_eq!(created, reloaded, "reloading must yield the same key");

    // A value encrypted under the first handle must decrypt under the second.
    let ciphertext = encrypt_text(&created, b"round trip".as_ref())?;
    assert_eq!(decrypt_text(&reloaded, &ciphertext)?, "round trip");

    Ok(())
}

#[test]
fn test_load_key_b64_from_missing_path_errors() {
    let (_dir, key_path, _) = temp_env();
    assert!(load_key_b64_from(&key_path).is_err());
}

#[test]
fn test_distinct_key_files_produce_distinct_keys() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let (_dir2, key_path2, _) = temp_env();

    let a = load_or_create_key_b64_from(&key_path)?;
    let b = load_or_create_key_b64_from(&key_path2)?;
    assert_ne!(a, b);

    // A ciphertext from one key must not decrypt under the other.
    let ciphertext = encrypt_text(&a, b"secret".as_ref())?;
    assert!(decrypt_text(&b, &ciphertext).is_err());

    Ok(())
}

// ---------- text encryption ----------

#[test]
fn test_encrypt_decrypt_text_round_trip() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let ciphertext = encrypt_text(&key, b"plaintext message2".as_ref())?;
    assert_eq!(decrypt_text(&key, &ciphertext)?, "plaintext message2");

    Ok(())
}

#[test]
fn test_encrypt_text_uses_fresh_nonce() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let a = encrypt_text(&key, b"same message".as_ref())?;
    let b = encrypt_text(&key, b"same message".as_ref())?;

    assert_ne!(
        a, b,
        "identical plaintexts must not produce identical ciphertexts"
    );
    assert_eq!(decrypt_text(&key, &a)?, "same message");
    assert_eq!(decrypt_text(&key, &b)?, "same message");

    Ok(())
}

#[test]
fn test_decrypt_text_rejects_truncated_input() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    // Shorter than the 24-byte nonce prefix.
    let too_short = b64_encode(&[0u8; 8]);
    assert!(decrypt_text(&key, &too_short).is_err());

    Ok(())
}

#[test]
fn test_decrypt_text_rejects_tampered_ciphertext() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let ciphertext = encrypt_text(&key, b"authentic".as_ref())?;
    let mut bytes = b64_decode(&ciphertext);

    // Flip a bit in the tag region; Poly1305 must reject it.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    assert!(decrypt_text(&key, &b64_encode(&bytes)).is_err());

    Ok(())
}

// ---------- credential encryption ----------

#[test]
fn test_encrypt_decrypt_cred_round_trip() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let cred = sample_credential2();
    let enc = encrypt_cred(&key, &cred)?;
    let dec = decrypt_cred(&key, &enc)?;

    assert_eq!(dec.user_name, cred.user_name);
    assert_eq!(dec.password, cred.password);
    assert_eq!(dec.security_questions.len(), cred.security_questions.len());
    assert_eq!(dec.sub_credentials.len(), cred.sub_credentials.len());
    assert_eq!(
        dec.security_questions[0].answer,
        cred.security_questions[0].answer
    );
    assert_eq!(
        dec.sub_credentials[0].password,
        cred.sub_credentials[0].password
    );

    Ok(())
}

#[test]
fn test_encrypt_cred_leaves_labels_in_plaintext() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let cred = sample_credential2();
    let enc = encrypt_cred(&key, &cred)?;

    // Documents current behaviour: values are encrypted, labels are not.
    assert_eq!(enc.account_name, cred.account_name);
    assert_eq!(enc.security_questions[0].question, "what is your name");
    assert_eq!(enc.sub_credentials[0].cred_name, "sub_cred1");
    assert_ne!(enc.user_name, cred.user_name);

    Ok(())
}

// ---------- store: upsert / find / delete ----------

#[test]
fn test_upsert_then_find_round_trip() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let cred = sample_credential2();
    upsert_credential(&creds_path, encrypt_cred(&key, &cred)?)?;

    let found = find_and_decrypt("RustRover", &key_path, &creds_path)?;
    assert_eq!(found.user_name, "sean_z");
    assert_eq!(found.password, "password");

    Ok(())
}

#[test]
fn test_find_is_case_insensitive() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    upsert_credential(&creds_path, encrypt_cred(&key, &sample_credential2())?)?;

    assert!(find_and_decrypt("rustrover", &key_path, &creds_path).is_ok());
    assert!(find_and_decrypt("RUSTROVER", &key_path, &creds_path).is_ok());

    Ok(())
}

#[test]
fn test_upsert_replaces_existing_account() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    upsert_credential(&creds_path, encrypt_cred(&key, &sample_credential2())?)?;

    let mut updated = sample_credential2();
    updated.password = "second-password".to_string();
    upsert_credential(&creds_path, encrypt_cred(&key, &updated)?)?;

    let found = find_and_decrypt("RustRover", &key_path, &creds_path)?;
    assert_eq!(found.password, "second-password");

    Ok(())
}

#[test]
fn test_find_missing_account_errors() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    upsert_credential(&creds_path, encrypt_cred(&key, &sample_credential2())?)?;

    assert!(find_and_decrypt("NoSuchAccount", &key_path, &creds_path).is_err());

    Ok(())
}

#[test]
fn test_delete_credential() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    upsert_credential(&creds_path, encrypt_cred(&key, &sample_credential2())?)?;

    // Case-insensitive, consistent with find.
    delete_credential(&creds_path, "rustrover")?;
    assert!(find_and_decrypt("RustRover", &key_path, &creds_path).is_err());

    // Deleting again must report the miss rather than succeeding silently.
    assert!(delete_credential(&creds_path, "RustRover").is_err());

    Ok(())
}

#[test]
fn test_multiple_accounts_are_independent() -> MyResult {
    let (_dir, key_path, creds_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let mut first = sample_credential();
    first.account_name = "Alpha".into();
    first.password = "alpha-pass".into();
    let mut second = sample_credential();
    second.account_name = "Beta".into();
    second.password = "beta-pass".into();

    upsert_credential(&creds_path, encrypt_cred(&key, &first)?)?;
    upsert_credential(&creds_path, encrypt_cred(&key, &second)?)?;

    assert_eq!(
        find_and_decrypt("Alpha", &key_path, &creds_path)?.password,
        "alpha-pass"
    );
    assert_eq!(
        find_and_decrypt("Beta", &key_path, &creds_path)?.password,
        "beta-pass"
    );

    delete_credential(&creds_path, "Alpha")?;
    assert!(find_and_decrypt("Beta", &key_path, &creds_path).is_ok());

    Ok(())
}
