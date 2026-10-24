use std::path::PathBuf;
use std::process::Command;

use proptest::prelude::*;
use pwd_manager::*;
use tempfile::TempDir;

const TEST_MASTER_PASSPHRASE: &str = "test-only master passphrase";

/// Each test gets its own directory so nothing is shared across parallel runs.
fn temp_env() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let key_path = dir.path().join("key.txt");
    let vault_path = dir.path().join("vault.redb");
    (dir, key_path, vault_path)
}

fn load_or_create_key_b64_from(
    path: impl AsRef<std::path::Path>,
) -> Result<chacha20poly1305::Key, UpstreamError> {
    load_or_create_key(path, TEST_MASTER_PASSPHRASE)
}

fn load_key_b64_from(
    path: impl AsRef<std::path::Path>,
) -> Result<chacha20poly1305::Key, UpstreamError> {
    load_key_from(path, TEST_MASTER_PASSPHRASE)
}

fn sample_credential2() -> Credential {
    Credential {
        account_name: "RustRover".to_string().into(),
        user_name: "sean_z".to_string().into(),
        password: "password".to_string().into(),
        security_questions: vec![
            SecurityQuestion {
                question: "what is your name".to_string().into(),
                answer: "Sean Z".to_string().into(),
            },
            SecurityQuestion {
                question: "what do you live".to_string().into(),
                answer: "Canada".to_string().into(),
            },
        ],
        sub_credentials: vec![
            SubCredential {
                cred_name: "sub_cred1".to_string().into(),
                password: "password1".to_string().into(),
            },
            SubCredential {
                cred_name: "sub_cred2".to_string().into(),
                password: "password2".to_string().into(),
            },
        ],
    }
}

fn sample_credential() -> Credential {
    Credential {
        account_name: "RustRover".to_string().into(),
        user_name: "sean_z".to_string().into(),
        password: "password".to_string().into(),
        security_questions: vec![],
        sub_credentials: vec![],
    }
}

#[test]
fn test_credential_debug_redacts_secrets_and_identifiers() {
    let credential = Credential {
        account_name: "visible-account".to_string().into(),
        user_name: "private-username".to_string().into(),
        password: "private-password".to_string().into(),
        security_questions: vec![SecurityQuestion {
            question: "private-question".to_string().into(),
            answer: "private-answer".to_string().into(),
        }],
        sub_credentials: vec![SubCredential {
            cred_name: "private-sub-name".to_string().into(),
            password: "private-sub-password".to_string().into(),
        }],
    };

    let debug = format!("{credential:?}");
    assert!(debug.contains("visible-account"));
    for secret in [
        "private-username",
        "private-password",
        "private-question",
        "private-answer",
        "private-sub-name",
        "private-sub-password",
    ] {
        assert!(!debug.contains(secret), "Debug output leaked {secret}");
    }
    assert!(debug.contains("[REDACTED]"));
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.decode(s).expect("valid base64")
}

fn encrypt_legacy_fixed_nonce(
    key: &chacha20poly1305::Key,
    nonce: &chacha20poly1305::XNonce,
    plaintext: &[u8],
) -> String {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    let cipher = XChaCha20Poly1305::new(key);
    b64_encode(
        &cipher
            .encrypt(nonce, plaintext)
            .expect("test encryption succeeds"),
    )
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
    assert_eq!(decrypt_text(&reloaded, &ciphertext)?.as_str(), "round trip");

    Ok(())
}

#[test]
fn test_load_key_b64_from_missing_path_errors() {
    let (_dir, key_path, _) = temp_env();
    assert!(load_key_b64_from(&key_path).is_err());
}

#[test]
fn test_wrapped_key_rejects_wrong_passphrase() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    assert!(load_key_from(&key_path, "incorrect passphrase").is_err());
    assert_eq!(load_key_from(&key_path, TEST_MASTER_PASSPHRASE)?, key);
    Ok(())
}

#[test]
fn test_wrapped_key_rejects_tampered_kdf_parameters() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    load_or_create_test_key(&key_path)?;
    let contents = std::fs::read_to_string(&key_path)?;
    let tampered = if let Some(pos) = contents.find("\"memory_kib\":") {
        let start = pos + "\"memory_kib\":".len();
        let mut bytes = contents.clone().into_bytes();
        if let Some(digit_pos) = bytes[start..].iter().position(|b| b.is_ascii_digit()) {
            let global_pos = start + digit_pos;
            bytes[global_pos] = bytes[global_pos].wrapping_add(1);
            String::from_utf8(bytes).unwrap()
        } else {
            contents.clone()
        }
    } else {
        contents.clone()
    };
    assert_ne!(tampered, contents);
    std::fs::write(&key_path, tampered)?;
    assert!(load_key_from(&key_path, TEST_MASTER_PASSPHRASE).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_wrapped_key_file_is_owner_only() -> MyResult {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, key_path, _) = temp_env();
    load_or_create_test_key(&key_path)?;
    let mode = std::fs::metadata(&key_path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    Ok(())
}

#[test]
fn test_legacy_key_file_is_upgraded_without_changing_data_key() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let legacy_key = [42u8; 32];
    std::fs::write(&key_path, b64_encode(&legacy_key))?;

    let loaded = load_key_from(&key_path, TEST_MASTER_PASSPHRASE)?;
    let expected = chacha20poly1305::Key::try_from_iter(legacy_key)
        .map_err(|e| UpstreamError::Other(e.to_string()))?;
    assert_eq!(loaded, expected);
    assert!(std::fs::read_to_string(&key_path)?.starts_with("PWD_MANAGER_WRAPPED_KEY_V1\n"));
    assert!(!key_file_requires_confirmation(&key_path)?);
    Ok(())
}

fn load_or_create_test_key(
    path: impl AsRef<std::path::Path>,
) -> Result<chacha20poly1305::Key, UpstreamError> {
    load_or_create_key(path, TEST_MASTER_PASSPHRASE)
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
    assert_eq!(
        decrypt_text(&key, &ciphertext)?.as_str(),
        "plaintext message2"
    );

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn property_encrypt_decrypt_text_round_trip(message in any::<String>()) {
        let key = chacha20poly1305::Key::try_from_iter([0x42u8; 32])
            .expect("32-byte test key is valid");
        let encrypted = encrypt_text(&key, message.as_bytes())
            .expect("text encryption succeeds");
        let decrypted = decrypt_text(&key, &encrypted)
            .expect("generated ciphertext decrypts");
        prop_assert_eq!(decrypted.as_str(), message.as_str());
    }
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
    assert_eq!(decrypt_text(&key, &a)?.as_str(), "same message");
    assert_eq!(decrypt_text(&key, &b)?.as_str(), "same message");

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

// ---------- whole-document credential encryption ----------

#[test]
fn test_encrypt_decrypt_credential_round_trip() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let cred = sample_credential2();
    let envelope = encrypt_credential(&key, "rustrover", &cred)?;
    let dec = decrypt_credential(&key, "rustrover", &envelope)?;

    assert_eq!(dec.user_name, cred.user_name);
    assert_eq!(dec.password, cred.password);
    assert_eq!(dec.security_questions.len(), cred.security_questions.len());
    assert_eq!(dec.sub_credentials.len(), cred.sub_credentials.len());
    assert_eq!(
        dec.security_questions[0].question,
        cred.security_questions[0].question
    );
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
fn test_decrypt_credential_rejects_wrong_account_key() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let envelope = encrypt_credential(&key, "github", &sample_credential2())?;

    // A ciphertext moved to a different account must fail authentication,
    // since the account key is bound in as AAD.
    assert!(decrypt_credential(&key, "gitlab", &envelope).is_err());

    Ok(())
}

// ---------- store: upsert / find / delete / list ----------

#[test]
fn test_upsert_then_find_round_trip() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let cred = sample_credential2();
    upsert_credential(&vault_path, &key, &cred)?;

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.user_name.as_str(), "sean_z");
    assert_eq!(found.password.as_str(), "password");

    Ok(())
}

#[test]
fn test_find_is_case_insensitive() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    upsert_credential(&vault_path, &key, &sample_credential2())?;

    assert!(find_and_decrypt("rustrover", &key, &vault_path).is_ok());
    assert!(find_and_decrypt("RUSTROVER", &key, &vault_path).is_ok());

    Ok(())
}

#[test]
fn test_upsert_replaces_existing_account() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    upsert_credential(&vault_path, &key, &sample_credential2())?;

    let mut updated = sample_credential2();
    updated.password = "second-password".to_string().into();
    upsert_credential(&vault_path, &key, &updated)?;

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.password.as_str(), "second-password");

    Ok(())
}

#[test]
fn test_find_missing_account_errors() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    upsert_credential(&vault_path, &key, &sample_credential2())?;

    assert!(find_and_decrypt("NoSuchAccount", &key, &vault_path).is_err());

    Ok(())
}

#[test]
fn test_delete_credential() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    upsert_credential(&vault_path, &key, &sample_credential2())?;

    // Case-insensitive, consistent with find.
    delete_credential(&vault_path, "rustrover")?;
    assert!(find_and_decrypt("RustRover", &key, &vault_path).is_err());

    // Deleting again must report the miss rather than succeeding silently.
    assert!(delete_credential(&vault_path, "RustRover").is_err());

    Ok(())
}

#[test]
fn test_update_credential_changes_only_touched_fields() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    upsert_credential(&vault_path, &key, &sample_credential2())?;

    update_credential(&vault_path, &key, "RustRover", |c| {
        c.password = "rotated".to_string().into();
        Ok(())
    })?;

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.password.as_str(), "rotated");
    assert_eq!(found.user_name.as_str(), "sean_z"); // untouched field survives
    assert_eq!(found.security_questions.len(), 2); // untouched field survives

    Ok(())
}

#[test]
fn test_update_missing_account_errors() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let result = update_credential(&vault_path, &key, "NoSuchAccount", |c| {
        c.password = "x".to_string().into();
        Ok(())
    });
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_multiple_accounts_are_independent() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let mut first = sample_credential();
    first.account_name = "Alpha".to_string().into();
    first.password = "alpha-pass".to_string().into();
    let mut second = sample_credential();
    second.account_name = "Beta".to_string().into();
    second.password = "beta-pass".to_string().into();

    upsert_credential(&vault_path, &key, &first)?;
    upsert_credential(&vault_path, &key, &second)?;

    assert_eq!(
        find_and_decrypt("Alpha", &key, &vault_path)?
            .password
            .as_str(),
        "alpha-pass"
    );
    assert_eq!(
        find_and_decrypt("Beta", &key, &vault_path)?
            .password
            .as_str(),
        "beta-pass"
    );

    delete_credential(&vault_path, "Alpha")?;
    assert!(find_and_decrypt("Beta", &key, &vault_path).is_ok());

    Ok(())
}

#[test]
fn test_list_accounts() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    assert!(list_accounts(&vault_path)?.is_empty());

    let mut first = sample_credential();
    first.account_name = "Alpha".to_string().into();
    let mut second = sample_credential();
    second.account_name = "Beta".to_string().into();
    upsert_credential(&vault_path, &key, &first)?;
    upsert_credential(&vault_path, &key, &second)?;

    let mut accounts = list_accounts(&vault_path)?;
    accounts.sort();
    assert_eq!(accounts, vec!["alpha".to_string(), "beta".to_string()]);

    Ok(())
}

// ---------- import from the legacy per-field JSON store ----------

#[test]
fn test_import_legacy_json() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    // Hand-build a legacy-format JSON store: a map of normalized account name
    // to a Credential whose user_name/password/answers are individually
    // encrypted text envelopes, matching what the old per-field code wrote.
    let legacy_cred = Credential {
        account_name: "RustRover".to_string().into(),
        user_name: encrypt_text(&key, b"sean_z")?.into(),
        password: encrypt_text(&key, b"password")?.into(),
        security_questions: vec![SecurityQuestion {
            question: "what is your name".to_string().into(),
            answer: encrypt_text(&key, b"Sean Z")?.into(),
        }],
        sub_credentials: vec![SubCredential {
            cred_name: "sub_cred1".to_string().into(),
            password: encrypt_text(&key, b"password1")?.into(),
        }],
    };
    let mut legacy_map = std::collections::BTreeMap::new();
    legacy_map.insert("rustrover".to_string(), legacy_cred);

    let legacy_path = _dir.path().join("legacy.json");
    let file = std::fs::File::create(&legacy_path)?;
    serde_json::to_writer_pretty(file, &legacy_map)
        .map_err(|e| pwd_manager::UpstreamError::Other(e.to_string()))?;

    let imported = import_legacy_json(&legacy_path, &key, &vault_path)?;
    assert_eq!(imported, 1);

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.user_name.as_str(), "sean_z");
    assert_eq!(found.password.as_str(), "password");
    assert_eq!(found.security_questions[0].answer.as_str(), "Sean Z");
    assert_eq!(found.sub_credentials[0].password.as_str(), "password1");

    Ok(())
}

#[test]
fn test_import_legacy_json_with_shared_nonce_via_cli() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key_bytes = [42u8; 32];
    std::fs::write(&key_path, b64_encode(&key_bytes))?;
    let key = chacha20poly1305::Key::try_from_iter(key_bytes)
        .map_err(|e| UpstreamError::Other(e.to_string()))?;
    let nonce_bytes = [17u8; 24];
    let nonce = chacha20poly1305::XNonce::try_from_iter(nonce_bytes)
        .map_err(|e| UpstreamError::Other(e.to_string()))?;

    let legacy_credential = Credential {
        account_name: "LegacyAccount".to_string().into(),
        user_name: encrypt_legacy_fixed_nonce(&key, &nonce, b"legacy-user").into(),
        password: encrypt_legacy_fixed_nonce(&key, &nonce, b"legacy-password").into(),
        security_questions: vec![SecurityQuestion {
            question: "First school?".to_string().into(),
            answer: encrypt_legacy_fixed_nonce(&key, &nonce, b"legacy-answer").into(),
        }],
        sub_credentials: vec![SubCredential {
            cred_name: "mail".to_string().into(),
            password: encrypt_legacy_fixed_nonce(&key, &nonce, b"legacy-mail-password").into(),
        }],
    };
    let legacy_json = dir.path().join("legacy.json");
    let legacy_map =
        std::collections::BTreeMap::from([("legacyaccount".to_string(), legacy_credential)]);
    std::fs::write(&legacy_json, serde_json::to_vec(&legacy_map).unwrap())?;

    let nonce_file = dir.path().join("legacy_nonce.txt");
    std::fs::write(&nonce_file, b64_encode(&nonce_bytes))?;
    let passphrase_file = dir.path().join("master_passphrase.txt");
    std::fs::write(&passphrase_file, TEST_MASTER_PASSPHRASE)?;

    let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "import",
            "--legacy-input",
            legacy_json.to_str().expect("temporary path is UTF-8"),
            "--legacy-nonce-file",
            nonce_file.to_str().expect("temporary path is UTF-8"),
            "--master-passphrase-file",
            passphrase_file.to_str().expect("temporary path is UTF-8"),
            "--key-file",
            key_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            vault_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "import command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Imported 1 credential"));

    let unlocked_key = load_key_from(&key_path, TEST_MASTER_PASSPHRASE)?;
    let imported = find_and_decrypt("LegacyAccount", &unlocked_key, &vault_path)?;
    assert_eq!(imported.user_name.as_str(), "legacy-user");
    assert_eq!(imported.password.as_str(), "legacy-password");
    assert_eq!(
        imported.security_questions[0].answer.as_str(),
        "legacy-answer"
    );
    assert_eq!(
        imported.sub_credentials[0].password.as_str(),
        "legacy-mail-password"
    );

    Ok(())
}

#[test]
fn test_import_legacy_json_does_not_overwrite_existing_records() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let existing = sample_credential();
    upsert_credential(&vault_path, &key, &existing)?;

    let mut legacy_map = std::collections::BTreeMap::new();
    for name in ["RustRover", "NewAccount"] {
        let mut credential = sample_credential();
        credential.account_name = name.to_string().into();
        credential.user_name = encrypt_text(&key, b"legacy-user")?.into();
        credential.password = encrypt_text(&key, b"legacy-password")?.into();
        legacy_map.insert(name.to_ascii_lowercase(), credential);
    }
    let legacy_path = _dir.path().join("legacy.json");
    std::fs::write(&legacy_path, serde_json::to_vec(&legacy_map).unwrap())?;

    assert!(import_legacy_json(&legacy_path, &key, &vault_path).is_err());
    assert_eq!(
        find_and_decrypt("RustRover", &key, &vault_path)?.password,
        existing.password
    );
    assert!(find_and_decrypt("NewAccount", &key, &vault_path).is_err());

    Ok(())
}

#[test]
fn test_import_legacy_json_missing_file_errors() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let missing = _dir.path().join("missing.json");
    assert!(import_legacy_json(&missing, &key, &vault_path).is_err());
    assert!(!vault_path.exists());
    Ok(())
}

#[test]
fn test_import_legacy_json_malformed_input_does_not_create_vault() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let legacy_path = _dir.path().join("legacy.json");
    std::fs::write(&legacy_path, "{invalid json")?;

    assert!(import_legacy_json(&legacy_path, &key, &vault_path).is_err());
    assert!(!vault_path.exists());
    Ok(())
}

#[test]
fn test_import_legacy_json_wrong_key_does_not_create_vault() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let mut legacy_credential = sample_credential();
    legacy_credential.user_name = encrypt_text(&key, b"legacy-user")?.into();
    legacy_credential.password = encrypt_text(&key, b"legacy-password")?.into();
    let legacy_map =
        std::collections::BTreeMap::from([("rustrover".to_string(), legacy_credential)]);
    let legacy_path = _dir.path().join("legacy.json");
    std::fs::write(&legacy_path, serde_json::to_vec(&legacy_map).unwrap())?;

    let wrong_key_path = _dir.path().join("wrong-key.txt");
    let wrong_key = load_or_create_key_b64_from(&wrong_key_path)?;
    assert!(import_legacy_json(&legacy_path, &wrong_key, &vault_path).is_err());
    assert!(!vault_path.exists());
    Ok(())
}

#[test]
fn test_import_legacy_json_rejects_same_input_and_output() -> MyResult {
    let (_dir, key_path, _) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let legacy_path = _dir.path().join("legacy.json");
    std::fs::write(&legacy_path, "{}")?;

    assert!(import_legacy_json(&legacy_path, &key, &legacy_path).is_err());
    assert_eq!(std::fs::read_to_string(&legacy_path)?, "{}");
    Ok(())
}

#[test]
fn test_find_redacts_secrets_unless_reveal_is_requested() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let passphrase_file = tempfile::NamedTempFile::new_in(dir.path())?;
    std::fs::write(passphrase_file.path(), TEST_MASTER_PASSPHRASE)?;
    let mut credential = sample_credential2();
    credential.password = "main-pass-S3cr3t".to_string().into();
    credential.security_questions[0].answer = "answer-one-S3cr3t".to_string().into();
    credential.security_questions[1].answer = "answer-two-S3cr3t".to_string().into();
    credential.sub_credentials[0].password = "sub-one-S3cr3t".to_string().into();
    credential.sub_credentials[1].password = "sub-two-S3cr3t".to_string().into();
    upsert_credential(&vault_path, &key, &credential)?;

    let secrets = [
        "main-pass-S3cr3t",
        "answer-one-S3cr3t",
        "answer-two-S3cr3t",
        "sub-one-S3cr3t",
        "sub-two-S3cr3t",
    ];

    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pwd_manager"));
        command.args([
            "find",
            "RustRover",
            "--key-file",
            key_path.to_str().expect("temporary path is UTF-8"),
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--master-passphrase-file",
            passphrase_file
                .path()
                .to_str()
                .expect("temporary path is UTF-8"),
        ]);
        if json {
            command.arg("--json");
        }

        let output = command.output()?;
        assert!(output.status.success());
        let stdout =
            String::from_utf8(output.stdout).map_err(|e| UpstreamError::Other(e.to_string()))?;
        for secret in secrets {
            assert!(
                !stdout.contains(secret),
                "default find output leaked {secret:?}: {stdout}"
            );
        }
        assert!(stdout.contains("******"));

        let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
            .args([
                "find",
                "RustRover",
                "--key-file",
                key_path.to_str().expect("temporary path is UTF-8"),
                "--input",
                vault_path.to_str().expect("temporary path is UTF-8"),
                "--reveal",
                "--master-passphrase-file",
                passphrase_file
                    .path()
                    .to_str()
                    .expect("temporary path is UTF-8"),
            ])
            .args(if json { vec!["--json"] } else { vec![] })
            .output()?;
        assert!(output.status.success());
        let stdout =
            String::from_utf8(output.stdout).map_err(|e| UpstreamError::Other(e.to_string()))?;
        for secret in secrets {
            assert!(
                stdout.contains(secret),
                "--reveal output omitted {secret:?}: {stdout}"
            );
        }
    }

    Ok(())
}

#[test]
fn test_cli_help_with_assert_cmd() {
    let output = assert_cmd::Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let help = String::from_utf8(output).expect("CLI help is valid UTF-8");
    assert!(help.contains("backup"));
    assert!(help.contains("maintenance"));
}

#[test]
fn test_export_cli_writes_owner_only_json_without_overwriting() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let passphrase_file = dir.path().join("master_passphrase.txt");
    std::fs::write(&passphrase_file, TEST_MASTER_PASSPHRASE)?;

    let mut credential = sample_credential2();
    credential.password = "exported-main-secret".to_string().into();
    credential.security_questions[0].answer = "exported-answer-secret".to_string().into();
    upsert_credential(&vault_path, &key, &credential)?;

    let export_path = dir.path().join("export.json");
    let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "export",
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            export_path.to_str().expect("temporary path is UTF-8"),
            "--key-file",
            key_path.to_str().expect("temporary path is UTF-8"),
            "--master-passphrase-file",
            passphrase_file.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "export command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exported 1 credential"));
    assert!(!stdout.contains("exported-main-secret"));
    assert!(!stdout.contains("exported-answer-secret"));

    let exported: std::collections::BTreeMap<String, Credential> =
        serde_json::from_slice(&std::fs::read(&export_path)?)
            .map_err(|e| UpstreamError::Other(e.to_string()))?;
    assert_eq!(
        exported["rustrover"].password.as_str(),
        "exported-main-secret"
    );
    assert_eq!(
        exported["rustrover"].security_questions[0].answer.as_str(),
        "exported-answer-secret"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&export_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let original_export = std::fs::read(&export_path)?;
    let second_attempt = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "export",
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            export_path.to_str().expect("temporary path is UTF-8"),
            "--key-file",
            key_path.to_str().expect("temporary path is UTF-8"),
            "--master-passphrase-file",
            passphrase_file.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(!second_attempt.status.success());
    assert_eq!(std::fs::read(&export_path)?, original_export);

    Ok(())
}

#[test]
fn test_export_missing_vault_fails_without_creating_files() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let export_path = vault_path.with_file_name("export.json");

    assert!(export_credentials(&vault_path, &key, &export_path).is_err());
    assert!(!vault_path.exists());
    assert!(!export_path.exists());
    Ok(())
}

#[test]
fn test_find_clipboard_selection_rejects_invalid_indices() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let passphrase_file = dir.path().join("master_passphrase.txt");
    std::fs::write(&passphrase_file, TEST_MASTER_PASSPHRASE)?;
    upsert_credential(&vault_path, &key, &sample_credential2())?;

    for (flag, index) in [("--copy-answer", "0"), ("--copy-sub-password", "3")] {
        let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
            .args([
                "find",
                "RustRover",
                flag,
                index,
                "--key-file",
                key_path.to_str().expect("temporary path is UTF-8"),
                "--input",
                vault_path.to_str().expect("temporary path is UTF-8"),
                "--master-passphrase-file",
                passphrase_file.to_str().expect("temporary path is UTF-8"),
            ])
            .output()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("out of range"),
            "unexpected error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_find_copies_only_selected_secret_to_clipboard() -> MyResult {
    use std::os::unix::fs::PermissionsExt;

    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let passphrase_file = dir.path().join("master_passphrase.txt");
    std::fs::write(&passphrase_file, TEST_MASTER_PASSPHRASE)?;

    let secret = "clipboard-only-secret";
    let mut credential = sample_credential2();
    credential.password = secret.to_string().into();
    upsert_credential(&vault_path, &key, &credential)?;

    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir)?;
    let fake_pbcopy = bin_dir.join("pbcopy");
    std::fs::write(
        &fake_pbcopy,
        "#!/bin/sh\ncat > \"$PWD_MANAGER_CLIPBOARD_CAPTURE\"\n",
    )?;
    std::fs::set_permissions(&fake_pbcopy, std::fs::Permissions::from_mode(0o700))?;

    let capture_path = dir.path().join("clipboard.txt");
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin_dir)
        .chain(std::env::split_paths(&old_path))
        .collect::<Vec<_>>();
    let path = std::env::join_paths(paths)
        .map_err(|e| UpstreamError::Other(format!("Invalid test PATH: {}", e)))?;

    let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "find",
            "RustRover",
            "--copy-password",
            "--key-file",
            key_path.to_str().expect("temporary path is UTF-8"),
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--master-passphrase-file",
            passphrase_file.to_str().expect("temporary path is UTF-8"),
        ])
        .env("PATH", path)
        .env("PWD_MANAGER_CLIPBOARD_CAPTURE", &capture_path)
        .output()?;
    assert!(
        output.status.success(),
        "clipboard command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Copied account password to clipboard."));
    assert!(!stdout.contains(secret));
    assert_eq!(std::fs::read_to_string(capture_path)?, secret);
    Ok(())
}

#[test]
fn test_backup_and_restore_cli_preserve_vault_and_reject_overwrite() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let mut credential = sample_credential2();
    credential.password = "backup-round-trip-secret".to_string().into();
    upsert_credential(&vault_path, &key, &credential)?;

    let backup_path = dir.path().join("backups/vault.redb");
    let backup = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "backup",
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            backup_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(
        backup.status.success(),
        "backup command failed: {}",
        String::from_utf8_lossy(&backup.stderr)
    );
    assert_eq!(
        find_and_decrypt("RustRover", &key, &backup_path)?
            .password
            .as_str(),
        "backup-round-trip-secret"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let restored_path = dir.path().join("restored.redb");
    let restore = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "restore",
            "--input",
            backup_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            restored_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(
        restore.status.success(),
        "restore command failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&restored_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(
        find_and_decrypt("RustRover", &key, &restored_path)?
            .password
            .as_str(),
        "backup-round-trip-secret"
    );

    let overwrite = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "backup",
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            backup_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(!overwrite.status.success());
    assert_eq!(
        find_and_decrypt("RustRover", &key, &backup_path)?
            .password
            .as_str(),
        "backup-round-trip-secret"
    );

    let restore_overwrite = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "restore",
            "--input",
            backup_path.to_str().expect("temporary path is UTF-8"),
            "--output",
            restored_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(!restore_overwrite.status.success());
    assert_eq!(
        find_and_decrypt("RustRover", &key, &restored_path)?
            .password
            .as_str(),
        "backup-round-trip-secret"
    );
    Ok(())
}

#[test]
fn test_backup_rejects_non_vault_source_without_creating_destination() -> MyResult {
    let (dir, _, _) = temp_env();
    let source = dir.path().join("not-a-vault.redb");
    let destination = dir.path().join("backup.redb");
    std::fs::write(&source, b"not a redb database")?;

    let output = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "backup",
            "--input",
            source.to_str().expect("temporary path is UTF-8"),
            "--output",
            destination.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn test_compact_cli_preserves_vault_records() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_test_key(&key_path)?;
    let original = sample_credential2();
    upsert_credential(&vault_path, &key, &original)?;

    let compact = Command::new(env!("CARGO_BIN_EXE_pwd_manager"))
        .args([
            "maintenance",
            "compact",
            "--input",
            vault_path.to_str().expect("temporary path is UTF-8"),
        ])
        .output()?;
    assert!(
        compact.status.success(),
        "compact command failed: {}",
        String::from_utf8_lossy(&compact.stderr)
    );
    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.user_name, original.user_name);
    assert_eq!(found.password, original.password);
    assert_eq!(
        found.security_questions.len(),
        original.security_questions.len()
    );
    assert_eq!(found.sub_credentials.len(), original.sub_credentials.len());
    Ok(())
}
