use std::path::PathBuf;
use std::process::Command;

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
    let tampered = contents.replace("\"memory_kib\":19456", "\"memory_kib\":19457");
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
    assert_eq!(found.user_name, "sean_z");
    assert_eq!(found.password, "password");

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
    updated.password = "second-password".to_string();
    upsert_credential(&vault_path, &key, &updated)?;

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.password, "second-password");

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
        c.password = "rotated".to_string();
        Ok(())
    })?;

    let found = find_and_decrypt("RustRover", &key, &vault_path)?;
    assert_eq!(found.password, "rotated");
    assert_eq!(found.user_name, "sean_z"); // untouched field survives
    assert_eq!(found.security_questions.len(), 2); // untouched field survives

    Ok(())
}

#[test]
fn test_update_missing_account_errors() -> MyResult {
    let (_dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;

    let result = update_credential(&vault_path, &key, "NoSuchAccount", |c| {
        c.password = "x".to_string();
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
    first.account_name = "Alpha".into();
    first.password = "alpha-pass".into();
    let mut second = sample_credential();
    second.account_name = "Beta".into();
    second.password = "beta-pass".into();

    upsert_credential(&vault_path, &key, &first)?;
    upsert_credential(&vault_path, &key, &second)?;

    assert_eq!(
        find_and_decrypt("Alpha", &key, &vault_path)?.password,
        "alpha-pass"
    );
    assert_eq!(
        find_and_decrypt("Beta", &key, &vault_path)?.password,
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
    first.account_name = "Alpha".into();
    let mut second = sample_credential();
    second.account_name = "Beta".into();
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
        account_name: "RustRover".to_string(),
        user_name: encrypt_text(&key, b"sean_z")?,
        password: encrypt_text(&key, b"password")?,
        security_questions: vec![SecurityQuestion {
            question: "what is your name".to_string(),
            answer: encrypt_text(&key, b"Sean Z")?,
        }],
        sub_credentials: vec![SubCredential {
            cred_name: "sub_cred1".to_string(),
            password: encrypt_text(&key, b"password1")?,
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
    assert_eq!(found.user_name, "sean_z");
    assert_eq!(found.password, "password");
    assert_eq!(found.security_questions[0].answer, "Sean Z");
    assert_eq!(found.sub_credentials[0].password, "password1");

    Ok(())
}

#[test]
fn test_find_redacts_secrets_unless_reveal_is_requested() -> MyResult {
    let (dir, key_path, vault_path) = temp_env();
    let key = load_or_create_key_b64_from(&key_path)?;
    let passphrase_file = tempfile::NamedTempFile::new_in(dir.path())?;
    std::fs::write(passphrase_file.path(), TEST_MASTER_PASSPHRASE)?;
    let mut credential = sample_credential2();
    credential.password = "main-pass-S3cr3t".to_string();
    credential.security_questions[0].answer = "answer-one-S3cr3t".to_string();
    credential.security_questions[1].answer = "answer-two-S3cr3t".to_string();
    credential.sub_credentials[0].password = "sub-one-S3cr3t".to_string();
    credential.sub_credentials[1].password = "sub-two-S3cr3t".to_string();
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
