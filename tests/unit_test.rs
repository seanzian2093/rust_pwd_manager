use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305
};

use pwd_manager::*;

fn sample_credential2() -> Credential {
    let sub_credential1 = SubCredential {
        cred_name: "sub_cred1".to_string(),
        password: "password1".to_string(),
    };

    let sub_credential2 = SubCredential {
        cred_name: "sub_cred2".to_string(),
        password: "password2".to_string(),
    };

    let sub_credentials = vec![sub_credential1, sub_credential2];

    let security_question1 = SecurityQuestion {
        question: "what is your name".to_string(),
        answer: "Sean Z".to_string(),
    };

    let security_question2 = SecurityQuestion {
        question: "what do you live".to_string(),
        answer: "Canada".to_string(),
    };

    let security_questions = vec![security_question1, security_question2];

    let credential = Credential {
        account_name: "RustRover".to_string(),
        user_name: "sean_z".to_string(),
        password: "password".to_string(),
        security_questions,
        sub_credentials,
    };
    credential
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

#[test]
fn test_load_or_create_key() -> MyResult {
    let key = load_or_create_key()?;

    let nonce = load_or_create_nonce_b64()?; // or _bin()
    let cipher = XChaCha20Poly1305::new(&key);

    let ciphertext = cipher.encrypt(&nonce, b"plaintext message2".as_ref())?;
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    assert_eq!(&plaintext, b"plaintext message2");

    Ok(())
}


#[test]
fn test_encrypt_text() -> MyResult {
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?; // or _bin()
    let ciphertext = encrypt_text(&key, &nonce, b"plaintext message2".as_ref());

    assert!(ciphertext.is_ok());
    Ok(())
}

#[test]
fn test_decrypt_text() -> MyResult {
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?; // or _bin()

    // encrypted from `plaintext message2`
    let hex_s = "117234a709dadbeef318d727b9bf5f60d63ff99e4c39e1fbed95eff3672a24929afb".to_string();
    let plaintext = decrypt_text(&key, &nonce, &hex_s)?;
    assert_eq!(plaintext, "plaintext message2".to_string());

    Ok(())
}

#[test]
fn test_encrypt_cred() -> MyResult {
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?;

    let cred = sample_credential2();
    let c_cred = encrypt_cred(&key, &nonce, &cred);
    // dbg!(&c_cred);
    assert!(c_cred.is_ok());

    Ok(())
}

#[test]
fn test_decrypt_cred() -> MyResult {
    let c_cred = read_from_json("data/output/credentials.json")?;
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?;

    let cred = decrypt_cred(&key, &nonce, &c_cred)?;
    dbg!(&cred);

    Ok(())
}

#[test]
fn test_load_or_create_key_b64() -> MyResult {
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?; // or _bin()

    let cipher = XChaCha20Poly1305::new(&key);

    let ciphertext = cipher.encrypt(&nonce, b"plaintext message2".as_ref())?;
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    assert_eq!(&plaintext, b"plaintext message2");

    Ok(())
}

#[test]
fn test_write_to_json() -> MyResult {
    let key = load_or_create_key_b64()?;
    let nonce = load_or_create_nonce_b64()?;

    let cred = sample_credential2();
    let c_cred = encrypt_cred(&key, &nonce, &cred)?;
    write_to_json(c_cred, "data/output/credentials.json")?;
    Ok(())
}

// Reading and writing the same file causes race condition
#[test]
#[ignore]
fn test_read_from_json() -> MyResult {
    let credential = read_from_json("data/output/credentials.json")?;
    assert_eq!(credential.account_name, "RustRover");
    Ok(())
}

#[test]
fn test_write_to_json_independent() -> MyResult {
    let tmp = tempfile::NamedTempFile::new()?;
    write_to_json(sample_credential(), tmp.path().to_str().unwrap())?;
    Ok(())
}

#[test]
fn test_read_from_json_independent() -> MyResult {
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    write_to_json(sample_credential(), path)?;
    let cred = read_from_json(path)?;
    assert_eq!(cred.account_name, "RustRover");
    Ok(())
}
