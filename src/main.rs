use clap::Parser;
use pwd_manager::{
    MyResult,
    Credential, cli::{Cli, Commands},
    encrypt_cred,
    load_or_create_key_b64_from,
    load_or_create_nonce_b64_from,
    // append_credential,
    upsert_credential,
    update_credential,
    find_and_decrypt,
    delete_credential,
    encrypt_text,
    encrypt_security_question,
    encrypt_sub_credential,
};

fn main() -> MyResult {
    let cli = Cli::parse();

    match cli.command {
        Commands::Add {
            account_name,
            user_name,
            password,
            security_questions,
            sub_credentials,
            key_file,
            nonce_file,
            output
        } => {
            let cred = Credential {
                account_name,
                user_name,
                password,
                security_questions,
                sub_credentials,
            };

            println!("Adding credential: {:#?} - started", cred.account_name);

            // to decrypt, key and nonce must match
            let key = load_or_create_key_b64_from(&key_file)?;
            let nonce = load_or_create_nonce_b64_from(&nonce_file)?;

            let enc = encrypt_cred(&key, &nonce, &cred).expect("Encryption failed");
            // append_credential(&output, enc).expect("Write failed");
            upsert_credential(&output, enc).expect("Write failed");

            println!("Adding credential: {:#?} - succeeded", cred.account_name);
        }
        Commands::Find { 
            account, 
            json ,
            key_file,
            nonce_file,
            input,
        } => {
            match find_and_decrypt(&account, &key_file, &nonce_file, &input) {
                Ok(cred) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&cred).unwrap());
                    } else {
                        println!(
                            "Found credential for '{}': user={}, password={}",
                            cred.account_name, cred.user_name, cred.password
                        );

                        if !cred.security_questions.is_empty() {
                            println!("Security questions:");
                            for q in &cred.security_questions {
                                println!("  - {} = {}", q.question, q.answer);
                            }
                        }

                        if !cred.sub_credentials.is_empty() {
                            println!("Sub credentials:");
                            for s in &cred.sub_credentials {
                                println!("  - {} = {}", s.cred_name, s.password);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error in finding credentials for '{}': {}", account, e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Delete { account, input } => {
            delete_credential(&input, &account)?;
            println!("Deleted credentials for account: {}", account);
        }
        Commands::Update { account, user_name, password, security_questions, sub_credentials, input, key_file, nonce_file } => {
            // Load key/nonce to (re)encrypt changed fields
            let key = load_or_create_key_b64_from(&key_file)?;
            let nonce = load_or_create_nonce_b64_from(&nonce_file)?;

            update_credential(&input, &account, |c| {
                if let Some(u) = user_name.as_ref() {
                    c.user_name = encrypt_text(&key, &nonce, u.as_bytes()).unwrap();
                }
                if let Some(p) = password.as_ref() {
                    c.password = encrypt_text(&key, &nonce, p.as_bytes()).unwrap();
                }
                if !security_questions.is_empty() {
                    c.security_questions = security_questions
                        .iter()
                        .map(|q| encrypt_security_question(&key, &nonce, q))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                }
                if !sub_credentials.is_empty() {
                    c.sub_credentials = sub_credentials
                        .iter()
                        .map(|s| encrypt_sub_credential(&key, &nonce, s))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                }
                // Keep struct.account_name unchanged to preserve original casing
            })?;
            println!("Updated credentials for account: {}", account);
        }
    }

    Ok(())
}
