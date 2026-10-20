use std::path::Path;

use clap::Parser;
use pwd_manager::{
    Credential, UpstreamError,
    cli::{Cli, Commands},
    delete_credential, find_and_decrypt, import_legacy_json, list_accounts, load_key_b64_from,
    load_or_create_key_b64_from,
    secret_input::{SecretSource, read_security_questions, read_sub_credentials, resolve_secret},
    update_credential, upsert_credential,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), UpstreamError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Add {
            account_name,
            user_name,
            password_file,
            password_stdin,
            sec_file,
            sub_file,
            key_file,
            output,
        } => {
            let source = match (&password_file, password_stdin) {
                (Some(p), _) => SecretSource::File(Path::new(p)),
                (None, true) => SecretSource::Stdin,
                (None, false) => SecretSource::Auto,
            };
            let password = resolve_secret(source, &format!("Password for {}: ", account_name))?;

            let security_questions = match &sec_file {
                Some(p) => read_security_questions(Path::new(p))?,
                None => Vec::new(),
            };
            let sub_credentials = match &sub_file {
                Some(p) => read_sub_credentials(Path::new(p))?,
                None => Vec::new(),
            };

            let cred = Credential {
                account_name,
                user_name,
                password: password.to_string(),
                security_questions,
                sub_credentials,
            };

            println!("Adding credential: {:#?} - started", cred.account_name);

            let key = load_or_create_key_b64_from(&key_file)?;

            upsert_credential(&output, &key, &cred)?;

            println!("Adding credential: {:#?} - succeeded", cred.account_name);
        }
        Commands::Find {
            account,
            json,
            key_file,
            input,
        } => {
            // Do not create a key here: finding must fail if no vault key exists yet.
            let key = load_key_b64_from(&key_file)?;
            let cred = find_and_decrypt(&account, &key, &input)?;

            if json {
                let rendered = serde_json::to_string_pretty(&cred)
                    .map_err(|e| UpstreamError::Other(format!("Failed to render JSON: {}", e)))?;
                println!("{}", rendered);
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
        Commands::Delete { account, input } => {
            delete_credential(&input, &account)?;
            println!("Deleted credentials for account: {}", account);
        }
        Commands::List { input } => {
            let accounts = list_accounts(&input)?;
            if accounts.is_empty() {
                println!("No credentials stored.");
            } else {
                for account in accounts {
                    println!("{}", account);
                }
            }
        }
        Commands::Import {
            legacy_input,
            key_file,
            output,
        } => {
            let key = load_key_b64_from(&key_file)?;
            let count = import_legacy_json(&legacy_input, &key, &output)?;
            println!("Imported {} credential(s) into {}", count, output);
        }
        Commands::Update {
            account,
            user_name,
            set_password,
            password_file,
            sec_file,
            sub_file,
            input,
            key_file,
        } => {
            let password = match (&password_file, set_password) {
                (Some(p), _) => Some(resolve_secret(
                    SecretSource::File(Path::new(p)),
                    &format!("New password for {}: ", account),
                )?),
                (None, true) => Some(resolve_secret(
                    SecretSource::Auto,
                    &format!("New password for {}: ", account),
                )?),
                (None, false) => None,
            };

            let security_questions = match &sec_file {
                Some(p) => read_security_questions(Path::new(p))?,
                None => Vec::new(),
            };
            let sub_credentials = match &sub_file {
                Some(p) => read_sub_credentials(Path::new(p))?,
                None => Vec::new(),
            };

            // Load the key to (re)encrypt the whole document on save
            let key = load_or_create_key_b64_from(&key_file)?;

            update_credential(&input, &key, &account, |c| {
                if let Some(u) = user_name {
                    c.user_name = u;
                }
                if let Some(p) = password {
                    c.password = p.to_string();
                }
                if !security_questions.is_empty() {
                    c.security_questions = security_questions;
                }
                if !sub_credentials.is_empty() {
                    c.sub_credentials = sub_credentials;
                }
                // Keep struct.account_name unchanged to preserve original casing
                Ok(())
            })?;
            println!("Updated credentials for account: {}", account);
        }
    }

    Ok(())
}
