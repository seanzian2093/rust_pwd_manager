use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use clap::Parser;
use pwd_manager::{
    Credential, UpstreamError, backup_vault,
    cli::{Cli, Commands, MaintenanceCommands},
    compact_vault, delete_credential, export_credentials, find_and_decrypt,
    import_legacy_json_with_nonce, key_file_requires_confirmation, list_accounts, load_key_from,
    load_or_create_key, restore_vault,
    secret_input::{
        SecretSource, read_security_questions, read_sub_credentials, resolve_master_passphrase,
        resolve_secret,
    },
    update_credential, upsert_credential,
};
use zeroize::Zeroizing;

fn copy_to_clipboard(secret: &str) -> Result<(), UpstreamError> {
    #[cfg(target_os = "macos")]
    let clipboard_commands: &[(&str, &[&str])] = &[("pbcopy", &[])];

    #[cfg(target_os = "windows")]
    let clipboard_commands: &[(&str, &[&str])] = &[("clip", &[])];

    #[cfg(target_os = "linux")]
    let clipboard_commands: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return Err(UpstreamError::Other(
        "Clipboard output is not supported on this platform".to_string(),
    ));

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let mut not_found = Vec::new();
        for (program, args) in clipboard_commands {
            let mut child = match Command::new(program)
                .args(*args)
                .stdin(Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    not_found.push(*program);
                    continue;
                }
                Err(error) => return Err(UpstreamError::IO(error)),
            };

            let mut stdin = child.stdin.take().ok_or_else(|| {
                UpstreamError::Other(format!("Failed to open stdin for {}", program))
            })?;
            let write_result = stdin.write_all(secret.as_bytes());
            drop(stdin);
            let status = child.wait()?;
            write_result?;
            if !status.success() {
                return Err(UpstreamError::Other(format!(
                    "Clipboard utility {} exited with status {}",
                    program, status
                )));
            }
            return Ok(());
        }

        Err(UpstreamError::Other(format!(
            "No clipboard utility found (tried {})",
            not_found.join(", ")
        )))
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn unlock_key_file(
    key_file: &str,
    create_if_missing: bool,
    passphrase_file: Option<&str>,
) -> Result<chacha20poly1305::Key, UpstreamError> {
    if !create_if_missing && !Path::new(key_file).exists() {
        return Err(UpstreamError::Other(format!("{} does not exist", key_file)));
    }
    let confirm = key_file_requires_confirmation(key_file)?;
    let passphrase = resolve_master_passphrase(passphrase_file.map(Path::new), confirm)?;
    if create_if_missing {
        load_or_create_key(key_file, &passphrase)
    } else {
        load_key_from(key_file, &passphrase)
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
            master_passphrase_file,
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
                account_name: Zeroizing::new(account_name.to_string()),
                user_name: Zeroizing::new(user_name.to_string()),
                password: Zeroizing::new(password.to_string()),
                security_questions,
                sub_credentials,
            };

            println!("Adding credential: {:#?} - started", cred.account_name);

            let key = unlock_key_file(&key_file, true, master_passphrase_file.as_deref())?;

            upsert_credential(&output, &key, &cred)?;

            println!("Adding credential: {:#?} - succeeded", cred.account_name);
        }
        Commands::Find {
            account,
            json,
            reveal,
            copy_password,
            copy_answer,
            copy_sub_password,
            master_passphrase_file,
            key_file,
            input,
        } => {
            // Do not create or replace a missing key while finding.
            let key = unlock_key_file(&key_file, false, master_passphrase_file.as_deref())?;
            let cred = find_and_decrypt(&account, &key, &input)?;

            if copy_password {
                copy_to_clipboard(&cred.password)?;
                println!("Copied account password to clipboard.");
            } else if let Some(index) = copy_answer {
                let answer = index
                    .checked_sub(1)
                    .and_then(|index| cred.security_questions.get(index))
                    .ok_or_else(|| {
                        UpstreamError::Other(format!(
                            "Security-question index {} is out of range (indices start at 1)",
                            index
                        ))
                    })?;
                copy_to_clipboard(&answer.answer)?;
                println!("Copied security-question answer {} to clipboard.", index);
            } else if let Some(index) = copy_sub_password {
                let password = index
                    .checked_sub(1)
                    .and_then(|index| cred.sub_credentials.get(index))
                    .ok_or_else(|| {
                        UpstreamError::Other(format!(
                            "Sub-credential index {} is out of range (indices start at 1)",
                            index
                        ))
                    })?;
                copy_to_clipboard(&password.password)?;
                println!("Copied sub-credential password {} to clipboard.", index);
            } else if json {
                let mut output_cred = cred;
                if !reveal {
                    output_cred.password = Zeroizing::new("******".to_string());
                    for question in &mut output_cred.security_questions {
                        question.answer = Zeroizing::new("******".to_string());
                    }
                    for sub_credential in &mut output_cred.sub_credentials {
                        sub_credential.password = Zeroizing::new("******".to_string());
                    }
                }
                let rendered =
                    Zeroizing::new(serde_json::to_string_pretty(&output_cred).map_err(|e| {
                        UpstreamError::Other(format!("Failed to render JSON: {}", e))
                    })?);
                println!("{}", *rendered);
            } else {
                let password = if reveal { &cred.password } else { "******" };
                println!(
                    "Found credential for '{}': user={}, password={}",
                    cred.account_name.as_str(),
                    cred.user_name.as_str(),
                    password
                );

                if !cred.security_questions.is_empty() {
                    println!("Security questions:");
                    for q in &cred.security_questions {
                        let answer = if reveal { &q.answer } else { "******" };
                        println!("  - {} = {}", q.question.as_str(), answer);
                    }
                }

                if !cred.sub_credentials.is_empty() {
                    println!("Sub credentials:");
                    for s in &cred.sub_credentials {
                        let password = if reveal { &s.password } else { "******" };
                        println!("  - {} = {}", s.cred_name.as_str(), password);
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
            legacy_nonce_file,
            master_passphrase_file,
            key_file,
            output,
        } => {
            let key = unlock_key_file(&key_file, false, master_passphrase_file.as_deref())?;
            let count = import_legacy_json_with_nonce(
                &legacy_input,
                &key,
                legacy_nonce_file.as_deref().map(Path::new),
                &output,
            )?;
            println!("Imported {} credential(s) into {}", count, output);
        }
        Commands::Export {
            input,
            output,
            master_passphrase_file,
            key_file,
        } => {
            let key = unlock_key_file(&key_file, false, master_passphrase_file.as_deref())?;
            let count = export_credentials(&input, &key, &output)?;
            println!("Exported {} credential(s) to {}", count, output);
        }
        Commands::Backup { input, output } => {
            backup_vault(&input, &output)?;
            println!("Backed up vault {} to {}", input, output);
            eprintln!("Keep the backup separate from the key file and master passphrase.");
        }
        Commands::Restore { input, output } => {
            restore_vault(&input, &output)?;
            println!("Restored vault backup {} to {}", input, output);
            eprintln!(
                "Ensure the matching key file and master passphrase are available separately."
            );
        }
        Commands::Maintenance { command } => match command {
            MaintenanceCommands::Compact { input } => {
                if compact_vault(&input)? {
                    println!("Compacted vault: {}", input);
                } else {
                    println!("No further compaction was possible for vault: {}", input);
                }
            }
        },
        Commands::Update {
            account,
            user_name,
            set_password,
            password_file,
            sec_file,
            sub_file,
            master_passphrase_file,
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
            let key = unlock_key_file(&key_file, true, master_passphrase_file.as_deref())?;

            update_credential(&input, &key, &account, |c| {
                if let Some(u) = user_name {
                    c.user_name = Zeroizing::new(u.to_string());
                }
                if let Some(p) = password {
                    c.password = Zeroizing::new(p.to_string());
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
