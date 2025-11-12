use clap::Parser;
use pwd_manager::{
    MyResult,
    Credential, cli::{Cli, Commands},
    encrypt_cred,
    load_or_create_key_b64_from,
    load_or_create_nonce_b64_from,
    append_credential,
    find_and_decrypt,
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
            append_credential(&output, enc).expect("Write failed");

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
    }

    Ok(())
}
