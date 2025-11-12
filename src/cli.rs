use clap::{Parser, Subcommand};

use crate::{SecurityQuestion, SubCredential};

// Parsers for key=value style flags
fn parse_security_question(s: &str) -> Result<SecurityQuestion, String> {
    let (q, a) = s
        .split_once('=')
        .ok_or_else(|| "expected QUESTION=ANSWER".to_string())?;
    if q.trim().is_empty() || a.trim().is_empty() {
        return Err("QUESTION and ANSWER must be non-empty".to_string());
    }
    Ok(SecurityQuestion {
        question: q.trim().to_string(),
        answer: a.trim().to_string(),
    })
}

fn parse_sub_credential(s: &str) -> Result<SubCredential, String> {
    let (name, pwd) = s
        .split_once('=')
        .ok_or_else(|| "expected NAME=PASSWORD".to_string())?;
    if name.trim().is_empty() || pwd.trim().is_empty() {
        return Err("NAME and PASSWORD must be non-empty".to_string());
    }
    Ok(SubCredential {
        cred_name: name.trim().to_string(),
        password: pwd.trim().to_string(),
    })
}

// `#[derive(Parser)]` turns the `Cli` struct into a parser for command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "pwd_manager",
    version,
    about = "A tiny password manager CLI example",
    arg_required_else_help = true
)]

pub struct Cli {
    /// Subcommands: add, find
    #[command(subcommand)]
    pub command: Commands,
}

//`#[derive(Subcommand)]` lets you define `enum Commands` variants that become subcommands.
// - Each field in a subcommand variant becomes a positional argument or a flag based on attributes:
// - Bare fields like `account: String` are positional.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Add a credential
    Add {
        /// Account name (e.g., "GitHub")
        account_name: String,

        /// Username for the account
        #[arg(short = 'u', long = "user-name")]
        user_name: String,

        /// Password for the account
        #[arg(short, long)]
        password: String,

        /// Security question(s) as QUESTION=ANSWER (repeat flag to add multiple)
        /// Example: --sec "Mother's maiden?=Smith" --sec "Pet name?=Rex"
        #[arg(long = "sec", value_parser = parse_security_question, value_name = "QUESTION=ANSWER")]
        security_questions: Vec<SecurityQuestion>,

        /// Sub credential(s) as NAME=PASSWORD (repeat flag to add multiple)
        /// Example: --sub "api=ap1-SECRET" --sub "db=db-SECRET"
        #[arg(long = "sub", value_parser = parse_sub_credential, value_name = "NAME=PASSWORD")]
        sub_credentials: Vec<SubCredential>,

        /// Path to the Base64 key file (will be created if missing)
        #[arg(long = "key-file", value_name = "PATH", default_value = "data/input/key.txt")]
        key_file: String,

        /// Path to the Base64 none file (will be created if missing)
        #[arg(long = "nonce-file", value_name = "PATH", default_value = "data/input/nonce.txt")]
        nonce_file: String,

        /// Path to the output JSON file
        #[arg(short = 'o', long = "output", value_name = "FILE", default_value = "data/output/credentials.json")]
        output: String,
    },

    /// Find a credential by account name
    Find {
        /// Account name to search for
        account: String,

        /// Print raw JSON output
        #[arg(short, long)]
        json: bool,

        /// Path to the Base64 key file
        #[arg(long = "key-file", value_name = "PATH", default_value = "data/input/key.txt")]
        key_file: String,

        /// Path to the Base64 none file (will be created if missing)
        #[arg(long = "nonce-file", value_name = "PATH", default_value = "data/input/nonce.txt")]
        nonce_file: String,

        /// Path to the credentials JSON file to read from
        #[arg(short = 'i', long = "input", value_name = "FILE", default_value = "data/output/credentials.json")]
        input: String,
    },
}
