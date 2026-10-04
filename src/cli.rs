use clap::{Parser, Subcommand};

use crate::{SecurityQuestion, SubCredential};

// Parsers for key=value style flags
pub(crate) fn parse_security_question(s: &str) -> Result<SecurityQuestion, String> {
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

pub(crate) fn parse_sub_credential(s: &str) -> Result<SubCredential, String> {
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

        /// Read the password from this file (first line; owner-only permissions enforced)
        #[arg(
            long = "password-file",
            value_name = "PATH",
            conflicts_with = "password_stdin"
        )]
        password_file: Option<String>,

        /// Read the password from stdin
        #[arg(long = "password-stdin")]
        password_stdin: bool,

        /// Read security questions from this file, one QUESTION=ANSWER per line
        #[arg(long = "sec-file", value_name = "PATH")]
        sec_file: Option<String>,

        /// Read sub credentials from this file, one NAME=PASSWORD per line
        #[arg(long = "sub-file", value_name = "PATH")]
        sub_file: Option<String>,

        /// Path to the Base64 key file (will be created if missing)
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,

        /// Path to the output JSON file
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FILE",
            default_value = "data/output/credentials.json"
        )]
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
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,

        /// Path to the credentials JSON file to read from
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/credentials.json"
        )]
        input: String,
    },

    /// Delete a credential by account name
    Delete {
        account: String,
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/credentials.json"
        )]
        input: String,
    },

    /// Update credential fields; unspecified fields remain unchanged
    Update {
        account: String,
        #[arg(short = 'u', long = "user-name")]
        user_name: Option<String>,

        /// Prompt for a new password (or read it from stdin when piped)
        #[arg(long = "set-password")]
        set_password: bool,

        /// Read the new password from this file
        #[arg(
            long = "password-file",
            value_name = "PATH",
            conflicts_with = "set_password"
        )]
        password_file: Option<String>,

        /// Read security questions from this file, one QUESTION=ANSWER per line
        #[arg(long = "sec-file", value_name = "PATH")]
        sec_file: Option<String>,

        /// Read sub credentials from this file, one NAME=PASSWORD per line
        #[arg(long = "sub-file", value_name = "PATH")]
        sub_file: Option<String>,

        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/credentials.json"
        )]
        input: String,
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,
    },
}
