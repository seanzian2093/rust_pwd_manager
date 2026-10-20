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

        /// Read the vault master passphrase from an owner-only file
        #[arg(long = "master-passphrase-file", value_name = "PATH")]
        master_passphrase_file: Option<String>,

        /// Read security questions from this file, one QUESTION=ANSWER per line
        #[arg(long = "sec-file", value_name = "PATH")]
        sec_file: Option<String>,

        /// Read sub credentials from this file, one NAME=PASSWORD per line
        #[arg(long = "sub-file", value_name = "PATH")]
        sub_file: Option<String>,

        /// Path to the Argon2-wrapped key file (created or upgraded if needed)
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,

        /// Path to the vault file (redb; created if missing)
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
        )]
        output: String,
    },

    /// Find a credential by account name
    Find {
        /// Account name to search for
        account: String,

        /// Print JSON output (secrets are redacted unless --reveal is set)
        #[arg(short, long)]
        json: bool,

        /// Reveal passwords and security-question answers in the output
        #[arg(long)]
        reveal: bool,

        /// Copy the account password to the clipboard instead of printing secrets
        #[arg(
            long,
            conflicts_with_all = ["json", "reveal", "copy_answer", "copy_sub_password"]
        )]
        copy_password: bool,

        /// Copy a security-question answer to the clipboard (1-based index)
        #[arg(
            long,
            value_name = "INDEX",
            conflicts_with_all = ["json", "reveal", "copy_password", "copy_sub_password"]
        )]
        copy_answer: Option<usize>,

        /// Copy a sub-credential password to the clipboard (1-based index)
        #[arg(
            long,
            value_name = "INDEX",
            conflicts_with_all = ["json", "reveal", "copy_password", "copy_answer"]
        )]
        copy_sub_password: Option<usize>,

        /// Read the vault master passphrase from an owner-only file
        #[arg(long = "master-passphrase-file", value_name = "PATH")]
        master_passphrase_file: Option<String>,

        /// Path to the Argon2-wrapped key file
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,

        /// Path to the vault file to read from
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
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
            default_value = "data/output/vault.redb"
        )]
        input: String,
    },

    /// List every stored account name
    List {
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
        )]
        input: String,
    },

    /// Import credentials from the legacy per-field JSON store into the vault
    Import {
        /// Path to the old JSON credentials file
        #[arg(long = "legacy-input", value_name = "FILE")]
        legacy_input: String,

        /// Path to the legacy shared-nonce file, required for the earliest JSON format
        #[arg(long = "legacy-nonce-file", value_name = "FILE")]
        legacy_nonce_file: Option<String>,

        /// Read the vault master passphrase from an owner-only file
        #[arg(long = "master-passphrase-file", value_name = "PATH")]
        master_passphrase_file: Option<String>,

        /// Path to the wrapped key file used to encrypt the legacy store
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,

        /// Path to the vault file to import into (created if missing)
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
        )]
        output: String,
    },

    /// Export all credentials to a new owner-only plaintext JSON file
    Export {
        /// Path to the vault file to export
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
        )]
        input: String,

        /// Destination JSON file; must not already exist
        #[arg(long = "output", value_name = "FILE", required = true)]
        output: String,

        /// Read the vault master passphrase from an owner-only file
        #[arg(long = "master-passphrase-file", value_name = "PATH")]
        master_passphrase_file: Option<String>,

        /// Path to the Argon2-wrapped key file
        #[arg(
            long = "key-file",
            value_name = "PATH",
            default_value = "data/input/key.txt"
        )]
        key_file: String,
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

        /// Read the vault master passphrase from an owner-only file
        #[arg(long = "master-passphrase-file", value_name = "PATH")]
        master_passphrase_file: Option<String>,

        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "data/output/vault.redb"
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
