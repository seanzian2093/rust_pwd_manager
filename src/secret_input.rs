//! Resolves secrets from a file, stdin, or an interactive prompt - never from argv.

use std::{
    fs,
    io::{self, IsTerminal, Read},
    path::Path,
};

use zeroize::Zeroizing;

use crate::{SecurityQuestion, SubCredential, UpstreamError, ensure_owner_only};

/// Where a secret value should be read from.
#[derive(Debug, Clone, Copy)]
pub enum SecretSource<'a> {
    File(&'a Path),
    Stdin,
    /// Read stdin when piped, otherwise prompt on the terminal.
    Auto,
}

/// Strips exactly one trailing newline, preserving any other trailing whitespace.
fn strip_one_newline(s: &str) -> &str {
    s.strip_suffix('\n')
        .map(|t| t.strip_suffix('\r').unwrap_or(t))
        .unwrap_or(s)
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, UpstreamError> {
    if !path.exists() {
        return Err(UpstreamError::Other(format!(
            "{} does not exist",
            path.display()
        )));
    }
    ensure_owner_only(path)?;

    let raw = Zeroizing::new(fs::read_to_string(path)?);
    Ok(Zeroizing::new(strip_one_newline(&raw).to_string()))
}

fn read_stdin() -> Result<Zeroizing<String>, UpstreamError> {
    let mut buf = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut buf)?;
    Ok(Zeroizing::new(strip_one_newline(&buf).to_string()))
}

/// Resolves a single secret, prompting with `prompt` when a terminal is attached.
pub fn resolve_secret(
    source: SecretSource<'_>,
    prompt: &str,
) -> Result<Zeroizing<String>, UpstreamError> {
    let value = match source {
        SecretSource::File(path) => read_secret_file(path)?,
        SecretSource::Stdin => read_stdin()?,
        SecretSource::Auto => {
            if io::stdin().is_terminal() {
                Zeroizing::new(
                    rpassword::prompt_password(prompt)
                        .map_err(|e| UpstreamError::Other(format!("Prompt failed: {}", e)))?,
                )
            } else {
                read_stdin()?
            }
        }
    };

    if value.is_empty() {
        return Err(UpstreamError::Other("Secret must not be empty".to_string()));
    }
    Ok(value)
}

/// Reads `KEY=VALUE` lines from `path`, skipping blanks and `#` comments.
///
/// Each line has the same syntax as the corresponding command-line flag used to.
fn read_pairs_file<T, F>(path: &Path, parse: F) -> Result<Vec<T>, UpstreamError>
where
    F: Fn(&str) -> Result<T, String>,
{
    if !path.exists() {
        return Err(UpstreamError::Other(format!(
            "{} does not exist",
            path.display()
        )));
    }
    ensure_owner_only(path)?;

    let contents = Zeroizing::new(fs::read_to_string(path)?);
    let mut out = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed = parse(trimmed)
            .map_err(|e| UpstreamError::Other(format!("{}:{}: {}", path.display(), i + 1, e)))?;
        out.push(parsed);
    }

    Ok(out)
}

pub fn read_security_questions(path: &Path) -> Result<Vec<SecurityQuestion>, UpstreamError> {
    read_pairs_file(path, crate::cli::parse_security_question)
}

pub fn read_sub_credentials(path: &Path) -> Result<Vec<SubCredential>, UpstreamError> {
    read_pairs_file(path, crate::cli::parse_sub_credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_one_trailing_newline() {
        assert_eq!(strip_one_newline("secret\n"), "secret");
        assert_eq!(strip_one_newline("secret\r\n"), "secret");
        assert_eq!(strip_one_newline("secret\n\n"), "secret\n");
        assert_eq!(strip_one_newline("secret"), "secret");
        // Trailing spaces are legitimate password characters.
        assert_eq!(strip_one_newline("secret  \n"), "secret  ");
    }
}
