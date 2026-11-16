//! Who may get an identity with this home: anyone (`open`, the default), whoever has an invite (`invite`), or nobody
//! (`closed`). The site's own addition to the host protocol, which has no notion of it.
//!
//! The gate is on the two requests that make an identity homed here: `POST /v0/id/register`, and
//! `POST /v0/id/{account}/instance` for an identity this home does not know yet (a move from another home). Everything
//! else (sign-in, lookups, the identities already here) works the same in every mode.
//!
//! An invite is a token sent in the `Rootcard-Invite` header. Tokens come from `ROOTCARD_SITE_INVITES` (comma separated)
//! and from `ROOTCARD_SITE_INVITES_FILE`, one per line, read again at every check: adding or deleting a line takes effect
//! at once, without a restart. A line is a token, optionally followed by a `#` comment (whom it is for). A token can be
//! used any number of times until it is removed. `rootcard-site invite [note]` makes one, adds it to the file and prints
//! the link `<url>/create#invite=<token>`, which fills the token in on the registration page.

use std::path::{Path, PathBuf};

/// The request header that carries the invite.
pub const HEADER: &str = "rootcard-invite";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Open,
    Invite,
    Closed,
}

impl Mode {
    /// The name of the mode, as in `ROOTCARD_SITE_REGISTRATION` and in the pages' `<!--#if-->` markers.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Open => "open",
            Mode::Invite => "invite",
            Mode::Closed => "closed",
        }
    }
}

pub struct Registration {
    pub mode: Mode,
    tokens: Vec<String>,
    pub file: Option<PathBuf>,
}

/// Whether `t` can be an invite: 8 to 128 characters that need no escaping in a URL or a header.
pub fn valid_token(t: &str) -> bool {
    (8..=128).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// The tokens of an invites file: the first word of every line that is not empty or a comment.
fn file_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|l| l.split('#').next()?.split_whitespace().next())
}

/// Equality that takes the same time wherever the first difference is.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

impl Registration {
    /// The configuration from the environment (`env` returns a variable, `None` when unset or empty).
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> Result<Registration, String> {
        let tokens: Vec<String> = env("ROOTCARD_SITE_INVITES")
            .map(|v| {
                v.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(bad) = tokens.iter().find(|t| !valid_token(t)) {
            return Err(format!(
                "ROOTCARD_SITE_INVITES: {bad:?} is not an invite: 8 to 128 letters, digits, '-', '.', '_' or '~'"
            ));
        }
        let file = env("ROOTCARD_SITE_INVITES_FILE").map(PathBuf::from);
        let has_invites = !tokens.is_empty() || file.is_some();
        let mode = match env("ROOTCARD_SITE_REGISTRATION").as_deref().map(str::trim) {
            None if has_invites => Mode::Invite,
            None | Some("open") => Mode::Open,
            Some("invite") => Mode::Invite,
            Some("closed") => Mode::Closed,
            Some(other) => {
                return Err(format!(
                    "ROOTCARD_SITE_REGISTRATION: {other:?}; use open (anyone), invite (with an invite) or closed (nobody)"
                ));
            }
        };
        if mode != Mode::Invite && has_invites {
            return Err(format!(
                "ROOTCARD_SITE_INVITES and ROOTCARD_SITE_INVITES_FILE are for ROOTCARD_SITE_REGISTRATION=invite, not {}",
                mode.name()
            ));
        }
        if mode == Mode::Invite && !has_invites {
            return Err(
                "ROOTCARD_SITE_REGISTRATION=invite: give the invites in ROOTCARD_SITE_INVITES or ROOTCARD_SITE_INVITES_FILE"
                    .into(),
            );
        }
        let r = Registration { mode, tokens, file };
        if let Some(path) = &r.file {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    if let Some(bad) = file_tokens(&text).find(|t| !valid_token(t)) {
                        return Err(format!(
                            "{}: {bad:?} is not an invite: 8 to 128 letters, digits, '-', '.', '_' or '~'",
                            path.display()
                        ));
                    }
                }
                // No invites yet: `rootcard-site invite` makes the file.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Ok(r)
    }

    /// Whether a new identity may be homed here, given the invite sent with the request. `Err` is the error code.
    pub fn check(&self, invite: Option<&str>) -> Result<(), &'static str> {
        match self.mode {
            Mode::Open => Ok(()),
            Mode::Closed => Err("registration_closed"),
            Mode::Invite => {
                let Some(invite) = invite.map(str::trim).filter(|t| !t.is_empty()) else {
                    return Err("invite_required");
                };
                if valid_token(invite) && self.accepts(invite) {
                    Ok(())
                } else {
                    Err("invite_invalid")
                }
            }
        }
    }

    fn accepts(&self, invite: &str) -> bool {
        let mut found = false;
        for t in &self.tokens {
            found |= same(t.as_bytes(), invite.as_bytes());
        }
        if let Some(path) = &self.file {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    for t in file_tokens(&text) {
                        found |= same(t.as_bytes(), invite.as_bytes());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // Unreadable: no invite from it is accepted.
                Err(e) => eprintln!("rootcard-site: {}: {e}", path.display()),
            }
        }
        found
    }
}

/// A new random invite: 120 bits, as 24 lower-case base32 characters.
pub fn new_token(random: impl FnOnce(&mut [u8])) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut b = [0u8; 15];
    random(&mut b);
    let mut out = String::with_capacity(24);
    for chunk in b.chunks(5) {
        let n = chunk.iter().fold(0u64, |n, &x| n << 8 | u64::from(x));
        for i in (0..8).rev() {
            out.push(ALPHABET[(n >> (i * 5) & 31) as usize] as char);
        }
    }
    out
}

/// Add `token` to the invites file at `path`, created with mode 0600 if it does not exist, with `note` as its comment.
pub fn append(path: &Path, token: &str, note: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    let note: String = note.chars().filter(|c| !c.is_control()).collect();
    let line = if note.trim().is_empty() {
        format!("{token}\n")
    } else {
        format!("{token}  # {}\n", note.trim())
    };
    f.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn reg(vars: &[(&str, &str)]) -> Result<Registration, String> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Registration::from_env(|k| m.get(k).cloned())
    }

    #[test]
    fn modes() {
        assert_eq!(reg(&[]).expect("open").mode, Mode::Open);
        assert_eq!(
            reg(&[("ROOTCARD_SITE_REGISTRATION", "closed")]).expect("closed").mode,
            Mode::Closed
        );
        // Invites alone mean invite mode.
        assert_eq!(
            reg(&[("ROOTCARD_SITE_INVITES", "abcdefgh")]).expect("invite").mode,
            Mode::Invite
        );
        assert!(reg(&[("ROOTCARD_SITE_REGISTRATION", "invite")]).is_err());
        assert!(
            reg(&[
                ("ROOTCARD_SITE_REGISTRATION", "closed"),
                ("ROOTCARD_SITE_INVITES", "abcdefgh")
            ])
            .is_err()
        );
        assert!(reg(&[("ROOTCARD_SITE_REGISTRATION", "maybe")]).is_err());
        assert!(reg(&[("ROOTCARD_SITE_INVITES", "short")]).is_err());
        assert!(reg(&[("ROOTCARD_SITE_INVITES", "has space in it")]).is_err());
    }

    #[test]
    fn checks() {
        assert_eq!(reg(&[]).expect("open").check(None), Ok(()));
        let closed = reg(&[("ROOTCARD_SITE_REGISTRATION", "closed")]).expect("closed");
        assert_eq!(closed.check(Some("abcdefgh")), Err("registration_closed"));
        let r = reg(&[("ROOTCARD_SITE_INVITES", "abcdefgh, second-invite")]).expect("invite");
        assert_eq!(r.check(Some("abcdefgh")), Ok(()));
        assert_eq!(r.check(Some(" second-invite ")), Ok(()));
        assert_eq!(r.check(None), Err("invite_required"));
        assert_eq!(r.check(Some("")), Err("invite_required"));
        assert_eq!(r.check(Some("abcdefgi")), Err("invite_invalid"));
        assert_eq!(r.check(Some("abcdefg")), Err("invite_invalid"));
    }

    #[test]
    fn invites_file() {
        let dir = std::env::temp_dir().join(format!("rootcard-site-invites-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let path = dir.to_string_lossy().to_string();
        let r = reg(&[("ROOTCARD_SITE_INVITES_FILE", &path)]).expect("missing file is no invites yet");
        assert_eq!(r.mode, Mode::Invite);
        assert_eq!(r.check(Some("abcdefgh")), Err("invite_invalid"));
        // Read again at every check: a new line counts at once, a deleted one stops counting.
        let token = new_token(|b| b.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8));
        assert!(valid_token(&token) && token.len() == 24);
        append(&dir, &token, "for Alice\n").expect("append");
        append(&dir, "other-invite", "").expect("append");
        assert_eq!(r.check(Some(&token)), Ok(()));
        assert_eq!(r.check(Some("other-invite")), Ok(()));
        assert_eq!(r.check(Some("for")), Err("invite_invalid"));
        let text = std::fs::read_to_string(&dir).expect("read");
        assert!(text.contains(&format!("{token}  # for Alice\n")));
        std::fs::write(&dir, "# all gone\n").expect("write");
        assert_eq!(r.check(Some(&token)), Err("invite_invalid"));
        std::fs::write(&dir, "not valid!\n").expect("write");
        assert!(reg(&[("ROOTCARD_SITE_INVITES_FILE", &path)]).is_err());
        let _ = std::fs::remove_file(&dir);
    }
}
