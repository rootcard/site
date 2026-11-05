//! Rate limits for the host endpoints, following rootcard's HOST_PROTOCOL.md §6. Fixed windows per network address and,
//! where the protocol recommends it, per identity. In memory: the site runs as one process.

use std::collections::HashMap;
use std::sync::Mutex;

/// A limit: at most `count` requests per `window` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub count: u32,
    pub window: i64,
}

const fn per(count: u32, window: i64) -> Option<Limit> {
    Some(Limit { count, window })
}

const MINUTE: i64 = 60;
const HOUR: i64 = 3600;

/// An operation class with its limits per address and per identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    pub name: &'static str,
    pub address: Option<Limit>,
    pub identity: Option<Limit>,
}

/// The class of a request (method and path relative to the API root, without the query), and the account it names.
pub fn classify<'a>(method: &str, path: &'a str) -> (Class, Option<&'a str>) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let c = |name, address, identity| Class {
        name,
        address,
        identity,
    };
    match (method, parts.as_slice()) {
        ("POST", ["id", "register"]) => (c("register", per(3, HOUR), None), None),
        ("GET", ["host"]) | ("GET", ["id", "lookup"]) => (c("read", per(120, MINUTE), None), None),
        ("GET", ["id", a, "log" | "public"]) => (c("read", per(120, MINUTE), None), Some(a)),
        ("GET", ["id", a, "locks"]) => (c("locks", per(30, HOUR), per(30, HOUR)), Some(a)),
        ("POST", ["id", a, "challenge"]) => (c("challenge", per(10, MINUTE), per(30, HOUR)), Some(a)),
        ("POST", ["id", a, "fetch"]) => (c("fetch", per(30, HOUR), per(10, HOUR)), Some(a)),
        ("POST", ["id", a, "login"]) => (c("login", per(10, MINUTE), per(30, HOUR)), Some(a)),
        ("POST", ["id", a, "events" | "instance"]) | ("PUT", ["id", a, "vault"]) => {
            (c("write", per(30, HOUR), None), Some(a))
        }
        ("POST", ["session", "password"]) => (c("password", per(10, HOUR), None), None),
        (_, ["session", ..]) => (c("session", per(120, MINUTE), None), None),
        ("OPTIONS", _) => (c("options", None, None), None),
        _ => (c("other", per(120, MINUTE), None), None),
    }
}

/// `(class, address or identity)` → `(window start, count)`.
type Windows = HashMap<(&'static str, String), (i64, u32)>;

/// Fixed-window counters.
#[derive(Default)]
pub struct Limiter(Mutex<Windows>);

impl Limiter {
    /// Count a request. Returns `Err(retry_after)` if a limit is exceeded.
    pub fn check(&self, class: &Class, address: &str, account: Option<&str>, now: i64) -> Result<(), i64> {
        let Ok(mut map) = self.0.lock() else {
            return Ok(());
        };
        let mut hit = |key: String, limit: Limit| -> Result<(), i64> {
            let e = map.entry((class.name, key)).or_insert((now, 0));
            if now - e.0 >= limit.window {
                *e = (now, 0);
            }
            if e.1 >= limit.count {
                return Err((e.0 + limit.window - now).max(1));
            }
            e.1 += 1;
            Ok(())
        };
        if let Some(l) = class.address {
            hit(format!("a:{address}"), l)?;
        }
        if let (Some(l), Some(a)) = (class.identity, account) {
            hit(format!("i:{a}"), l)?;
        }
        Ok(())
    }

    /// Drop windows that have ended (called periodically).
    pub fn sweep(&self, now: i64) {
        if let Ok(mut map) = self.0.lock() {
            map.retain(|_, (start, _)| now - *start < 2 * HOUR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(classify("POST", "/id/register").0.name, "register");
        let (c, a) = classify("POST", "/id/ABCD/fetch");
        assert_eq!((c.name, a), ("fetch", Some("ABCD")));
        assert_eq!(classify("GET", "/session/vault").0.name, "session");
        assert_eq!(classify("OPTIONS", "/id/register").0.name, "options");
    }

    #[test]
    fn window() {
        let l = Limiter::default();
        let (c, _) = classify("POST", "/id/register");
        for _ in 0..3 {
            assert!(l.check(&c, "1.2.3.4", None, 100).is_ok());
        }
        assert_eq!(l.check(&c, "1.2.3.4", None, 101), Err(3599));
        assert!(l.check(&c, "5.6.7.8", None, 101).is_ok());
        assert!(l.check(&c, "1.2.3.4", None, 100 + 3600).is_ok());
    }

    #[test]
    fn per_identity() {
        let l = Limiter::default();
        let (c, a) = classify("POST", "/id/ACCT/fetch");
        for i in 0..10 {
            assert!(l.check(&c, &format!("10.0.0.{i}"), a, 0).is_ok());
        }
        assert!(l.check(&c, "10.0.1.1", a, 0).is_err());
    }
}
