//! Rate limits for the host endpoints, following rootcard's HOST_PROTOCOL.md §6. Fixed windows per network address and,
//! where the protocol recommends it, per identity. In memory: the site runs as one process.
//!
//! Every request counts against its address. Only failed requests count against the identity they name: §6 asks hosts to
//! count failed fetches (online password guesses) separately, and warns that limits per identity let an attacker delay
//! the owner (AR8). Counting every request would let anyone lock an owner out of signing in with 30 `GET …/locks`.
//!
//! IPv6 addresses are limited per /64, the block one subscriber usually gets: per address, one subscriber would have
//! 2^64 of them.

use std::collections::HashMap;
use std::net::IpAddr;
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

/// Whether `a` has the form of an account id (52 digits and upper-case letters). Only those are counted per
/// identity, so arbitrary path segments cannot fill the limiter's memory.
fn is_account(a: &str) -> bool {
    a.len() == 52 && a.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// The key an address is limited by: the address itself, or its /64 for IPv6 (an IPv4 address mapped into IPv6 is the
/// IPv4 address). Text that is not an address is used as it is.
pub fn address_key(address: &str) -> String {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => address.to_string(),
    }
}

/// The class of a request (method and path relative to the API root, without the query), and the account it names.
pub fn classify<'a>(method: &str, path: &'a str) -> (Class, Option<&'a str>) {
    let (class, account) = classify_path(method, path);
    (class, account.filter(|a| is_account(a)))
}

fn classify_path<'a>(method: &str, path: &'a str) -> (Class, Option<&'a str>) {
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
    /// Count a request against its address, and check that the identity it names has failures left. Returns
    /// `Err(retry_after)` if a limit is exceeded. Report the outcome with [`Limiter::failed`].
    pub fn check(&self, class: &Class, address: &str, account: Option<&str>, now: i64) -> Result<(), i64> {
        let Ok(mut map) = self.0.lock() else {
            return Ok(());
        };
        if let Some(limit) = class.address {
            let e = map
                .entry((class.name, format!("a:{}", address_key(address))))
                .or_insert((now, 0));
            if now - e.0 >= limit.window {
                *e = (now, 0);
            }
            if e.1 >= limit.count {
                return Err((e.0 + limit.window - now).max(1));
            }
            e.1 += 1;
        }
        if let (Some(limit), Some(a)) = (class.identity, account)
            && let Some(e) = map.get(&(class.name, format!("i:{a}")))
            && now - e.0 < limit.window
            && e.1 >= limit.count
        {
            return Err((e.0 + limit.window - now).max(1));
        }
        Ok(())
    }

    /// Count a failed request against the identity it names.
    pub fn failed(&self, class: &Class, account: Option<&str>, now: i64) {
        let (Some(limit), Some(a)) = (class.identity, account) else {
            return;
        };
        let Ok(mut map) = self.0.lock() else {
            return;
        };
        let e = map.entry((class.name, format!("i:{a}"))).or_insert((now, 0));
        if now - e.0 >= limit.window {
            *e = (now, 0);
        }
        e.1 = e.1.saturating_add(1);
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

    const ACCT: &str = "3F9CQ7M2K8XH4T1VZ6RBNW0J5PDGA9SE3YC7KFM2HQ8T4V1XZ6RB";

    #[test]
    fn classes() {
        assert_eq!(classify("POST", "/id/register").0.name, "register");
        let path = format!("/id/{ACCT}/fetch");
        let (c, a) = classify("POST", &path);
        assert_eq!((c.name, a), ("fetch", Some(ACCT)));
        // Anything else in the place of the account is not counted per identity.
        assert_eq!(classify("POST", "/id/ABCD/fetch").1, None);
        assert_eq!(classify("GET", &format!("/id/{}/locks", ACCT.to_lowercase())).1, None);
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
    fn per_identity_counts_failures_only() {
        let l = Limiter::default();
        let path = format!("/id/{ACCT}/fetch");
        let (c, a) = classify("POST", &path);
        // Successful requests from many addresses leave the identity's budget alone.
        for i in 0..20 {
            assert!(l.check(&c, &format!("10.0.0.{i}"), a, 0).is_ok());
        }
        for i in 0..10 {
            assert!(l.check(&c, &format!("10.0.1.{i}"), a, 0).is_ok());
            l.failed(&c, a, 0);
        }
        assert_eq!(l.check(&c, "10.0.2.1", a, 10), Err(3590));
        assert!(l.check(&c, "10.0.2.1", a, 3600).is_ok());
    }

    #[test]
    fn locks_cannot_lock_out_the_owner() {
        let l = Limiter::default();
        let path = format!("/id/{ACCT}/locks");
        let (c, a) = classify("GET", &path);
        for i in 0..30 {
            assert!(l.check(&c, &format!("10.0.0.{i}"), a, 0).is_ok());
        }
        assert!(l.check(&c, "192.0.2.1", a, 0).is_ok());
    }

    #[test]
    fn ipv6_per_64() {
        assert_eq!(address_key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(address_key("2001:db8:1:2:ffff::1"), "2001:db8:1:2::/64");
        assert_eq!(address_key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(address_key("192.0.2.1"), "192.0.2.1");
        let l = Limiter::default();
        let (c, _) = classify("POST", "/id/register");
        for i in 0..3 {
            assert!(l.check(&c, &format!("2001:db8::{i}"), None, 0).is_ok());
        }
        assert!(l.check(&c, "2001:db8::ffff", None, 0).is_err());
        assert!(l.check(&c, "2001:db8:0:1::1", None, 0).is_ok());
    }
}
