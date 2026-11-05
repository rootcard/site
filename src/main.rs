//! rootcard.org: the product site and a public rootcard home.
//!
//! One binary serves the static site (embedded at build time from `web/`) and the rootcard host protocol under
//! `<base URL>/v0` through `rootcard_host::http::route`, with SQLite storage and the recommended rate limits. The base
//! URL is the site's origin (`https://rootcard.org`), so the pages it serves derive the address they sign from
//! `location.origin` (HOST_PROTOCOL.md §1).
#![forbid(unsafe_code)]

mod limits;
mod store;

mod assets {
    pub struct Asset {
        pub path: &'static str,
        pub body: &'static [u8],
        pub mime: &'static str,
        pub etag: &'static str,
    }
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));

    pub fn find(path: &str) -> Option<&'static Asset> {
        ASSETS.iter().find(|a| a.path == path)
    }
}

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use limits::{Limiter, classify};
use rootcard::encoding::{hex_decode, hex_encode};
use rootcard_host::http::{MAX_BODY, Request as HostRequest, route};
use rootcard_host::peer::PeerHeaders;
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Db;
use zeroize::Zeroizing;

type SiteHost = Host<Db, Db, Db>;

struct App {
    host: SiteHost,
    db: Db,
    limiter: Limiter,
    trust_proxy: bool,
    https: bool,
}

/// The strict policy for every page the site serves: they handle passwords (rootcard THREAT_MODEL.md T19), so no inline
/// script and nothing from a third party.
const CSP: &str = "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data: blob:; \
    connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random(buf: &mut [u8]) {
    // Without a working random generator the host must not issue challenges or tokens.
    if getrandom::fill(buf).is_err() {
        eprintln!("fatal: the operating system's random generator failed");
        std::process::abort();
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("rootcard-site: {msg}");
    std::process::exit(2)
}

/// The host key: `ROOTCARD_SITE_SEED` (64 hex), or the file `ROOTCARD_SITE_KEY_FILE` (default `host.key`), created with
/// a fresh key on first start. The key signs receipts ([HST-17]); keep it with the database.
fn host_seed() -> Zeroizing<[u8; 32]> {
    let parse = |text: &str| -> Zeroizing<[u8; 32]> {
        let bytes = Zeroizing::new(hex_decode(text.trim()).unwrap_or_else(|_| fail("the host key is not hex")));
        if bytes.len() != 32 {
            fail("the host key is not 32 bytes");
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes);
        seed
    };
    if let Some(hex) = env("ROOTCARD_SITE_SEED") {
        return parse(&hex);
    }
    let path = PathBuf::from(env("ROOTCARD_SITE_KEY_FILE").unwrap_or_else(|| "host.key".into()));
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&Zeroizing::new(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = Zeroizing::new([0u8; 32]);
            random(&mut seed[..]);
            write_secret(&path, &Zeroizing::new(hex_encode(&seed[..])));
            eprintln!("rootcard-site: created a new host key in {}", path.display());
            seed
        }
        Err(e) => fail(format!("{}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn write_secret(path: &std::path::Path, text: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    f.write_all(text.as_bytes())
        .unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
}

#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
}

fn config() -> HostConfig {
    let urls: Vec<String> = env("ROOTCARD_SITE_URLS")
        .unwrap_or_else(|| "https://rootcard.org".into())
        .split(',')
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .collect();
    for u in &urls {
        // The site is the host, so the base URL is an origin: its pages derive it from `location.origin`.
        if u.splitn(4, '/').nth(3).is_some() {
            fail(format!(
                "{u}: the site serves the host at the root of its origin; use a base URL without a path"
            ));
        }
    }
    let realms = env("ROOTCARD_SITE_REALMS")
        .unwrap_or_else(|| "global".into())
        .split(',')
        .map(|r| RealmConfig {
            realm: r.trim().to_string(),
            policy: UsernamePolicy::DEFAULT,
        })
        .collect();
    let retired_keys = env("ROOTCARD_SITE_RETIRED_KEYS")
        .map(|v| {
            v.split(',')
                .map(|k| {
                    hex_decode(k.trim())
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .unwrap_or_else(|| fail("ROOTCARD_SITE_RETIRED_KEYS: 32-byte hex public keys"))
                })
                .collect()
        })
        .unwrap_or_default();
    let config = HostConfig {
        key_seed: host_seed(),
        retired_keys,
        urls,
        realms,
        peers: Vec::new(),
    };
    if config.check().is_err() {
        fail("ROOTCARD_SITE_URLS: base URLs are https:// (http:// only on loopback), without /v0 ([HST-22])");
    }
    config
}

#[tokio::main]
async fn main() {
    let config = config();
    let https = config.urls.iter().all(|u| u.starts_with("https://"));
    let urls = config.urls.join(", ");
    let db_path = PathBuf::from(env("ROOTCARD_SITE_DB").unwrap_or_else(|| "rootcard-site.db".into()));
    let db = Db::open(&db_path).unwrap_or_else(|e| fail(format!("{}: {e}", db_path.display())));
    let host = Host::new(config, db.clone(), db.clone(), db.clone());
    let key = hex_encode(&host.config.key());
    let app = Arc::new(App {
        host,
        db,
        limiter: Limiter::default(),
        trust_proxy: env("ROOTCARD_SITE_TRUST_PROXY").is_some_and(|v| v == "1" || v == "true"),
        https,
    });

    let sweeper = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let a = sweeper.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let t = now();
                if let Err(e) = a.db.sweep(t) {
                    eprintln!("rootcard-site: sweep: {e}");
                }
                a.limiter.sweep(t);
            })
            .await;
        }
    });

    let router = axum::Router::new().fallback(handle).with_state(app);
    let bind = env("ROOTCARD_SITE_BIND").unwrap_or_else(|| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| fail(format!("{bind}: {e}")));
    eprintln!("rootcard-site on {bind}, host key {key}, base URL {urls}");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await
        .unwrap_or_else(|e| fail(e));
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Whether the first path segment is an API version (`/v0`, `/v1`, …): those paths belong to the host protocol.
fn is_api(path: &str) -> bool {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    first.len() >= 2 && first.starts_with('v') && first[1..].bytes().all(|b| b.is_ascii_digit())
}

fn client_address(app: &App, peer: SocketAddr, headers: &HeaderMap) -> String {
    if app.trust_proxy {
        // The reverse proxy appends the address it saw; the last entry is the only one it vouches for.
        if let Some(last) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
        {
            let ip = last.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    peer.ip().to_string()
}

fn security_headers(app: &App, h: &mut HeaderMap) {
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    if app.https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
}

fn json_error(status: u16, code: &str) -> Response {
    let mut r = Response::new(Body::from(format!("{{\"error\":\"{code}\"}}")));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn handle(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    let path = req.uri().path().to_string();
    let mut res = if is_api(&path) {
        api(&app, peer, req).await
    } else {
        site(&app, req.method(), &path, req.headers()).await
    };
    security_headers(&app, res.headers_mut());
    res
}

async fn api(app: &Arc<App>, peer: SocketAddr, req: axum::extract::Request) -> Response {
    let method = req.method().as_str().to_string();
    let path_only = req.uri().path().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| path_only.clone());
    let headers = req.headers().clone();
    let address = client_address(app, peer, &headers);
    // The path relative to the API root, for the rate-limit classes (`/v0/id/register` → `/id/register`).
    let relative = path_only
        .splitn(3, '/')
        .nth(2)
        .map(|p| format!("/{p}"))
        .unwrap_or_default();
    let (class, account) = classify(&method, &relative);
    if let Err(retry) = app.limiter.check(&class, &address, account, now()) {
        let mut r = json_error(429, "rate_limited");
        if let Ok(v) = HeaderValue::from_str(&retry.to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return r;
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_BODY)
    {
        return json_error(413, "too_large");
    }
    let Ok(body) = to_bytes(req.into_body(), MAX_BODY).await else {
        return json_error(413, "too_large");
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let peer_headers = match (
        header("rootcard-peer-key"),
        header("rootcard-peer-time").and_then(|t| t.parse().ok()),
        header("rootcard-peer-sig"),
    ) {
        (Some(key), Some(time), Some(sig)) => Some(PeerHeaders { key, time, sig }),
        _ => None,
    };
    let host_req = HostRequest {
        method,
        path,
        bearer: header("authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_string)),
        peer: peer_headers,
        body: body.to_vec(),
    };
    let a = app.clone();
    let Ok(out) = tokio::task::spawn_blocking(move || route(&a.host, &host_req, now(), &mut random)).await else {
        return json_error(500, "internal");
    };
    let has_body = out.body.is_some();
    let mut r = Response::new(Body::from(out.body.unwrap_or_default()));
    *r.status_mut() = StatusCode::from_u16(out.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    if has_body {
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    for (k, v) in out.headers {
        if let (Ok(k), Ok(v)) = (header::HeaderName::try_from(k), HeaderValue::from_str(&v)) {
            h.append(k, v);
        }
    }
    r
}

/// The file behind a site path: `/` is `index.html`, `/create` is `create.html`.
fn asset_for(path: &str) -> Option<&'static assets::Asset> {
    if path.contains("/_") || path.contains("..") {
        return None;
    }
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return assets::find("/index.html");
    }
    assets::find(p).or_else(|| assets::find(&format!("{p}.html")))
}

async fn site(app: &Arc<App>, method: &Method, path: &str, headers: &HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }
    if path == "/stats.json" {
        let a = app.clone();
        let count = tokio::task::spawn_blocking(move || a.db.count().unwrap_or(0))
            .await
            .unwrap_or(0);
        let mut r = Response::new(Body::from(format!("{{\"cards\":{count}}}")));
        let h = r.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        return r;
    }
    // The key tool is meant to be opened from the user's own disk (rootcard SPEC [PWR-6]): it is only ever downloaded
    // from here, never rendered, so this site never runs a page that asks for a recovery key.
    let download = path == "/download/rootcard-keytool.html";
    let lookup = if download {
        assets::find("/vendor/rootcard/keytool.html")
    } else {
        asset_for(path)
    };
    let (status, asset) = match lookup {
        Some(a) => (StatusCode::OK, a),
        None => match assets::find("/404.html") {
            Some(a) => (StatusCode::NOT_FOUND, a),
            None => {
                let mut r = Response::new(Body::from("not found"));
                *r.status_mut() = StatusCode::NOT_FOUND;
                return r;
            }
        },
    };
    let attachment = download || (asset.path.starts_with("/vendor/") && asset.path.ends_with(".html"));
    let fresh = status == StatusCode::OK
        && headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim() == asset.etag));
    let mut r = if fresh || method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(asset.body))
    };
    *r.status_mut() = if fresh { StatusCode::NOT_MODIFIED } else { status };
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.mime));
    h.insert(header::ETAG, HeaderValue::from_static(asset.etag));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );
    if attachment {
        h.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"rootcard-keytool.html\""),
        );
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_paths() {
        assert!(is_api("/v0/host"));
        assert!(is_api("/v12"));
        assert!(!is_api("/verify"));
        assert!(!is_api("/v"));
        assert!(!is_api("/"));
    }

    #[test]
    fn asset_paths() {
        assert_eq!(asset_for("/").map(|a| a.path), Some("/index.html"));
        assert_eq!(asset_for("/create").map(|a| a.path), Some("/create.html"));
        assert!(asset_for("/_partials/header").is_none());
        assert!(asset_for("/../Cargo.toml").is_none());
    }
}
