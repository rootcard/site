//! Embeds `web/` into the binary, configured for one home by `home.toml` (or the file named by `ROOTCARD_HOME`).
//!
//! - The home's `overlay` directory, if any, replaces or adds files of `web/` by path, partials included.
//! - HTML files get their `<!--#include name-->` directives replaced by `_partials/name.html`, `{{rootcard_version}}` /
//!   `{{keytool_sha256}}` by the vendored package's version and the SHA-256 of its `keytool.html`, and `{{home.*}}` by
//!   the home's values, HTML-escaped.
//! - `{{page.url}}`, `{{page.title}}` and `{{page.description}}` are the page's canonical URL (`/create.html` is
//!   `<url>/create`), its `<title>` and its meta description, for the canonical link and the Open Graph tags.
//! - `robots.txt` gets the `{{home.*}}` values too (for its `Sitemap:` line).
//! - `/js/home-config.js` (the home's values for the scripts), `/site.webmanifest` and `/sitemap.xml` (every page
//!   without `<meta name="robots" content="noindex">`) are generated.
//! - `ROOTCARD_HOME_URL` and `ROOTCARD_HOME_REALM` are set for the server's defaults.
//!
//! Every asset gets a strong ETag (its SHA-256).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Every file under `dir`, by its path relative to `root` (with `/`).
fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for p in entries.map(|e| e.expect("entry").path()) {
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            let rel = p
                .strip_prefix(root)
                .expect("prefix")
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, p);
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A JSON string literal, safe inside a script (`<` and `>` escaped).
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '<' || c == '>' || c == '&' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn percent_encode(s: &str) -> String {
    s.bytes().fold(String::new(), |mut o, b| {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            let _ = write!(o, "%{b:02X}");
        }
        o
    })
}

/// The home of this build, from its `home.toml`.
struct Home {
    name: String,
    url: String,
    host: String,
    realm: String,
    operator: String,
    source: String,
    wordmark_html: String,
    overlay: Option<PathBuf>,
}

fn home(path: &Path) -> Home {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let t: toml::Table = text.parse().unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let known = ["name", "url", "realm", "operator", "source", "wordmark_html", "overlay"];
    if let Some(k) = t.keys().find(|k| !known.contains(&k.as_str())) {
        panic!("{}: unknown key {k:?}", path.display());
    }
    let get = |k: &str| {
        t.get(k).map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("{}: {k} is not a string", path.display()))
                .trim()
                .to_string()
        })
    };
    let need = |k: &str| {
        get(k)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| panic!("{}: {k} is required", path.display()))
    };
    let name = need("name");
    let url = need("url").trim_end_matches('/').to_string();
    let host = match url.split_once("://") {
        Some(("https" | "http", h)) if !h.is_empty() && !h.contains('/') => h.to_string(),
        _ => panic!(
            "{}: url is an origin such as https://id.example.com, without a path",
            path.display()
        ),
    };
    let realm = need("realm");
    let operator = need("operator");
    if !operator.contains('#') {
        panic!("{}: operator is a rootcard handle such as Name#TAG", path.display());
    }
    Home {
        wordmark_html: get("wordmark_html")
            .filter(|w| !w.is_empty())
            .unwrap_or_else(|| html_escape(&name)),
        name,
        url,
        host,
        realm,
        operator,
        source: need("source"),
        overlay: get("overlay").map(|o| path.parent().unwrap_or(Path::new(".")).join(o)),
    }
}

impl Home {
    fn substitute(&self, text: &str) -> String {
        text.replace("{{home.name}}", &html_escape(&self.name))
            .replace("{{home.url}}", &html_escape(&self.url))
            .replace("{{home.host}}", &html_escape(&self.host))
            .replace("{{home.realm}}", &html_escape(&self.realm))
            .replace("{{home.operator}}", &html_escape(&self.operator))
            .replace("{{home.operator_query}}", &percent_encode(&self.operator))
            .replace("{{home.source}}", &html_escape(&self.source))
            .replace("{{home.wordmark}}", &self.wordmark_html)
            .replace("{{home.jsonld}}", &self.json_ld())
    }

    /// Structured data for the home page: the site and who publishes it, so search engines show its name and logo.
    fn json_ld(&self) -> String {
        format!(
            "<script type=\"application/ld+json\">{{\"@context\":\"https://schema.org\",\"@graph\":[\
             {{\"@type\":\"WebSite\",\"name\":{n},\"url\":{u}}},\
             {{\"@type\":\"Organization\",\"name\":{n},\"url\":{u},\"logo\":{l},\"sameAs\":[{s}]}}]}}</script>",
            n = json_string(&self.name),
            u = json_string(&format!("{}/", self.url)),
            l = json_string(&format!("{}/img/icon-512.png", self.url)),
            s = json_string(&self.source)
        )
    }

    /// The canonical URL of the page at `rel` (`index.html` is the root, `create.html` is `/create`).
    fn page_url(&self, rel: &str) -> String {
        let path = rel.strip_suffix(".html").unwrap_or(rel);
        let path = if path == "index" {
            ""
        } else {
            path.strip_suffix("/index").unwrap_or(path)
        };
        format!("{}/{path}", self.url)
    }

    fn config_js(&self) -> String {
        format!(
            "// Generated by build.rs from home.toml: the values of this home for the scripts.\n\
             export const HOME = Object.freeze({{ name: {}, url: {}, host: {}, realm: {}, operator: {} }});\n",
            json_string(&self.name),
            json_string(&self.url),
            json_string(&self.host),
            json_string(&self.realm),
            json_string(&self.operator)
        )
    }

    fn manifest(&self) -> String {
        format!(
            "{{\"name\":{n},\"short_name\":{n},\"start_url\":\"/\",\"display\":\"standalone\",\"background_color\":\"#0a0f14\",\
             \"theme_color\":\"#0a0f14\",\"icons\":[{{\"src\":\"/img/logo.svg\",\"sizes\":\"any\",\"type\":\"image/svg+xml\"}},\
             {{\"src\":\"/img/icon-192.png\",\"sizes\":\"192x192\",\"type\":\"image/png\"}},\
             {{\"src\":\"/img/icon-512.png\",\"sizes\":\"512x512\",\"type\":\"image/png\"}}]}}\n",
            n = json_string(&self.name)
        )
    }
}

/// The text between `open` and the next `close` in `text`.
fn between<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = text.find(open)? + open.len();
    let len = text[start..].find(close)?;
    Some(&text[start..start + len])
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "json" | "webmanifest" => "application/json",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn main() {
    println!("cargo:rerun-if-changed=web");
    println!("cargo:rerun-if-env-changed=ROOTCARD_HOME");
    let home_path = PathBuf::from(std::env::var("ROOTCARD_HOME").unwrap_or_else(|_| "home.toml".into()));
    println!("cargo:rerun-if-changed={}", home_path.display());
    let home = home(&home_path);
    println!("cargo:rustc-env=ROOTCARD_HOME_URL={}", home.url);
    println!("cargo:rustc-env=ROOTCARD_HOME_REALM={}", home.realm);
    println!("cargo:rustc-env=ROOTCARD_HOME_NAME={}", home.name);

    let web = Path::new("web");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let pkg = fs::read_to_string(web.join("vendor/rootcard/package.json")).expect("vendored package.json");
    let version = pkg
        .split("\"version\"")
        .nth(1)
        .and_then(|r| r.split('"').nth(1))
        .expect("version")
        .to_string();
    let keytool = fs::read(web.join("vendor/rootcard/keytool.html")).expect("vendored keytool.html");
    let keytool_sha = hex(&Sha256::digest(&keytool));

    let mut files = BTreeMap::new();
    walk(web, web, &mut files);
    if let Some(dir) = &home.overlay {
        println!("cargo:rerun-if-changed={}", dir.display());
        walk(dir, dir, &mut files);
    }
    let partial = |name: &str| -> String {
        let rel = format!("_partials/{name}.html");
        let p = files.get(&rel).unwrap_or_else(|| panic!("missing partial {name}"));
        fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    };

    let mut assets: Vec<(String, Vec<u8>)> = Vec::new();
    let mut sitemap = Vec::new();
    for (rel, f) in &files {
        if rel.starts_with("_partials/") {
            continue;
        }
        let mut bytes = fs::read(f).expect("read asset");
        if rel.ends_with(".html") && !rel.starts_with("vendor/") {
            let mut text = String::from_utf8(bytes).expect("utf-8 html");
            while let Some(start) = text.find("<!--#include ") {
                let end = start + text[start..].find("-->").expect("unterminated include") + 3;
                let name = text[start + 13..end - 3].trim().to_string();
                text.replace_range(start..end, partial(&name).trim_end());
            }
            text = home
                .substitute(&text)
                .replace("{{rootcard_version}}", &version)
                .replace("{{keytool_sha256}}", &keytool_sha);
            let url = html_escape(&home.page_url(rel));
            if text.contains("{{page.") {
                // Already HTML-escaped text, used again in attribute values.
                let title = between(&text, "<title>", "</title>")
                    .unwrap_or_else(|| panic!("web/{rel}: no <title>"))
                    .trim()
                    .replace('"', "&quot;");
                let description = between(&text, "<meta name=\"description\" content=\"", "\"")
                    .unwrap_or_else(|| panic!("web/{rel}: no meta description"))
                    .to_string();
                text = text
                    .replace("{{page.url}}", &url)
                    .replace("{{page.title}}", &title)
                    .replace("{{page.description}}", &description);
            }
            if !text.contains("<meta name=\"robots\" content=\"noindex") {
                sitemap.push(url);
            }
            bytes = text.into_bytes();
        } else if rel == "robots.txt" {
            bytes = home
                .substitute(&String::from_utf8(bytes).expect("utf-8 robots.txt"))
                .into_bytes();
        }
        if (rel.ends_with(".html") && !rel.starts_with("vendor/")) || rel == "robots.txt" {
            let text = String::from_utf8_lossy(&bytes);
            if let Some(i) = text.find("{{") {
                let token: String = text[i..].chars().take(40).collect();
                panic!("web/{rel}: unknown placeholder {token}");
            }
        }
        assets.push((rel.clone(), bytes));
    }
    let sitemap = sitemap.iter().fold(
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"),
        |mut s, u| {
            let _ = writeln!(s, "  <url><loc>{u}</loc></url>");
            s
        },
    ) + "</urlset>\n";
    for (rel, body) in [
        ("js/home-config.js", home.config_js()),
        ("site.webmanifest", home.manifest()),
        ("sitemap.xml", sitemap),
    ] {
        if !files.contains_key(rel) {
            assets.push((rel.to_string(), body.into_bytes()));
        }
    }

    let mut table = String::from("pub static ASSETS: &[Asset] = &[\n");
    for (rel, bytes) in assets {
        let etag = hex(&Sha256::digest(&bytes)[..16]);
        let target = out.join("web").join(&rel);
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        fs::write(&target, &bytes).expect("write asset");
        let _ = writeln!(
            table,
            "    Asset {{ path: {:?}, body: include_bytes!({:?}), mime: {:?}, etag: {:?} }},",
            format!("/{rel}"),
            target.to_string_lossy(),
            mime(&rel),
            format!("\"{etag}\"")
        );
    }
    table.push_str("];\n");
    fs::write(out.join("assets.rs"), table).expect("write assets.rs");
}
