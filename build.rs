//! Embeds `web/` into the binary. HTML files get their `<!--#include name-->` directives replaced by
//! `web/_partials/name.html`, and `{{rootcard_version}}` / `{{keytool_sha256}}` by the vendored package's version and the
//! SHA-256 of its `keytool.html`. Every asset gets a strong ETag (its SHA-256).

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read web/")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "_partials") {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
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
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn main() {
    println!("cargo:rerun-if-changed=web");
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

    let mut files = Vec::new();
    walk(web, &mut files);
    let mut table = String::from("pub static ASSETS: &[Asset] = &[\n");
    for f in files {
        let rel = f
            .strip_prefix(web)
            .expect("prefix")
            .to_string_lossy()
            .replace('\\', "/");
        let mut bytes = fs::read(&f).expect("read asset");
        if rel.ends_with(".html") && !rel.starts_with("vendor/") {
            let mut text = String::from_utf8(bytes).expect("utf-8 html");
            while let Some(start) = text.find("<!--#include ") {
                let end = start + text[start..].find("-->").expect("unterminated include") + 3;
                let name = text[start + 13..end - 3].trim().to_string();
                let part = fs::read_to_string(web.join("_partials").join(format!("{name}.html")))
                    .unwrap_or_else(|_| panic!("missing partial {name}"));
                text.replace_range(start..end, part.trim_end());
            }
            text = text
                .replace("{{rootcard_version}}", &version)
                .replace("{{keytool_sha256}}", &keytool_sha);
            bytes = text.into_bytes();
        }
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
