//! The pages this server serves, chosen when it starts: `ROOTCARD_SITE_PAGES` and the registration mode.
//!
//! Every page of the build is embedded; at start the server keeps the chosen ones, applies the pages' `<!--#if-->`
//! markers (`src/cond.rs`) so that nothing links to a page that is not served, and drops those pages from the sitemap.
//! A page that is not served answers 404. The home page and the not-found page are always served. `create` is not served
//! when registration is closed.

use crate::assets::{ASSETS, Asset};
use crate::cond;
use crate::registration::Mode;

/// `ROOTCARD_SITE_PAGES=minimal`: what a home needs for the identities it holds, without the pages about rootcard.
pub const MINIMAL: [&str; 5] = ["account", "card", "create", "keytool", "policy"];

/// The pages that are always served.
const ALWAYS: [&str; 2] = ["index", "404"];

pub struct Site {
    assets: Vec<Asset>,
    /// The names of the pages served (`create` for `/create`), the home page and the not-found page included.
    pub pages: Vec<String>,
}

/// The name of the page at asset path `path` (`/create.html` → `create`), if it is one of the site's pages.
fn page_name(path: &str) -> Option<&str> {
    path.strip_prefix('/')?
        .strip_suffix(".html")
        .filter(|n| !n.contains('/'))
}

/// Every page of the build that a home can choose, in the order of the asset table.
pub fn choosable() -> Vec<&'static str> {
    ASSETS
        .iter()
        .filter_map(|a| page_name(a.path))
        .filter(|n| !ALWAYS.contains(n))
        .collect()
}

/// The pages chosen by `ROOTCARD_SITE_PAGES`: `all` (the default), `minimal`, page names, and `-name` to leave one out.
/// A list that starts with `-name` starts from all.
pub fn select(value: Option<&str>) -> Result<Vec<String>, String> {
    let all = choosable();
    let items: Vec<&str> = value
        .unwrap_or("all")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut chosen: Vec<&str> = if items.first().is_none_or(|i| i.starts_with('-')) {
        all.clone()
    } else {
        Vec::new()
    };
    for item in items {
        let (remove, name) = match item.strip_prefix('-') {
            Some(n) => (true, n),
            None => (false, item),
        };
        let names: Vec<&str> = match name {
            "all" => all.clone(),
            "minimal" => MINIMAL.iter().copied().filter(|n| all.contains(n)).collect(),
            n if all.contains(&n) => vec![n],
            n if ALWAYS.contains(&n) => {
                return Err(format!("ROOTCARD_SITE_PAGES: {n} is always served"));
            }
            n => {
                return Err(format!(
                    "ROOTCARD_SITE_PAGES: no page {n:?}; the pages are {}, or all or minimal",
                    all.join(", ")
                ));
            }
        };
        if remove {
            chosen.retain(|c| !names.contains(c));
        } else {
            for n in names {
                if !chosen.contains(&n) {
                    chosen.push(n);
                }
            }
        }
    }
    Ok(chosen.into_iter().map(str::to_string).collect())
}

/// The WebPulse client id of `ROOTCARD_SITE_WEBPULSE_ID`: 24 lowercase hex digits, as in the tracker's script URL
/// (`https://track.webpulseanalytics.com/client/<id>`). `None` when unset; anything else is an error, so a mistyped id
/// stops the server instead of loading a script from a wrong address.
pub fn webpulse_id(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(v) = value.map(str::trim) else {
        return Ok(None);
    };
    if v.len() == 24 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(Some(v.to_string()))
    } else {
        Err("ROOTCARD_SITE_WEBPULSE_ID: the WebPulse client id is 24 lowercase hex digits".into())
    }
}

/// FNV-1a: tells the ETags of differently configured pages apart (the content is fixed by the build and the flags).
fn fnv(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl Site {
    /// The site with `chosen` pages (from [`select`]) for a home in registration `mode`; `home_url` is the base of the
    /// sitemap's addresses. `webpulse` is the WebPulse tracker's client id (from [`webpulse_id`]): with one, the
    /// `webpulse` flag is set and `{{webpulse.id}}` is that id.
    pub fn new(chosen: &[String], mode: Mode, home_url: &str, webpulse: Option<&str>) -> Result<Site, String> {
        let mut pages: Vec<String> = ALWAYS.iter().map(|s| s.to_string()).collect();
        pages.extend(
            chosen
                .iter()
                .filter(|p| !(mode == Mode::Closed && *p == "create"))
                .cloned(),
        );
        let on = |flag: &str| {
            flag == mode.name() || (flag == "webpulse" && webpulse.is_some()) || pages.iter().any(|p| p == flag)
        };
        let mut fingerprint = format!("{}:{}:", mode.name(), webpulse.unwrap_or(""));
        let mut sorted = pages.clone();
        sorted.sort();
        fingerprint.push_str(&sorted.join(","));
        let tag = format!("{:016x}", fnv(&fingerprint));
        let mut assets = Vec::with_capacity(ASSETS.len());
        for a in ASSETS {
            if let Some(name) = page_name(a.path)
                && !pages.iter().any(|p| p == name)
            {
                continue;
            }
            let text = (a.path.ends_with(".html") && !a.path.starts_with("/vendor/"))
                .then(|| std::str::from_utf8(a.body).ok())
                .flatten();
            let changed = match (a.path, text) {
                (_, Some(t)) if t.contains("<!--#") => {
                    let t = cond::apply(t, &on).map_err(|e| format!("{}: {e}", a.path))?;
                    Some(t.replace("{{webpulse.id}}", webpulse.unwrap_or("")))
                }
                ("/sitemap.xml", _) => Some(sitemap(a.body, home_url, &pages)),
                _ => None,
            };
            assets.push(match changed {
                Some(body) => Asset {
                    path: a.path,
                    body: Box::leak(body.into_bytes().into_boxed_slice()),
                    mime: a.mime,
                    etag: String::leak(format!("{}-{tag}\"", a.etag.trim_end_matches('"'))),
                },
                None => Asset { ..*a },
            });
        }
        Ok(Site { assets, pages })
    }

    pub fn find(&self, path: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.path == path)
    }

    #[cfg(test)]
    pub fn serves(&self, page: &str) -> bool {
        self.pages.iter().any(|p| p == page)
    }

    /// The file behind a site path: `/` is `index.html`, `/create` is `create.html`.
    pub fn asset_for(&self, path: &str) -> Option<&Asset> {
        if path.contains("/_") || path.contains("..") {
            return None;
        }
        let p = path.trim_end_matches('/');
        if p.is_empty() {
            return self.find("/index.html");
        }
        self.find(p).or_else(|| self.find(&format!("{p}.html")))
    }

    /// The one address of a page reached another way: `/create.html` and `/create/` are `/create`, `/index.html` and
    /// `/index` are `/`. `None` for a path that is already canonical or is not a page.
    pub fn canonical_path(&self, path: &str) -> Option<String> {
        let asset = self.asset_for(path)?;
        if !asset.path.ends_with(".html") || asset.path.starts_with("/vendor/") || asset.path == "/404.html" {
            return None;
        }
        let page = asset.path.trim_end_matches(".html");
        let page = if page == "/index" { "/" } else { page };
        (path != page).then(|| page.to_string())
    }
}

/// The sitemap without the pages that are not served.
fn sitemap(body: &[u8], home_url: &str, pages: &[String]) -> String {
    String::from_utf8_lossy(body)
        .lines()
        .filter(|l| {
            let Some(loc) = l.split("<loc>").nth(1).and_then(|r| r.split("</loc>").next()) else {
                return true;
            };
            let name = loc.strip_prefix(home_url).unwrap_or(loc).trim_matches('/');
            name.is_empty() || pages.iter().any(|p| p == name)
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selections() {
        let all = choosable();
        assert!(all.contains(&"create") && all.contains(&"developers") && !all.contains(&"index"));
        assert_eq!(select(None).expect("all").len(), all.len());
        assert_eq!(select(Some("all")).expect("all").len(), all.len());
        let m = select(Some("minimal")).expect("minimal");
        assert!(m.contains(&"account".to_string()) && !m.contains(&"developers".to_string()));
        let less = select(Some("-developers,-rootcard")).expect("less");
        assert_eq!(less.len(), all.len() - 2);
        assert_eq!(select(Some("card,policy")).expect("two"), ["card", "policy"]);
        assert!(select(Some("nope")).is_err());
        assert!(select(Some("index")).is_err());
    }

    fn page<'a>(site: &'a Site, path: &str) -> &'a str {
        std::str::from_utf8(site.find(path).unwrap_or_else(|| panic!("{path}")).body).expect("utf-8")
    }

    #[test]
    fn full_site() {
        let site = Site::new(&select(None).expect("all"), Mode::Open, crate::HOME_URL, None).expect("site");
        for a in &site.assets {
            if a.path.ends_with(".html") && !a.path.starts_with("/vendor/") {
                assert!(
                    !std::str::from_utf8(a.body).expect("utf-8").contains("<!--#"),
                    "{}",
                    a.path
                );
            }
        }
        let index = page(&site, "/index.html");
        assert!(index.contains("href=\"/create\"") && index.contains("href=\"/developers\""));
        assert!(!page(&site, "/create.html").contains("id=\"invite\""));
        assert!(site.find("/developers.html").is_some());
    }

    #[test]
    fn closed_minimal_site() {
        let site = Site::new(
            &select(Some("minimal")).expect("minimal"),
            Mode::Closed,
            crate::HOME_URL,
            None,
        )
        .expect("site");
        assert!(!site.serves("create") && !site.serves("developers") && site.serves("account"));
        assert!(site.asset_for("/create").is_none() && site.asset_for("/developers").is_none());
        assert_eq!(site.canonical_path("/create.html"), None);
        // No page links to a page that is not served.
        for a in &site.assets {
            if a.path.ends_with(".html") && !a.path.starts_with("/vendor/") {
                let text = std::str::from_utf8(a.body).expect("utf-8");
                for gone in ["/create", "/developers", "/rootcard\""] {
                    assert!(!text.contains(&format!("href=\"{gone}")), "{} links to {gone}", a.path);
                }
            }
        }
        let sitemap = page(&site, "/sitemap.xml");
        assert!(sitemap.contains("<urlset") && sitemap.contains("</urlset>"));
        assert!(!sitemap.contains("/create<") && !sitemap.contains("/developers<"));
        // A different configuration is a different ETag.
        let full = Site::new(&select(None).expect("all"), Mode::Open, crate::HOME_URL, None).expect("site");
        assert_ne!(
            site.find("/index.html").map(|a| a.etag),
            full.find("/index.html").map(|a| a.etag)
        );
    }

    #[test]
    fn invite_site() {
        let site = Site::new(&select(None).expect("all"), Mode::Invite, crate::HOME_URL, None).expect("site");
        assert!(page(&site, "/create.html").contains("id=\"invite\""));
        assert!(page(&site, "/index.html").contains("href=\"/create\""));
    }

    #[test]
    fn webpulse() {
        let id = "6aed1d8c6c10731d6a70cca2";
        assert_eq!(webpulse_id(None), Ok(None));
        assert_eq!(webpulse_id(Some(id)), Ok(Some(id.to_string())));
        for bad in [
            "",
            "6aed1d8c",
            "6AED1D8C6C10731D6A70CCA2",
            "6aed1d8c6c10731d6a70cca2/../x",
            "6aed1d8c6c10731d6a70ccag",
        ] {
            assert!(webpulse_id(Some(bad)).is_err(), "{bad:?}");
        }
        let off = Site::new(&select(None).expect("all"), Mode::Open, crate::HOME_URL, None).expect("site");
        let on = Site::new(&select(None).expect("all"), Mode::Open, crate::HOME_URL, Some(id)).expect("site");
        for path in ["/index.html", "/create.html", "/404.html"] {
            assert!(!page(&off, path).contains("webpulse"), "{path}");
            assert!(!page(&off, path).contains("{{"), "{path}");
            let script =
                format!("<script async src=\"https://track.webpulseanalytics.com/client/{id}\" type=\"module\">");
            assert!(page(&on, path).contains(&script), "{path}");
            assert_ne!(off.find(path).expect("page").etag, on.find(path).expect("page").etag);
        }
    }
}
