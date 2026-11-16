//! Conditional parts of the pages: `<!--#if FLAG-->…<!--#else-->…<!--#endif-->`, `FLAG` or `!FLAG`.
//!
//! The pages are embedded at build time, but which pages a home serves and whether it takes registrations are chosen
//! when the server starts (`ROOTCARD_SITE_PAGES`, `ROOTCARD_SITE_REGISTRATION`). The server applies these markers once
//! at start, so a link to a page that is not served, or a "Create a card" button on a closed home, is not in the page
//! at all. A flag is the name of a page (`developers`: `/developers` is served) or a registration mode (`open`,
//! `invite`, `closed`). Markers do not nest. build.rs checks every page with [`flags`], so a malformed marker or an
//! unknown flag fails the build, not the server.
//!
//! Shared by build.rs and the server (`#[path]`), so it uses nothing but the standard library.

const IF: &str = "<!--#if ";
const ELSE: &str = "<!--#else-->";
const ENDIF: &str = "<!--#endif-->";
const STRAY: &str = "<!--#else--> or <!--#endif--> without <!--#if";

/// The registration modes, which are flags too.
pub const MODES: [&str; 3] = ["open", "invite", "closed"];

/// One conditional block of `text`: byte ranges of the whole block, the flag (with its `!`), the kept parts.
struct Block<'a> {
    start: usize,
    end: usize,
    flag: &'a str,
    then: &'a str,
    otherwise: &'a str,
}

fn next_block(text: &str, from: usize) -> Result<Option<Block<'_>>, String> {
    let Some(i) = text[from..].find(IF).map(|i| i + from) else {
        if text[from..].contains(ENDIF) || text[from..].contains(ELSE) {
            return Err(STRAY.into());
        }
        return Ok(None);
    };
    if text[from..i].contains(ENDIF) || text[from..i].contains(ELSE) {
        return Err(STRAY.into());
    }
    let head_end = text[i..].find("-->").map(|j| i + j).ok_or("unterminated <!--#if")?;
    let flag = text[i + IF.len()..head_end].trim();
    let body_start = head_end + 3;
    let close = text[body_start..]
        .find(ENDIF)
        .map(|j| body_start + j)
        .ok_or_else(|| format!("<!--#if {flag}--> without <!--#endif-->"))?;
    let body = &text[body_start..close];
    if body.contains(IF) {
        return Err(format!("<!--#if {flag}-->: markers do not nest"));
    }
    let (then, otherwise) = match body.split_once(ELSE) {
        Some((t, o)) if !o.contains(ELSE) => (t, o),
        Some(_) => return Err(format!("<!--#if {flag}--> with two <!--#else-->")),
        None => (body, ""),
    };
    let name = flag.strip_prefix('!').unwrap_or(flag);
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "<!--#if {flag}-->: a flag is a page name or a registration mode"
        ));
    }
    Ok(Some(Block {
        start: i,
        end: close + ENDIF.len(),
        flag,
        then,
        otherwise,
    }))
}

/// The flags `text` uses (without `!`), or what is wrong with its markers.
pub fn flags(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(b) = next_block(text, at)? {
        out.push(b.flag.trim_start_matches('!').to_string());
        at = b.end;
    }
    Ok(out)
}

/// `text` with every block replaced by the part its flag selects; `on(flag)` says which flags are set.
pub fn apply(text: &str, on: &dyn Fn(&str) -> bool) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(b) = next_block(text, at)? {
        out.push_str(&text[at..b.start]);
        let set = match b.flag.strip_prefix('!') {
            Some(f) => !on(f),
            None => on(b.flag),
        };
        out.push_str(if set { b.then } else { b.otherwise });
        at = b.end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}
