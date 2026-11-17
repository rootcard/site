# Review findings and fix plan

A review of this repository (2026-11-17, at commit `0da7ed7`), covering the Rust server, the browser code, the page content
and README, and a local build and run. The deployed rootcard.org was not reviewed (not reachable from the review
environment).

**Baseline:** `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (also with
`ROOTCARD_HOME=homes/example/home.toml`), `cargo build --locked`, `tests/browser/e2e.mjs` and `tests/browser/invite.mjs`
all pass. Security headers match the README; path traversal attempts answer 404.

Tick a box when the fix is merged. Line numbers refer to `0da7ed7`.

## Phase 1: server (security)

- [ ] **1. Anyone can lock an identity out of signing in.** `src/main.rs:505-507` calls `limiter.failed()` for every
  non-2xx answer; `src/limits.rs:84-86` allows 10 `fetch` / 30 `challenge` / 30 `login` failures per identity per hour.
  Reproduced locally: 10 × `POST /v0/id/{account}/fetch` with body `{}` (400 each) make that identity's real `fetch`
  answer 429 for the rest of the hour. Account ids are public.
  *Fix:* count only real guesses (a bad signature after a consumed challenge), not 400s or unknown challenges; consider
  keying failures on (identity, address /64). Add a test.
- [ ] **2. `X-Forwarded-For` can be spoofed.** `src/main.rs:369-380` reads only the first header line and does not parse the
  value as an IP; `Dockerfile:17` turns `ROOTCARD_SITE_TRUST_PROXY=1` on and any private peer is trusted, which
  includes docker-proxy (`172.17.0.1`). Junk values become fresh limiter keys; `[v6]:port` escapes /64 grouping.
  *Fix:* take the last entry across `get_all(...)`, require `IpAddr`, otherwise use the peer; make trusted proxy
  addresses explicit config rather than "any private address".
- [ ] **3. Memory exhaustion through request bodies.** `OPTIONS` has no limit (`src/limits.rs:92`), and every method's
  body (up to `MAX_BODY` = 6 MiB) is read and copied (`src/main.rs:462`, `:479`). No concurrency limit, no body read
  timeout.
  *Fix:* don't read bodies for `GET`/`HEAD`/`OPTIONS` (or cap them small); give `options` an address limit; add a
  concurrency limit and a read timeout.

## Phase 2: browser code

- [ ] **4. The recovery card stays on the page.** `web/js/create.js:174-184` (`startOver`) and the success path after
  `:205` leave the card in `#cardText`, `#printArea` and `reg`. Ctrl+P afterwards prints the secret recovery card.
  *Fix:* clear both elements and set `reg = null` after registration and in `startOver()`.
- [ ] **5. A dead worker hangs the page.** `web/js/common.js:184-187`: `onerror` rejects pending calls but keeps the worker,
  so later `work()` calls never settle.
  *Fix:* `worker.terminate(); worker = undefined;` in `onerror`; optionally a timeout.
- [ ] **6. Activate can run twice.** `web/js/create.js:158-163`, `:187-189`: `#saved` stays live during `busy`, so
  untick/retick re-enables Activate while Argon2id runs and a second registration is built. (Not fully traced.)
  *Fix:* an in-flight flag checked by `updateActivate`, or disable `#saved` in `busy`.
- [ ] **7. Card page: a slow lookup overwrites a proof result.** `web/js/card.js:319-341`, `show()` at `:196-252`: the
  stamp disappears while `#proofStatus` still says valid.
  *Fix:* one run counter for lookup and proof, checked after every await (also inside `show()`).
- [ ] **8. Invite accepted from the query string.** `web/js/create.js:28` falls back to `?invite=`, which reaches server
  and proxy logs; the README promises `#invite=` only.
  *Fix:* drop the query-string fallback.

## Phase 3: content and docs

- [ ] **9. Misleading FAQ on linking.** `web/index.html:119-121` implies services cannot link accounts; every service sees
  the same account id and handle (`developers.html:38`).
  *Fix:* say so; separate identities for accounts that must not be linked.
- [ ] **10. The account file goes stale.** `create.html:86-88`, `index.html:113-114`, `policy.html:192` say the account
  file plus the recovery card "moves everything".
  *Fix:* say to download a fresh account file after each change (and which password opens it); repeat on `/account`.
- [ ] **11. Copy that is wrong for invite-only and closed homes.** "Use the key tool to move here" (`keytool.html:180-181`,
  `account.html:48-50`) fails there (README:113-114). "Public home" in `index.html:4-5`, `policy.html:5`, `:14`,
  `developers.html:25-26`, `_partials/head.html:11`.
  *Fix:* `<!--#if open-->` markers, or neutral wording.
- [ ] **12. Links to left-out pages remain.** README:121 says left-out pages are dropped from other pages' links, but
  unmarked links exist: `/keytool` (`account.html:46`, `:219`, `policy.html:178`), `/account` (`policy.html:176`,
  `create.html:90`), `/card` (`create.html:92`, `account.html:78`, `:117`, `:201`, `developers.html:42`, `:152`).
  The test `closed_minimal_site` (`src/pages.rs:231`) only checks `/create`, `/developers`, `/rootcard`.
  *Fix:* add markers; extend the test to every page that can be left out.
- [ ] **13. "Run your own home" is missing steps** (README:43-76): register first, then set `operator` /
  `operator_account` and rebuild; a `docker run` example (`-p`, `-v /data`, reverse proxy/TLS, DNS); override
  `ROOTCARD_SITE_URLS` to test locally; replace `og.png`.
- [ ] **14.** `index.html:112-114`: say plainly that without the recovery card the identity is lost when the home goes away.

## Phase 4: low

Server and build:
- [ ] Storage error text reaches clients (`host_response`, `src/main.rs:566`): return `{"error":"storage"}`, log the detail.
- [ ] A poisoned limiter mutex disables all limits (`src/limits.rs:108-110`): use `unwrap_or_else(|e| e.into_inner())`.
- [ ] The database and WAL files are created with the umask (`src/store.rs:67-69`): create with 0600. Consider
  `synchronous = FULL` (`store.rs:20`).
- [ ] The invite compare returns early on length (`src/registration.rs:55-57`): compare SHA-256 digests.
- [ ] Overlay pages in subdirectories are dropped from the sitemap (`src/pages.rs:176-188`); `foo/index.html` canonical
  `/foo` is a 404.
- [ ] With `keytool` left out, `/download/rootcard-keytool.html` is still served (`src/main.rs:683-686`).
- [ ] `.dockerignore` does not exclude `invites.txt`; base images pinned by tag, not digest; CI toolchain follows
  `stable`; `actions/checkout` without `persist-credentials: false`.

Browser:
- [ ] Secrets cloned into the worker are never wiped (`account.js:69`, `:588`, `worker.js:296-302`).
- [ ] An auto-filled challenge stays and marks a later valid proof invalid (`card.js:530-536`).
- [ ] A proof sent with another identity's log is stamped on that identity's card (`card.js:169-191`).
- [ ] "Print" counts as saved even if cancelled (`create.js:169-173`).
- [ ] Link check results are cached by link, not account (`account.js:326`, `:376-378`).
- [ ] "Check all links" swallows non-`RootcardError` errors (`card.js:289-306`).
- [ ] `tilt()` adds listeners on every `show()` (`account.js:198`).

Accessibility:
- [ ] Focus is lost on step changes and sign-in/out (`create.js:67-77`, `account.js:113`, `:156`).
- [ ] `<label>` without a control (`account.html:119`).
- [ ] Tabs lack `aria-controls` / `role="tabpanel"` (`account.html:63-69`).
- [ ] `aria-label` on a plain `<div>` (`index.html:33`).
- [ ] `<h4>` in the footer skips levels.
- [ ] Empty `<p>` spacers.

Text:
- [ ] The README route table lacks `POST /invite`, `/stats.json`, `/sitemap.xml`, `/download/…`; `Hexagon#DNTT` is
  hardcoded at README:36.
- [ ] Overclaims: "no server can … lock you out" (`index.html:5`); "Closing the tab signs you out" (`account.html:59`;
  the server session lives up to 24 h).
- [ ] `policy.html` "What is stored" omits the invites file.
- [ ] "Run your own host" vs "home" (`developers.html:23`); "like on any home" → "as" (`developers.html:78`,
  `policy.html:187-189`).
- [ ] The `/card` description says "any rootcard ID card" but the body says identities homed here.

## Checked and fine

- XSS: values go through `textContent`.
- CSP: no inline script or style.
- Proofs: an invalid proof cannot show as valid.
- SQL: queries are parameterized.
- Registration: the gate cannot be bypassed by path tricks.
- Files: the host key and invites file are created 0600.
- Docker: the container runs as non-root.
- Versions: 0.3.5 everywhere.
