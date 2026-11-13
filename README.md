# rootcard home site

A complete rootcard **home** in one Rust binary: the site people use (create a card, sign in, look up and verify, the
key tool download) and the host behind it. It runs [rootcard.org](https://rootcard.org), the public home for the
`global` realm of [rootcard](https://github.com/rootcard/rootcard), and it is a template for any other home: one file,
`home.toml`, says which home a build is for (see [Run your own home](#run-your-own-home)).

One Rust binary serves both:

- **The site of this home**: what rootcard.org is, what rootcard is and how it works, the comparison, the developer guide
  and the key tool download. rootcard.org is one home among many, not a central rootcard server, and the pages say so.
- **A home host**: the rootcard HTTP binding (`https://rootcard.org/v0/…`, rootcard's `docs/HOST_PROTOCOL.md`) through
  `rootcard_host::http::route`, with SQLite storage and the recommended rate limits. Anyone can get an ID card with
  rootcard.org as home from the browser, without running a server or the CLI.

The browser does all the cryptography with the published npm package (`web/vendor/rootcard`, `rootcard@0.3.4`
unchanged, integrity checked against the registry). The server never sees a password or a recovery key.

## What the pages do

| Page | What |
|---|---|
| `/` | Home page: what rootcard.org is (one home among many), getting started, questions |
| `/rootcard` | About the rootcard standard: how it works, power levels, comparison |
| `/create` | Registration ([CLT-1]): the recovery key is made in a Web Worker, the user must download or print the recovery card before anything is sent, then the registration is built (Argon2id off the main thread) and posted. The log is fetched back and verified |
| `/account` | Sign-in ([LGN-1]: lookup, log, locks, fetch, local unlock, login), then the low-power functions: public profile, private data in the vault, password change ([CHG-1]), linked accounts ([LNK-4]: the link token, add with a check from the browser first, remove), account file export, account proofs ([PRF-1]), including statement proofs ([PRF-5]) shared as a `/card#proof=…` link. The unlocked vault lives only in page memory; leaving the page logs the session out |
| `/card?h=Name%23TAG` | Public lookup: resolves a handle and verifies log and profile in the browser. Proof verification ([PRF-4]): a pasted proof (bare, or `{ proof, log, statement }`) is checked against the newest of the log sent with it and the log at this home ([VER-4]), and its status is stamped on the ID card: valid for you, a signed public statement, a valid signature with something unchecked, or invalid. `/card#proof=<base64url>` links carry a statement proof in the fragment (never sent to the server). Linked accounts of the profile ([LNK-3]) are listed and, when the viewer asks, checked in the viewer's browser ([LNK-9]–[LNK-12]) |
| `/keytool` | Explains the key tool and offers the npm package's `keytool.html` as a **download only** (never rendered from this origin), with its SHA-256. The site never asks for a recovery key ([PWR-6]) |
| `/developers` | Integration guide and this home's API |
| `/.well-known/rootcard` | The host pointer ([HST-23]) naming this origin as the base URL, so clients can be given the bare domain |
| `/.well-known/rootcard-link` | With `operator_account` in `home.toml`: the operator's link token ([LNK-5]), with open CORS, so the operator's identity can list this home's domain as its website (service `web`) |
| `/policy` | Operator (`Hexagon#DNTT`), the live host key from `/v0/host`, what is stored and for how long, how to leave |

Every page is served with a strict CSP (`script-src 'self'`, no inline script or style, nothing third-party), `nosniff`,
`no-referrer`, `frame-ancestors 'none'` and HSTS on https. `/card` and `/account` may also fetch (`connect-src`) from any
https origin, which a linked-account check needs (GitHub's API, the linked website, the DNS-over-HTTPS resolver); they do
so only when the user asks for a check, and read the answers as data only.

## Run your own home

Everything specific to a home is in `home.toml`, read at build time:

| Key | rootcard.org | |
|---|---|---|
| `name` | `rootcard.org` | What the pages call this home |
| `url` | `https://rootcard.org` | Its base URL, an origin. The default of `ROOTCARD_SITE_URLS` |
| `realm` | `global` | The realm the pages register and look up in. The default of `ROOTCARD_SITE_REALMS` |
| `operator` | `Hexagon#DNTT` | The operator's rootcard handle; the policy page links to its verified card |
| `source` | this repository | The source of the site, linked from the footer and the policy page |
| `wordmark_html` | `root<b>card</b>.org` | Optional: the wordmark in the header and footer (default: the name) |
| `dns_resolver` | – | Optional: the DNS-over-HTTPS resolver (JSON API, with CORS) for the TXT records of `dns` links (default: `https://cloudflare-dns.com/dns-query`) |
| `operator_account` | – | Optional: the operator's account id; `/.well-known/rootcard-link` then serves its link token |
| `overlay` | – | Optional: a directory (relative to `home.toml`) whose files replace or add to `web/` by path, partials included: your own `policy.html` terms, `img/logo.svg`, `_partials/footer.html` |

Either fork this repository and edit `home.toml`, or keep your home's files elsewhere and build with
`ROOTCARD_HOME=path/to/home.toml` (`docker build --build-arg ROOTCARD_HOME=…`). `homes/example` is a complete example,
built in CI, with an overlay that replaces `robots.txt`:

```bash
ROOTCARD_HOME=homes/example/home.toml cargo build --release
```

`build.rs` fills `{{home.*}}` in the pages (HTML-escaped) and `robots.txt`, gives every page a canonical link and Open
Graph tags from its own title and description, generates `/js/home-config.js` (the same values for the scripts),
`/site.webmanifest` and `/sitemap.xml` (every page not marked `noindex`), and fails on a placeholder it does not know.
The server redirects `/page.html` and `/page/` to `/page`. The link preview image `img/og.png` (1200×630) shows the
rootcard.org name: put your own in your overlay, with the PNG icons (`favicon.ico`, `img/icon-*.png`,
`img/apple-touch-icon.png`) if you change the logo. The pages say what *this* home stores and
how to leave it, which holds for any home running this software unchanged; if you change the software or the storage,
update `policy.html` (in your overlay) to match. Before opening a home to the public, publish contact details in the
operator identity's public profile and keep the host key with the database backups. The binary serves the host at the
root of its origin and answers the host pointer `/.well-known/rootcard` ([HST-23]) itself.

## Layout

```
src/main.rs      axum server: routing, security headers, config, static assets
src/store.rs     SQLite IdentityStore / ChallengeStore / SessionStore (schema of rootcard ARCHITECTURE.md §3.1)
src/limits.rs    rate limits of HOST_PROTOCOL.md §6, per address (IPv6 per /64) and, for failed requests, per identity
build.rs         embeds web/ into the binary for the home of home.toml (overlay, partials, {{home.*}}, version and
                 key tool hash substituted, home-config.js, webmanifest and sitemap generated, ETags)
home.toml        this build's home: rootcard.org
homes/example    another home built from the same sources
web/             pages, CSS, JS, logo; web/_partials are included into every page; web/js/links.js checks linked
                 accounts (SPEC §12.3) for the card and account pages
web/vendor/rootcard   the npm package rootcard@0.3.4 (src/, keytool.html, licenses)
tests/browser    Playwright end-to-end test of the whole flow
```

## Run

```bash
ROOTCARD_SITE_URLS=http://127.0.0.1:8080 cargo run
# open http://127.0.0.1:8080
```

| Variable | Default | |
|---|---|---|
| `ROOTCARD_SITE_URLS` | `url` of `home.toml` | Base URLs of the host, comma separated, the first preferred. Origins only (the site serves the host at the root). `http://` only on loopback |
| `ROOTCARD_SITE_BIND` | `127.0.0.1:8080` | Listen address |
| `ROOTCARD_SITE_DB` | `rootcard-site.db` | SQLite database |
| `ROOTCARD_SITE_KEY_FILE` | `host.key` | Host key (64 hex), created with mode 0600 on first start. **Back it up with the database**: it signs the receipts of every instance homed here |
| `ROOTCARD_SITE_SEED` | – | The host key as hex instead of a file |
| `ROOTCARD_SITE_RETIRED_KEYS` | – | Public keys (hex) of earlier host keys, after a key rotation ([HST-17]) |
| `ROOTCARD_SITE_REALMS` | `realm` of `home.toml` | Served realms |
| `ROOTCARD_SITE_TRUST_PROXY` | off (on in the `Dockerfile`) | Take the client address from the last `X-Forwarded-For` entry (for rate limits), when the connection comes from a loopback or private address (the reverse proxy) |

Production: run behind a TLS-terminating reverse proxy (Caddy, nginx) on the home's URL with
`ROOTCARD_SITE_TRUST_PROXY=1`, or use the `Dockerfile` (data in `/data`).

## Test

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
# browser end to end, against a running local server:
npm install --no-save --no-package-lock playwright@1.63.0 && npx playwright install chromium
node tests/browser/e2e.mjs
```

## Updating rootcard

Bump `rootcard` and `rootcard-host` in `Cargo.toml` and replace `web/vendor/rootcard` with the same version of the npm
package (`npm pack rootcard@X.Y.Z`, check the integrity against `npm view rootcard@X.Y.Z dist.integrity`). The two must
be the same release: the pages call the JS functions of that version (for example `changePassword` with a username and
`newRecoveryKey` since 0.3.0).

## License

MIT or Apache-2.0, at your option. The vendored package keeps its own license files.
