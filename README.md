# rootcard.org

The website of [rootcard](https://github.com/rootcard/rootcard), and a public rootcard **home** for the `global` realm.

One Rust binary serves both:

- **The product site**: what rootcard is, how it works, the comparison, the developer guide and the key tool download.
- **A home host**: the rootcard HTTP binding (`https://rootcard.org/v0/…`, rootcard's `docs/HOST_PROTOCOL.md`) through
  `rootcard_host::http::route`, with SQLite storage and the recommended rate limits. Anyone can get an ID card with
  rootcard.org as home from the browser, without running a server or the CLI.

The browser does all the cryptography with the published npm package (`web/vendor/rootcard`, `rootcard@0.3.1`
unchanged, integrity checked against the registry). The server never sees a password or a recovery key.

## What the pages do

| Page | What |
|---|---|
| `/` | Product page |
| `/create` | Registration ([CLT-1]): the recovery key is made in a Web Worker, the user must download or print the recovery card before anything is sent, then the registration is built (Argon2id off the main thread) and posted. The log is fetched back and verified |
| `/account` | Sign-in ([LGN-1]: lookup, log, locks, fetch, local unlock, login), then the low-power functions: public profile, private data in the vault, password change ([CHG-1]), account file export, account proofs ([PRF-1]). The unlocked vault lives only in page memory; leaving the page logs the session out |
| `/card?h=Name%23TAG` | Public lookup: resolves a handle and verifies log and profile in the browser |
| `/keytool` | Explains the key tool and offers the npm package's `keytool.html` as a **download only** (never rendered from this origin), with its SHA-256. The site never asks for a recovery key ([PWR-6]) |
| `/developers` | Integration guide and this home's API |

Every page is served with a strict CSP (`script-src 'self'`, no inline script or style, nothing third-party), `nosniff`,
`no-referrer`, `frame-ancestors 'none'` and HSTS on https.

## Layout

```
src/main.rs      axum server: routing, security headers, config, static assets
src/store.rs     SQLite IdentityStore / ChallengeStore / SessionStore (schema of rootcard ARCHITECTURE.md §3.1)
src/limits.rs    rate limits of HOST_PROTOCOL.md §6, per address and per identity
build.rs         embeds web/ into the binary (partials, version and key tool hash substituted, ETags)
web/             pages, CSS, JS, logo; web/_partials are included into every page
web/vendor/rootcard   the npm package rootcard@0.3.1 (src/, keytool.html, licenses)
tests/browser    Playwright end-to-end test of the whole flow
```

## Run

```bash
ROOTCARD_SITE_URLS=http://127.0.0.1:8080 cargo run
# open http://127.0.0.1:8080
```

| Variable | Default | |
|---|---|---|
| `ROOTCARD_SITE_URLS` | `https://rootcard.org` | Base URLs of the host, comma separated, the first preferred. Origins only (the site serves the host at the root). `http://` only on loopback |
| `ROOTCARD_SITE_BIND` | `127.0.0.1:8080` | Listen address |
| `ROOTCARD_SITE_DB` | `rootcard-site.db` | SQLite database |
| `ROOTCARD_SITE_KEY_FILE` | `host.key` | Host key (64 hex), created with mode 0600 on first start. **Back it up with the database**: it signs the receipts of every instance homed here |
| `ROOTCARD_SITE_SEED` | – | The host key as hex instead of a file |
| `ROOTCARD_SITE_RETIRED_KEYS` | – | Public keys (hex) of earlier host keys, after a key rotation ([HST-17]) |
| `ROOTCARD_SITE_REALMS` | `global` | Served realms |
| `ROOTCARD_SITE_TRUST_PROXY` | off | Take the client address from the last `X-Forwarded-For` entry (for rate limits) |

Production: run behind a TLS-terminating reverse proxy (Caddy, nginx) on `https://rootcard.org` with
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
