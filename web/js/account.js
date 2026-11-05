// Sign-in at this home and the low-power account functions (HOST_PROTOCOL.md §3, §4 and §7):
//   lookup → log (verified) → locks → challenge {fetch} → fetch the vault → unlock locally → challenge {login} → login.
// The unlocked vault lives only in this page's memory. Nothing here asks for the recovery key ([PWR-6]).

import { BASE, REALM, busy, download, explain, fetchLog, groups, http, instanceTime, now, random, rc, renderCard, status, tilt, work } from "/js/common.js";
import { checkPassword, checkContents, unwrapVaultKey, updateContents } from "/vendor/rootcard/src/vault.js";
import { aesGcmDecrypt, ed25519Public } from "/vendor/rootcard/src/crypto.js";
import { CONTENTS_LIMIT, contentsAad } from "/vendor/rootcard/src/vaultcheck.js";

const $ = (id) => document.getElementById(id);
let S = null; // { token, state, log, vault, u, lock, authSeed, public, publicData }

const params = new URLSearchParams(location.search);
if (params.get("h")) $("handle").value = params.get("h");
($("handle").value ? $("password") : $("handle")).focus();

/** Unlock a fetched vault with secrets already derived for the fetch, without a second Argon2id run ([VLT-8]). */
async function unlock(vault, state, lock, ls) {
  const info = await rc.verifyVault(vault, state);
  const l = info.locks.find((x) => x.kind === "password" && x.id === lock);
  if (!l) throw new rc.RootcardError("bad_locks");
  const vaultKey = await unwrapVaultKey(l.value.wrap, ls.boxSecret, l.box, state.account, vault.instance, lock);
  const pt = await aesGcmDecrypt(vaultKey, rc.base64urlDecode(vault.nonce), rc.base64urlDecode(vault.ct), contentsAad(vault));
  const contents = checkContents(rc.parseLimited(pt, CONTENTS_LIMIT));
  pt.fill(0);
  if (!state.instance) throw new rc.RootcardError("no_instance");
  if (rc.formatKey("ed25519", await ed25519Public(contents.accountSeed)) !== state.instance.account_key) {
    throw new rc.RootcardError("wrong_account_key");
  }
  return { vaultKey, contents, lock, lockSeed: ls.authSeed, info };
}

async function signIn(handleText, password, chosenLock) {
  const st = $("signinStatus");
  await rc.checkSupport();
  const parsed = rc.parseHandle(handleText.trim());
  status(st, "busy", "Looking up your identity…");
  const found = await http("GET", `/id/lookup?realm=${encodeURIComponent(REALM)}&handle=${encodeURIComponent(handleText.trim())}`);
  if (found.retired) throw new rc.RootcardError("account_retired");
  if (!found.home) throw new rc.RootcardError("no_instance");
  if (found.home.url !== BASE) {
    throw new Error(`${found.handle} has its home at ${found.home.url}. Sign in there.`);
  }
  const { log, state } = await fetchLog(found.account);
  if (!rc.handleMatches(parsed, state.username, state.account)) throw new rc.RootcardError("account_mismatch");
  if (!state.instance || state.instance.home.url !== BASE) throw new rc.RootcardError("not_home");
  checkPassword(password, state.username);

  const hints = await http("GET", `/id/${state.account}/locks`);
  if (hints.instance !== state.instance.hash) throw new rc.RootcardError("stale_version");
  const locks = hints.locks;
  if (!locks.length) throw new rc.RootcardError("bad_locks");
  let hint = locks.find((l) => l.id === chosenLock);
  if (!hint) {
    if (locks.length > 1) {
      $("lock").replaceChildren(...locks.map((l) => new Option(l.label, l.id)));
      $("lockField").hidden = false;
      status(st, "info", "Pick which password you typed, then sign in again.");
      return null;
    }
    hint = locks[0];
  }

  status(st, "busy", "Deriving your keys from the password (Argon2id). This takes a few seconds…");
  const kdf = { alg: hint.kdf.alg, m: hint.kdf.m, t: hint.kdf.t, p: hint.kdf.p };
  const ls = await work("derive", state.account, hint.id, password, kdf, rc.base64urlDecode(hint.kdf.salt));
  try {
    status(st, "busy", "Fetching your vault…");
    const fc = rc.parseChallenge(await http("POST", `/id/${state.account}/challenge`, { purpose: "fetch" }));
    if (fc.host !== state.instance.home.key) throw new rc.RootcardError("wrong_host");
    const fsig = await rc.ed25519Sign(ls.authSeed, rc.fetchMessage(state.account, fc.host, hint.id, fc.nonce, BASE));
    const { vault } = await http("POST", `/id/${state.account}/fetch`, {
      lock: hint.id, nonce: fc.nonce, url: BASE, sig: rc.base64urlEncode(fsig),
    });
    status(st, "busy", "Unlocking your vault…");
    const u = await unlock(vault, state, hint.id, ls);
    status(st, "busy", "Signing in…");
    const lc = await http("POST", `/id/${state.account}/challenge`, { purpose: "login" });
    const signed = await rc.signLogin(state, lc, BASE, hint.id, u.contents.accountSeed, ls.authSeed);
    const res = await http("POST", `/id/${state.account}/login`, {
      nonce: signed.nonce, version: signed.version, url: signed.url, lock: signed.lock, sig: signed.sig, lock_sig: signed.lock_sig,
    });
    ls.boxSecret.fill(0);
    let pub = null;
    let publicData = {};
    try {
      pub = await http("GET", `/id/${state.account}/public`);
      publicData = (await rc.verifyPublic(pub, state)).data;
    } catch {
      pub = null;
    }
    return { token: res.token, state, log, vault, u, lock: hint.id, authSeed: ls.authSeed, public: pub, publicData };
  } catch (e) {
    ls.authSeed.fill(0);
    ls.boxSecret.fill(0);
    throw e;
  }
}

$("signinForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("signinForm"), async () => {
    try {
      const chosen = $("lockField").hidden ? undefined : $("lock").value;
      const s = await signIn($("handle").value, $("password").value, chosen);
      if (!s) return;
      S = s;
      $("password").value = "";
      status($("signinStatus"), "", "");
      show();
    } catch (err) {
      const wrong = ["bad_signature", "unauthorized", "unlock_failed"].includes(err?.code);
      status($("signinStatus"), "error", wrong ? "Wrong password, or the handle belongs to someone else." : explain(err));
    }
  });
});

function forget() {
  if (!S) return;
  S.u.vaultKey.fill(0);
  S.u.contents.accountSeed.fill(0);
  S.authSeed.fill(0);
  S = null;
}

async function signOut() {
  const token = S?.token;
  forget();
  if (token) {
    try {
      await http("POST", "/session/logout", undefined, token);
    } catch {}
  }
  $("signedIn").hidden = true;
  $("signedOut").hidden = false;
  $("lockField").hidden = true;
}

// The unlocked vault cannot survive the page; end the session with it.
addEventListener("pagehide", () => {
  if (!S) return;
  fetch(`${BASE}/${rc.API_VERSION}/session/logout`, {
    method: "POST", headers: { Authorization: `Bearer ${S.token}` }, keepalive: true, credentials: "omit",
  }).catch(() => {});
});

function fact(dl, k, v, mono) {
  const dt = document.createElement("dt");
  dt.textContent = k;
  const dd = document.createElement("dd");
  dd.textContent = v;
  if (mono) dd.className = "mono";
  dl.append(dt, dd);
}

function show() {
  const { state, log } = S;
  $("signedOut").hidden = true;
  $("signedIn").hidden = false;
  $("hello").textContent = state.handle;
  renderCard($("card"), {
    username: state.username,
    account: state.account,
    realm: state.realm,
    home: state.instance?.home.url,
    since: instanceTime(log, state),
    display: typeof S.publicData["user.name"] === "string" ? S.publicData["user.name"] : undefined,
    verified: true,
  });
  tilt($("card"));
  const dl = $("facts");
  dl.replaceChildren();
  fact(dl, "Handle", state.handle);
  fact(dl, "Account id", groups(state.account), true);
  fact(dl, "Realm", state.realm);
  fact(dl, "Home", state.instance.home.url);
  fact(dl, "Version", `${state.version.seq} · ${state.version.hash.slice(0, 16)}…`, true);
  fact(dl, "Instance", `${state.instance.reason} · ${new Date((instanceTime(log, state) ?? 0) * 1000).toLocaleString()}`);
  fact(dl, "Passwords", S.u.info.slots.map((x) => x.label).join(", "));
  $("publicLink").href = `/card?h=${encodeURIComponent(state.handle)}`;
  const d = S.publicData;
  $("pName").value = typeof d["user.name"] === "string" ? d["user.name"] : "";
  $("pAbout").value = typeof d["user.about"] === "string" ? d["user.about"] : "";
  $("pUrl").value = typeof d["user.url"] === "string" ? d["user.url"] : "";
  const note = S.u.contents.data["user.note"];
  $("pNote").value = typeof note === "string" ? note : "";
  selectTab("overview");
}

function selectTab(name) {
  for (const b of document.querySelectorAll("[data-tab]")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== name;
}
for (const b of document.querySelectorAll("[data-tab]")) b.addEventListener("click", () => selectTab(b.dataset.tab));

$("signout").addEventListener("click", () => signOut());

$("export").addEventListener("click", () => {
  busy($("signedIn"), async () => {
    try {
      const file = await http("GET", "/session/export", undefined, S.token);
      await rc.importAccount(file, { realms: [REALM], now: now() });
      download(rc.accountFileName(S.state), file);
      status($("overviewStatus"), "ok", "Account file downloaded and verified. Keep it with your recovery card.");
    } catch (err) {
      status($("overviewStatus"), "error", explain(err));
    }
  });
});

function setText(data, key, value) {
  const v = value.trim();
  if (v) return { ...data, [key]: v };
  const d = { ...data };
  delete d[key];
  return d;
}

$("profileForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("profileForm"), async () => {
    const st = $("profileStatus");
    try {
      const url = $("pUrl").value.trim();
      if (url && !/^https:\/\/[^\s]+$/.test(url)) throw new Error("The website must start with https://");
      let data = S.publicData;
      data = setText(data, "user.name", $("pName").value);
      data = setText(data, "user.about", $("pAbout").value);
      data = setText(data, "user.url", url);
      if (rc.canonicalString(data) !== rc.canonicalString(S.publicData)) {
        status(st, "busy", "Signing and saving your public profile…");
        const rev = (S.public ? S.public.rev : 0) + 1;
        const pub = await rc.signPublic(S.state.account, S.state.instance.hash, rev, data, S.u.contents.accountSeed);
        await http("PUT", "/session/public", { public: pub }, S.token);
        S.public = pub;
        S.publicData = data;
      }
      const note = $("pNote").value;
      const privateData = setText(S.u.contents.data, "user.note", note);
      if (rc.canonicalString(privateData) !== rc.canonicalString(S.u.contents.data)) {
        status(st, "busy", "Encrypting and saving your vault…");
        const contents = { ...S.u.contents, data: privateData };
        const vault = await updateContents(S.u, S.vault, contents, random);
        await http("PUT", "/session/vault", { vault }, S.token);
        S.vault = vault;
        S.u = { ...S.u, contents, info: await rc.verifyVault(vault, S.state) };
      }
      status(st, "ok", "Saved.");
      show();
      selectTab("profile");
      status($("profileStatus"), "ok", "Saved.");
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
});

$("passwordForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("passwordForm"), async () => {
    const st = $("passwordStatus");
    try {
      const pw = $("newPassword").value;
      checkPassword(pw, S.state.username);
      if (pw !== $("newPassword2").value) throw new Error("The passwords do not match.");
      status(st, "busy", "Building the new lock (Argon2id). This takes a few seconds…");
      // [CHG-1]: the new vault, then a change proof signed with the old lock's key over the new lock's hash.
      const changed = await work("changePassword", S.u, S.vault, S.lock, pw, S.state.username, rc.KDF_DEFAULT);
      const ch = rc.parseChallenge(await http("POST", `/id/${S.state.account}/challenge`, { purpose: "change" }));
      if (ch.host !== S.state.instance.home.key) throw new rc.RootcardError("wrong_host");
      const msg = rc.changeMessage(S.state.account, ch.host, S.lock, rc.base64urlEncode(changed.new), ch.nonce, BASE);
      const proof = await rc.ed25519Sign(S.authSeed, msg);
      await http("POST", "/session/password", {
        lock: S.lock, nonce: ch.nonce, url: BASE, proof: rc.base64urlEncode(proof), vault: changed.vault,
      }, S.token);
      $("newPassword").value = "";
      $("newPassword2").value = "";
      const handle = S.state.handle;
      await signOut();
      $("handle").value = handle;
      status($("signinStatus"), "ok", "Password changed. Sign in with the new password.");
      $("password").focus();
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
});

async function challengeOf(text) {
  const t = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return rc.hexDecode(t);
  return rc.statementChallenge(rc.parseJson(new TextEncoder().encode(t)));
}

$("proveForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("proveForm"), async () => {
    const st = $("proveStatus");
    try {
      const recipient = $("recipient").value.trim();
      if (!recipient) throw new Error("Name the recipient: the service the proof is for.");
      const challenge = await challengeOf($("challenge").value);
      const proof = await rc.prove(S.state, "account", S.u.contents.accountSeed, challenge, recipient);
      const out = rc.canonicalString({ proof, log: S.log });
      $("proofOut").textContent = out;
      $("proofOut").hidden = false;
      $("copyProof").hidden = false;
      status(st, "ok", "Signed. Send the proof and your log to the recipient; it verifies both itself.");
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
});
$("copyProof").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("proofOut").textContent);
    status($("proveStatus"), "ok", "Copied.");
  } catch {
    status($("proveStatus"), "warn", "Copy failed; select the text instead.");
  }
});
