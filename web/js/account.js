// Sign-in at this home and the low-power account functions (HOST_PROTOCOL.md §3, §4 and §7):
//   lookup → log (verified) → locks → challenge {fetch} → fetch the vault → unlock locally → challenge {login} → login.
// The unlocked vault lives only in this page's memory. Nothing here asks for the recovery key ([PWR-6]).

import { BASE, REALM, busy, download, explain, fetchLog, groups, http, instanceTime, now, random, rc, renderCard, status, tilt, work } from "/js/common.js";
import { checkPassword, checkContents, unwrapVaultKey, updateContents } from "/vendor/rootcard/src/vault.js";
import { aesGcmDecrypt, ed25519Public } from "/vendor/rootcard/src/crypto.js";
import { CONTENTS_LIMIT, contentsAad } from "/vendor/rootcard/src/vaultcheck.js";
import { REGISTRY, SERVICES, check, contacts, githubUser, help, renderLinks, serviceLabel, statusOf, whereToken } from "/js/links.js";

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
  // Not the password rules ([LCK-8]): a password set under other rules, or by another client, must still sign in, and a
  // wrong password is reported as wrong, not as weak. The vault decides.
  if (!password) throw new Error("Enter your password.");

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

/** Back to the sign-in form, with nothing of the signed-out identity left on screen. */
function showSignedOut() {
  $("signedIn").hidden = true;
  $("signedOut").hidden = false;
  $("lockField").hidden = true;
  // Proofs of the signed-out identity stay valid, but are not left on screen for the next person.
  for (const id of ["proofOut", "copyProof", "copyProofLink", "openProof", "proofLinkNote"]) $(id).hidden = true;
  $("proofOut").textContent = "";
  for (const id of ["pName", "pAbout", "pUrl", "pNote", "newPassword", "newPassword2", "recipient", "challenge", "lName", "lUid", "lValue"]) $(id).value = "";
  $("facts").replaceChildren();
  $("linksList").replaceChildren();
  $("linksNote").replaceChildren();
  $("token").textContent = "";
  linkOutcomes.clear();
  pending = null;
  $("lConfirm").hidden = true;
  for (const id of ["overviewStatus", "profileStatus", "linksStatus", "passwordStatus", "proveStatus"]) status($(id), "", "");
}

async function signOut() {
  const token = S?.token;
  forget();
  if (token) {
    try {
      await http("POST", "/session/logout", undefined, token);
    } catch {}
  }
  showSignedOut();
}

// The unlocked vault cannot survive the page; end the session with it. The page may be kept in the back/forward cache
// and shown again, so the keys are erased and the view reset here too, not only the session on the server.
addEventListener("pagehide", () => {
  if (!S) return;
  fetch(`${BASE}/${rc.API_VERSION}/session/logout`, {
    method: "POST", headers: { Authorization: `Bearer ${S.token}` }, keepalive: true, credentials: "omit",
  }).catch(() => {});
  forget();
  showSignedOut();
});

// Leaving the page signs out: ask first, so a link does not end the session by surprise.
addEventListener("beforeunload", (e) => {
  if (S) e.preventDefault();
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
  $("token").textContent = rc.linkToken(state.account);
  $("linksCard").href = `/card?h=${encodeURIComponent(state.handle)}`;
  showLinks();
  selectTab("overview");
}

const TABS = [...document.querySelectorAll("[data-tab]")];

function selectTab(name, focus = false) {
  for (const b of TABS) {
    const on = b.dataset.tab === name;
    b.setAttribute("aria-selected", String(on));
    b.tabIndex = on ? 0 : -1;
    if (on && focus) b.focus();
  }
  for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== name;
}
for (const b of TABS) {
  const panel = document.querySelector(`[data-panel="${b.dataset.tab}"]`);
  b.type = "button";
  b.id = `tab-${b.dataset.tab}`;
  panel.id ||= `panel-${b.dataset.tab}`;
  b.setAttribute("aria-controls", panel.id);
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", b.id);
  b.addEventListener("click", () => selectTab(b.dataset.tab));
  // Arrow keys, Home and End move between the tabs (WAI-ARIA tabs pattern, automatic activation).
  b.addEventListener("keydown", (e) => {
    const i = TABS.indexOf(b);
    const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    selectTab(TABS[(to + TABS.length) % TABS.length].dataset.tab, true);
  });
}
selectTab("overview");

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

/** Sign and publish a new public profile with `data` ([DAT-3]: the next rev of this instance). */
async function publishProfile(data) {
  const rev = (S.public ? S.public.rev : 0) + 1;
  const pub = await rc.signPublic(S.state.account, S.state.instance.hash, rev, data, S.u.contents.accountSeed);
  await http("PUT", "/session/public", { public: pub }, S.token);
  S.public = pub;
  S.publicData = data;
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
        await publishProfile(data);
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

// ---- linked accounts (SPEC §12.3) ----
// The links are the public profile key `user.links`. Adding one checks it from this browser first ([LNK-4]), then shows
// the service, the name and that the link is public before it is published.

/** The application namespace this site writes under ([DAT-7]); links themselves are a `user.` key. */
const APP = "site";
const linkKey = (link) => rc.canonicalString(link);
const linkOutcomes = new Map(); // canonical link → the last check in this browser
let pending = null; // { link, links }: checked, waiting for "Publish"

/** parseLinks of the current profile, or [] with a note when the value as a whole cannot be read. */
function linkEntries() {
  try {
    return { entries: rc.parseLinks(S.publicData, REGISTRY), note: "" };
  } catch (e) {
    const note = e?.code === "unsupported"
      ? "Your profile lists linked accounts in a newer format than this site reads. Adding or removing a link here replaces that list."
      : "Your profile's list of linked accounts is malformed. Adding or removing a link here replaces it.";
    return { entries: [], note };
  }
}

/** The links a new list keeps: those this site can read. The others are dropped, and the user is told before. */
function kept(entries) {
  return entries.filter((e) => e.status === "ok").map((e) => e.link);
}

function dropped(entries, note) {
  const n = entries.filter((e) => e.status !== "ok").length;
  if (note) return " The list your profile has now is replaced.";
  return n ? ` ${n === 1 ? "One link" : `${n} links`} this site cannot read (shown above) ${n === 1 ? "is" : "are"} left out.` : "";
}

function showLinks() {
  const { entries, note } = linkEntries();
  $("linksNote").replaceChildren();
  if (note) {
    const n = document.createElement("div");
    n.className = "notice warn";
    const p = document.createElement("p");
    p.textContent = note;
    n.append(p);
    $("linksNote").append(n);
  }
  $("linksEmpty").hidden = entries.length > 0;
  renderLinks($("linksList"), entries, { get: (e) => (e.link ? linkOutcomes.get(linkKey(e.link)) : undefined) }, {
    owner: true,
    onCheck: (i) => checkExisting(entries[i]),
    onRemove: (i) => removeLink(entries, i),
  });
}

function checkExisting(entry) {
  return busy($("linksForm"), async () => {
    const st = $("linksStatus");
    try {
      status(st, "busy", `Checking from this browser (contacts ${contacts(entry.link).join(", ")})…`);
      const outcome = await check(entry.link, S.state.account);
      if (!S) return;
      linkOutcomes.set(linkKey(entry.link), outcome);
      showLinks();
      const s = statusOf(entry, outcome);
      const where = outcome.result === "verified" ? "" : ` ${whereToken(entry.link)}`;
      status(st, s.level === "bad" ? "error" : s.level || "info", `${serviceLabel(entry.link.service)} · ${entry.link.name}: ${s.text}${where}`);
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
}

async function removeLink(entries, i) {
  const st = $("linksStatus");
  const entry = entries[i];
  const what = entry.link ? `${serviceLabel(entry.link.service)} · ${entry.link.name}` : "this invalid link";
  if (!confirm(`Remove ${what} from your public profile?`)) return;
  await busy($("linksForm"), async () => {
    try {
      const { entries: now, note } = linkEntries();
      const rest = kept(now).filter((l) => !entry.link || linkKey(l) !== linkKey(entry.link));
      const data = rest.length
        ? rc.setData(S.publicData, APP, rc.LINKS_KEY, rc.linksValue(rest, REGISTRY))
        : rc.removeData(S.publicData, APP, rc.LINKS_KEY);
      status(st, "busy", "Signing and saving your public profile…");
      await publishProfile(data);
      showLinks();
      // [LNK-4]: older copies of the profile still list the link; only removing the token ends it.
      status(st, "ok", entry.link
        ? `Removed. Remove the token too: ${whereToken(entry.link)} Older copies of your profile still list the link, and the token is what makes it count.${dropped(now, note)}`
        : `Removed.${dropped(now, note)}`);
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
}

/** The descriptor of the chosen service. */
const chosen = () => rc.findDescriptor(REGISTRY, $("lService").value);

/** The link the form describes, as typed (not yet checked against the service's rules). */
function formLink() {
  const d = chosen();
  const link = { service: d.service, name: $("lName").value.trim() };
  if (d.uid) link.uid = $("lUid").value.trim();
  const form = $("lForm").value;
  if (d.forms.length && form) {
    const f = d.forms.find(([n]) => n === form);
    link.ref = f && f[1].kind !== "none" ? `${form}:${$("lValue").value.trim()}` : form;
  }
  return link;
}

/** Labels and fields for the chosen service and form. */
function linkFormChanged() {
  const d = chosen();
  const h = help(d.service);
  $("lNameLabel").textContent = h.name ?? "Name";
  $("lNameHint").textContent = h.nameHint ?? "";
  $("lName").placeholder = d.name.kind === "domain" ? "example.com" : "";
  $("lUidField").hidden = !d.uid;
  $("lUidLabel").textContent = h.uid ?? "Account id";
  $("lUidHint").textContent = h.uidHint ?? "";
  const forms = d.forms.map(([n]) => n);
  $("lFormField").hidden = forms.length === 0;
  const keep = $("lForm").value;
  const options = forms.map((n) => new Option(h.forms?.[n]?.label ?? n, n));
  if (d.checks.some(([k]) => k === "*") && forms.length) options.unshift(new Option("The service's usual place", ""));
  $("lForm").replaceChildren(...options);
  if (forms.includes(keep)) $("lForm").value = keep;
  const form = d.forms.find(([n]) => n === $("lForm").value);
  $("lValueField").hidden = !form || form[1].kind === "none";
  const fh = form ? h.forms?.[form[0]] : undefined;
  $("lValueLabel").textContent = fh?.value ?? "Reference";
  $("lValueHint").textContent = fh?.valueHint ?? "";
  $("lWhere").textContent = whereToken(formLink());
  pending = null;
  $("lConfirm").hidden = true;
}

$("lService").replaceChildren(...SERVICES.map((d) => new Option(serviceLabel(d.service), d.service)));
$("lService").addEventListener("change", () => {
  $("lName").value = "";
  $("lUid").value = "";
  $("lValue").value = "";
  linkFormChanged();
});
$("lForm").addEventListener("change", linkFormChanged);
$("lName").addEventListener("input", () => {
  // A uid filled in for another name is not this name's.
  if ($("lUid").dataset.auto === "1") {
    $("lUid").value = "";
    $("lUid").dataset.auto = "";
  }
  linkFormChanged();
});
$("lUid").addEventListener("input", () => {
  $("lUid").dataset.auto = "";
  linkFormChanged();
});
$("lValue").addEventListener("input", linkFormChanged);
linkFormChanged();

$("copyToken").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("token").textContent);
    status($("linksStatus"), "ok", "Token copied.");
  } catch {
    status($("linksStatus"), "warn", "Copy failed; select the token instead.");
  }
});

$("linksForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("linksForm"), async () => {
    const st = $("linksStatus");
    pending = null;
    $("lConfirm").hidden = true;
    try {
      const d = chosen();
      let link = formLink();
      if (!link.name) throw new Error(`Enter the ${(help(d.service).name ?? "name").toLowerCase()}.`);
      if (d.service === "github" && !link.uid) {
        // GitHub links name the stable user id too ([LNK-18]): ask GitHub for it, as the check will.
        status(st, "busy", "Asking GitHub for the account's user id (contacts api.github.com)…");
        const u = await githubUser(link.name);
        if (!u) throw new Error("GitHub does not know that username, or did not answer. Check it, or enter the user id yourself.");
        $("lName").value = u.name;
        $("lUid").value = u.uid;
        $("lUid").dataset.auto = "1";
        link = formLink();
      }
      try {
        rc.linksValue([link], REGISTRY);
      } catch (err) {
        throw new Error(`That is not a valid ${serviceLabel(d.service)} link: check the fields. (${err?.code ?? "error"})`);
      }
      const { entries, note } = linkEntries();
      const prior = kept(entries);
      if (prior.some((l) => sameAccount(l, link))) throw new Error("That account is already linked.");
      const links = [...prior, link];
      if (links.length > rc.MAX_LINKS) throw new Error(`A profile holds at most ${rc.MAX_LINKS} links. Remove one first.`);
      status(st, "busy", `Checking from this browser (contacts ${contacts(link).join(", ")})…`);
      const outcome = await check(link, S.state.account);
      if (!S) return;
      linkOutcomes.set(linkKey(link), outcome);
      const s = statusOf({ link, status: "ok" }, outcome);
      const what = `${serviceLabel(link.service)} · ${link.name}`;
      const tail = ` Publishing adds “${what}” to your public profile: anyone who looks you up sees it, and copies cannot be taken back.${dropped(entries, note)}`;
      if (outcome.result === "verified") {
        status(st, "ok", `${s.text}${tail}`);
        $("lPublish").textContent = "Publish link";
      } else {
        status(st, "warn", `${s.text} ${whereToken(link)} You can publish it anyway; it shows as not verified until the token is in place.${tail}`);
        $("lPublish").textContent = "Publish anyway";
      }
      pending = { link, links };
      $("lConfirm").hidden = false;
    } catch (err) {
      status(st, "error", explain(err));
    }
  });
});

/** Whether two valid links name the same account, as their service compares names ([LNK-2]). */
function sameAccount(a, b) {
  if (a.service !== b.service) return false;
  try {
    rc.linksValue([a, b], REGISTRY);
    return false;
  } catch {
    return true;
  }
}

$("lCancel").addEventListener("click", () => {
  pending = null;
  $("lConfirm").hidden = true;
  status($("linksStatus"), "", "");
});

$("lPublish").addEventListener("click", () => {
  const p = pending;
  if (!p) return;
  busy($("linksForm"), async () => {
    const st = $("linksStatus");
    try {
      status(st, "busy", "Signing and saving your public profile…");
      await publishProfile(rc.setData(S.publicData, APP, rc.LINKS_KEY, rc.linksValue(p.links, REGISTRY)));
      pending = null;
      $("lConfirm").hidden = true;
      for (const id of ["lName", "lUid", "lValue"]) $(id).value = "";
      linkFormChanged();
      showLinks();
      status(st, "ok", `Published. Anyone can check “${serviceLabel(p.link.service)} · ${p.link.name}” on your public card.`);
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

/** The challenge: 64 hex characters from the verifier, or a JSON statement hashed per [PRF-5] (returned with it). */
async function challengeOf(text) {
  const t = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return { challenge: rc.hexDecode(t) };
  let statement;
  try {
    statement = rc.parseJson(new TextEncoder().encode(t));
  } catch {
    throw new Error("The challenge is neither 64 hex characters nor JSON. A plain sentence needs quotes: \"I am Astra\".");
  }
  return { challenge: await rc.statementChallenge(statement), statement };
}

$("proveForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("proveForm"), async () => {
    const st = $("proveStatus");
    try {
      const recipient = $("recipient").value.trim();
      if (!recipient) throw new Error("Name the recipient: the service the proof is for.");
      const { challenge, statement } = await challengeOf($("challenge").value);
      const proof = await rc.prove(S.state, "account", S.u.contents.accountSeed, challenge, recipient);
      // The statement travels with its proof, so the verifier can read what was signed ([PRF-5]).
      const bundle = statement === undefined ? { proof, log: S.log } : { proof, log: S.log, statement };
      $("proofOut").textContent = rc.canonicalString(bundle);
      $("proofOut").hidden = false;
      $("copyProof").hidden = false;
      // A link for statements: the log stays out (this home serves it), so the link stays short.
      const link = statement === undefined
        ? ""
        : `${location.origin}/card#proof=${rc.base64urlEncode(new TextEncoder().encode(rc.canonicalString({ proof, statement })))}`;
      $("copyProofLink").hidden = !link;
      $("copyProofLink").dataset.link = link;
      $("openProof").hidden = !link;
      $("openProof").href = link || "/card";
      $("proofLinkNote").hidden = !link;
      status(st, "ok", statement === undefined
        ? "Signed. Send the proof and your log to the recipient; it verifies both itself."
        : "Signed. Send it, or share the link: anyone can check the statement on the card page.");
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
$("copyProofLink").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("copyProofLink").dataset.link);
    status($("proveStatus"), "ok", "Link copied.");
  } catch {
    status($("proveStatus"), "warn", "Copy failed; use “Check it on the card page” and copy its address.");
  }
});
