// Public card lookup and proof verification.
//   Lookup: resolve a handle ([HDL-3]), fetch the log and verify it ([LOG-12]), then the profile ([DAT-2]).
//   Proof:  take the proof (and the log and statement sent with it), merge that log with the one at this home ([VER-4]),
//           verify the proof against the newest ([PRF-4]) and stamp the result on the card.
// A proof link (`/card#proof=<base64url>`) carries the proof in the fragment, which is never sent to the server.
// A pasted proof is checked as it changes: there is no button to press.

import { HOME, REALM, busy, explain, groups, http, instanceTime, now, rc, renderCard, status, tilt } from "/js/common.js";

const $ = (id) => document.getElementById(id);
const card = $("card");
renderCard(card, { username: "Astra", realm: REALM });
card.classList.add("placeholder");
tilt(card);

const ACCOUNT = /^[0-9A-Z]{52}$/;
let proofRun = 0; // the newest proof check; older ones leave the page alone
let proofTimer;

function fact(dl, k, v, mono, note) {
  const dt = document.createElement("dt");
  dt.textContent = k;
  const dd = document.createElement("dd");
  if (v instanceof Node) dd.append(v);
  else dd.textContent = v;
  if (mono) dd.className = "mono";
  if (note) {
    const n = document.createElement("span");
    n.className = "hint";
    n.textContent = note;
    dd.append(n);
  }
  dl.append(dt, dd);
}

function li(text) {
  const e = document.createElement("li");
  e.textContent = text;
  return e;
}

function notice(kind, text) {
  const n = document.createElement("div");
  n.className = `notice ${kind}`;
  const p = document.createElement("p");
  p.textContent = text;
  n.append(p);
  return n;
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const REASON = {
  register: "first registration",
  revoke: "account key replaced",
  restore: "restored with the recovery key",
  fresh: "moved or started afresh",
};

function when(t) {
  return Number.isInteger(t) && t > 0 ? new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "";
}

function keyLine(label, key) {
  const p = el("p", "log-detail");
  p.append(document.createTextNode(`${label}: `), el("span", "mono", key));
  return p;
}

/** Every event of a verified log, oldest first, with the current instance and the newest version marked. */
function renderLog(log, state) {
  const ol = $("rLog");
  ol.replaceChildren();
  log.forEach((e, i) => {
    const item = el("li");
    const head = el("div", "log-head");
    const body = e?.body ?? {};
    const sigs = Array.isArray(e?.sigs) ? e.sigs.length : 0;
    const details = [];
    let title;
    if (e.kind === "incept") {
      title = "Created";
      details.push(el("p", "log-detail", `Handle ${body.username} in realm ${body.realm}. The account id is the hash of this event.`));
      details.push(keyLine("Recovery public key", body.recovery));
    } else if (e.kind === "instance") {
      title = "Account key and home";
      details.push(el("p", "log-detail", `${REASON[body.reason] ?? body.reason}; home ${hostOf(body.home?.url)}.`));
      details.push(keyLine("Account key", body.account_key));
    } else if (e.kind === "rotate_recovery") {
      title = "Recovery key replaced";
      details.push(keyLine("New recovery public key", body.recovery));
    } else if (e.kind === "retire") {
      title = "Retired";
      details.push(el("p", "log-detail", "The owner ended this identity. Nothing can follow this event."));
    } else title = String(e.kind);
    head.append(el("span", "faint mono", `#${i}`), el("b", "", title));
    if (when(e.time)) head.append(el("span", "faint", when(e.time)));
    const tags = [];
    if (state.instance && state.instance.seq === i) tags.push("current instance");
    if (state.version.seq === i) tags.push("newest");
    if (tags.length) head.append(el("span", "badge ok", tags.join(" · ")));
    if (state.instance && state.instance.seq === i) item.className = "current";
    item.append(head, ...details);
    item.append(el("p", "log-detail faint", `${sigs} signature${sigs === 1 ? "" : "s"}, verified.`));
    ol.append(item);
  });
}

async function resolve(q) {
  const t = q.trim().replace(/\s+/g, "");
  if (/^[0-9A-Za-z]{52}$/.test(t)) return t.toUpperCase();
  rc.parseHandle(q.trim());
  const found = await http("GET", `/id/lookup?realm=${encodeURIComponent(REALM)}&handle=${encodeURIComponent(q.trim())}`);
  return found.account;
}

const realmOf = (log) => (typeof log?.[0]?.body?.realm === "string" ? log[0].body.realm : REALM);
const verify = (log) => rc.verifyLog(log, { realms: [realmOf(log)], now: now() });

/** The log of `account` at this home, or null when this home does not know the identity. */
async function homeLog(account) {
  try {
    return (await http("GET", `/id/${account}/log`)).events;
  } catch (e) {
    if (e.code === "unknown_account") return null;
    throw e;
  }
}

/**
 * The newest valid log of `account` from this home's and the one sent with a proof ([VER-4]): `{ log, state, source,
 * current, notes }`. A fork is an error: the two cannot both be the owner's. `current` is whether the log is the one at
 * the identity's own home, this one: only that log shows the newest state. A log sent with a proof is chosen by the
 * prover, and this home's copy of an identity that moved elsewhere may be out of date; either can still name an account
 * key that was replaced since.
 */
async function newestLog(account, sent) {
  const r = await pickLog(account, sent);
  r.current = r.source === "home" && r.state.instance?.home.url === location.origin;
  if (r.source === "home" && !r.current && r.state.instance) {
    r.notes.push(`${HOME.name} keeps a copy of this log, but the identity's home is ${hostOf(r.state.instance.home.url)}: a newer log may be there.`);
  }
  return r;
}

async function pickLog(account, sent) {
  const notes = [];
  const home = await homeLog(account);
  let homeState = null;
  if (home) {
    homeState = await verify(home);
    if (homeState.account !== account) throw new rc.RootcardError("account_mismatch");
  }
  let sentState = null;
  if (Array.isArray(sent) && sent.length) {
    try {
      sentState = await verify(sent);
    } catch (e) {
      if (!homeState) throw e;
      notes.push(`The log sent with the proof does not verify (${e.code ?? "error"}); the log at ${HOME.name} was used.`);
    }
  }
  if (homeState && sentState) {
    const order = await rc.compareLogs(home, sent);
    if (order === "fork") throw new rc.RootcardError("fork");
    if (order === "newer") {
      notes.push(`The log sent with the proof is newer than the one at ${HOME.name}; the newer one was used.`);
      return { log: sent, state: sentState, source: "sent", notes };
    }
    return { log: home, state: homeState, source: "home", notes };
  }
  if (homeState) return { log: home, state: homeState, source: "home", notes };
  if (sentState) {
    notes.push(`${HOME.name} is not this identity's home, so the proof is only as fresh as the log sent with it.`);
    return { log: sent, state: sentState, source: "sent", notes };
  }
  throw new Error(`This identity is not homed at ${HOME.name}, and no log came with the proof. Ask for the proof with its log.`);
}

/** Show a verified identity: the card, its facts and what this browser checked. `proof` is the proof's outcome, if any. */
async function show(log, state, proof) {
  let data = {};
  let profileOk = false;
  if (state.instance && !state.retired && state.instance.home.url === location.origin) {
    try {
      const pub = await http("GET", `/id/${state.account}/public`);
      data = (await rc.verifyPublic(pub, state)).data;
      profileOk = true;
    } catch {}
  }
  const str = (k) => (typeof data[k] === "string" ? data[k] : undefined);
  renderCard(card, {
    username: state.username,
    account: state.account,
    realm: state.realm,
    home: state.instance?.home.url,
    since: instanceTime(log, state),
    display: str("user.name"),
    verified: !state.retired,
    proof: proof?.stamp,
  });
  card.classList.remove("placeholder");
  $("cardNote").textContent = proof
    ? proof.note
    : state.retired
      ? "This identity is retired."
      : "Verified against its public log.";
  $("rHandle").textContent = state.handle;
  $("rAbout").textContent = str("user.about") ?? "";
  $("rUrlRow").hidden = !str("user.url");
  $("rUrl").textContent = str("user.url") ?? "";
  const dl = $("rFacts");
  dl.replaceChildren();
  fact(dl, "Account id", groups(state.account), true);
  fact(dl, "Realm", state.realm);
  fact(dl, "Status", state.retired ? "retired" : state.instance ? "active" : "no instance");
  if (state.instance) fact(dl, "Home", state.instance.home.url);
  fact(dl, "Log", `${log.length} event${log.length === 1 ? "" : "s"}, version ${state.version.seq}`);
  // [CLT-8]: the public half of the recovery key, labelled as public. Never "Recovery key" alone: that is the secret on
  // the recovery card, and a page that shows a "recovery key" teaches that one belongs on websites.
  fact(dl, "Recovery public key", state.recovery, true,
    "Public and safe to see. The secret recovery key is only on the owner's recovery card, and is typed only into the key tool, never into a website.");
  const checks = $("rChecks");
  checks.replaceChildren(
    li("The account id is the SHA-256 of the inception, whose signature verifies with the recovery public key it names."),
    li(`Every one of the ${log.length} log events links to the one before and carries the signatures it needs.`),
  );
  if (state.instance) checks.append(li("The current instance carries the home's receipt."));
  if (profileOk) checks.append(li("The public profile is signed by the current account key."));
  for (const c of proof?.checks ?? []) checks.append(li(c));
  checks.append(li("Anything the profile or a statement says was written by the identity's owner, not checked by anyone."));
  renderLog(log, state);
  showProof(proof);
  $("result").hidden = false;
  $("grid").classList.add("has-result");
}

function showProof(proof) {
  $("rProof").hidden = !proof;
  if (!proof) return;
  $("rProofNotice").replaceChildren(notice(proof.stamp.level === "info" ? "ok" : proof.stamp.level === "bad" ? "error" : proof.stamp.level, proof.summary));
  const dl = $("rProofFacts");
  dl.replaceChildren();
  for (const [k, v, mono, note] of proof.facts) fact(dl, k, v, mono, note);
}

async function lookup(q) {
  const st = $("lookupStatus");
  proofRun++; // a proof still being checked must not replace this lookup
  clearTimeout(proofTimer);
  status($("proofStatus"), "", "");
  status(st, "busy", "Fetching and verifying…");
  $("result").hidden = true;
  try {
    await rc.checkSupport();
    const account = await resolve(q);
    const log = await homeLog(account);
    if (!log) throw new rc.RootcardError("unknown_account");
    const state = await verify(log);
    if (state.account !== account) throw new rc.RootcardError("account_mismatch");
    await show(log, state, null);
    status(st, "", "");
    history.replaceState(null, "", `/card?h=${encodeURIComponent(state.handle)}`);
  } catch (e) {
    if (e.code === "ambiguous_handle" && Array.isArray(e.body?.candidates)) {
      status(st, "warn", `Several identities match: ${e.body.candidates.map((c) => c.handle).join(", ")}. Use the longer tag.`);
    } else status(st, "error", explain(e));
  }
}

// ---- proofs (SPEC §14) ----

/** A pasted proof: a bare proof, or `{ proof, log?, statement? }` as the account page gives it out. */
function parseBundle(text) {
  const t = text.trim();
  if (!t) throw new Error("Paste a proof first.");
  const v = rc.parseJson(new TextEncoder().encode(t));
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new rc.RootcardError("bad_field");
  if ("proof" in v) return { proof: v.proof, log: v.log, statement: v.statement, hasStatement: "statement" in v };
  return { proof: v, hasStatement: false };
}

/** The expected challenge from the field: 64 hex characters, or a JSON statement hashed per [PRF-5]. */
async function expectedChallenge(text) {
  const t = text.trim();
  if (!t) return null;
  if (/^[0-9a-fA-F]{64}$/.test(t)) return { bytes: rc.hexDecode(t), statement: undefined };
  let statement;
  try {
    statement = rc.parseJson(new TextEncoder().encode(t));
  } catch {
    throw new Error("The statement is not valid JSON. A plain sentence needs quotes: \"I am Astra\".");
  }
  return { bytes: await rc.statementChallenge(statement), statement };
}

function statementView(statement) {
  const pre = document.createElement("pre");
  pre.className = "proof-statement";
  pre.textContent = typeof statement === "string" ? statement : JSON.stringify(statement, null, 2);
  return pre;
}

/** Verify a proof and build what the card and the panel show. Throws only when there is no identity to show. */
async function checkProof(bundleText, challengeText, recipientText) {
  const b = parseBundle(bundleText);
  const proof = b.proof;
  if (proof === null || typeof proof !== "object" || typeof proof.account !== "string" || !ACCOUNT.test(proof.account)) {
    throw new rc.RootcardError("bad_field");
  }
  const { log, state, source, current, notes } = await newestLog(proof.account, b.log);
  const by = proof.by === "recovery" ? "recovery" : "account";
  const expected = await expectedChallenge(challengeText);
  const challengeChecked = expected !== null;
  const recipientChecked = recipientText.trim() !== "";
  const recipient = recipientChecked ? recipientText.trim() : typeof proof.recipient === "string" ? proof.recipient : "";
  let challenge = expected?.bytes;
  if (!challenge) {
    try {
      challenge = rc.base64urlDecode(String(proof.challenge));
    } catch {
      challenge = new Uint8Array(32);
    }
  }
  const statement = expected?.statement;

  const facts = [];
  const kindText = by === "recovery"
    ? ["Root proof", false, "Signed with the recovery key, in the key tool. Valid while that key is the identity's recovery key."]
    : ["Account proof", false, "Signed with the account key of the current instance. Valid while that instance is current: a reset, a move or retirement ends it."];
  facts.push(["Kind", ...kindText]);
  facts.push(["Recipient", recipient, true,
    recipientChecked ? "As you entered it." : "As written in the proof, not checked against you: a proof convinces only the recipient it names."]);
  if (statement !== undefined) {
    facts.push(["Statement", statementView(statement), false,
      "Written by the owner. A statement proof can be shown again by anyone who has it, so check what it says it is for and until when."]);
  } else if (challengeChecked) facts.push(["Challenge", rc.hexEncode(challenge), true, "The challenge you entered."]);
  else facts.push(["Challenge", "not checked", false, "Enter the challenge you gave the prover, or the statement, to check it."]);
  const logUsed = source !== "home" ? "sent with the proof" : current ? `${HOME.name}, the identity's home` : `the copy at ${HOME.name}`;
  facts.push(["Log used", logUsed, false, notes.join(" ") || undefined]);

  let stamp;
  let summary;
  let note;
  let checks = [];
  try {
    await rc.verifyProof(proof, log, challenge, recipient, { realms: [state.realm], now: now() });
    const who = by === "recovery" ? "the current recovery public key" : "the account key of the current instance";
    checks = [
      `The proof is signed with ${who}, checked against the newest log.`,
      statement !== undefined
        ? "It signs exactly the statement shown."
        : challengeChecked
          ? "It answers the challenge you entered."
          : "Its challenge was not compared with one of yours.",
      recipientChecked ? `It is addressed to you (“${recipient}”).` : `It is addressed to “${recipient}”.`,
    ];
    const to = hostOf(recipient);
    if (!challengeChecked) {
      stamp = { level: "warn", title: "Signature valid", detail: "challenge not checked" };
      summary = `${state.handle} signed this proof, but nothing shows it was made just now or for you: enter the challenge you gave, or the statement it signs.`;
    } else if (statement !== undefined && !recipientChecked) {
      stamp = { level: "info", title: "Signed statement", detail: `for ${to}` };
      summary = `${state.handle} signed this statement, addressed to “${recipient}”. Anyone holding it can show it again: trust it for what it says, not as a sign-in.`;
    } else if (!recipientChecked) {
      stamp = { level: "warn", title: "Signature valid", detail: `for ${to}` };
      summary = `${state.handle} answered this challenge for “${recipient}”. Enter yourself as the recipient if it is meant for you.`;
    } else {
      stamp = { level: "ok", title: "Proof valid", detail: `for ${to}` };
      summary = statement !== undefined
        ? `${state.handle} signed this statement for you.`
        : `${state.handle} controls this identity now: the proof answers your challenge and is addressed to you.`;
    }
    if (!current) {
      // Without the log of the identity's home, the key that signed may have been replaced since: say "valid", never
      // "controls this identity now".
      const stale = `The log used is not the one at the identity's home, so the ${by === "recovery" ? "recovery" : "account"} key may have been replaced since.`;
      if (stamp.level === "ok") {
        stamp = { level: "warn", title: "Signature valid", detail: "log may be out of date" };
        summary = `${state.handle} signed this ${statement !== undefined ? "statement" : "proof"} for you with the key in the log used. ${stale}`;
      } else summary = `${summary} ${stale}`;
      checks.push(stale);
    }
    note = by === "recovery"
      ? "Proven with the recovery key (root proof)."
      : current ? "Proven with the current account key." : "Proven with the account key of the log used.";
  } catch (e) {
    stamp = { level: "bad", title: "Proof invalid", detail: e.code ?? "error" };
    summary = `This proof does not show that anyone controls ${state.handle}: ${explain(e)}`;
    note = "The identity's log verifies; the proof does not.";
  }
  return { log, state, proof: { stamp, summary, note, facts, checks } };
}

/** Check the pasted proof; only the newest run may touch the page, so typing never shows a stale result. */
async function verifyProofForm() {
  const run = ++proofRun;
  const st = $("proofStatus");
  if (!$("proofText").value.trim()) {
    status(st, "", "");
    return;
  }
  status(st, "busy", "Fetching the log and verifying…");
  try {
    await rc.checkSupport();
    const r = await checkProof($("proofText").value, $("proofChallenge").value, $("proofRecipient").value);
    if (run !== proofRun) return;
    await show(r.log, r.state, r.proof);
    if (run !== proofRun) return;
    status($("lookupStatus"), "", "");
    // The same summary as on the result, next to the field, for when the card is out of view.
    const level = r.proof.stamp.level;
    status(st, level === "bad" ? "error" : level === "info" ? "ok" : level, r.proof.summary);
    $("q").value = r.state.handle;
  } catch (e) {
    if (run !== proofRun) return;
    $("result").hidden = true;
    renderCard(card, { username: "?", realm: REALM, proof: { level: "bad", title: "Not verified", detail: e.code ?? "" } });
    card.classList.add("placeholder");
    $("grid").classList.add("has-result");
    $("cardNote").textContent = "No identity could be verified for this proof.";
    status(st, "error", explain(e));
  }
}

function verifySoon(delay = 350) {
  clearTimeout(proofTimer);
  proofTimer = setTimeout(() => verifyProofForm(), delay);
}

/** Fill the proof form from `#proof=<base64url of { proof, log?, statement? }>` (a link from the account page). */
function fromFragment() {
  const m = /^#proof=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (!m) return false;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(rc.base64urlDecode(m[1]));
    const b = parseBundle(text);
    $("proofText").value = text;
    $("proofChallenge").value = b.hasStatement ? JSON.stringify(b.statement) : "";
    $("proofRecipient").value = "";
    $("proofBox").open = true;
    return true;
  } catch {
    $("proofBox").open = true;
    status($("proofStatus"), "error", "The proof link is damaged.");
    return false;
  }
}

$("lookupForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("lookupForm"), () => lookup($("q").value));
});
$("proofForm").addEventListener("submit", (e) => {
  e.preventDefault();
  verifyProofForm();
});
$("proofText").addEventListener("input", () => {
  // Use the statement that came with a pasted proof, unless the verifier typed one.
  try {
    const b = parseBundle($("proofText").value);
    if (b.hasStatement && !$("proofChallenge").value.trim()) $("proofChallenge").value = JSON.stringify(b.statement);
  } catch {}
  verifySoon();
});
$("proofChallenge").addEventListener("input", () => verifySoon());
$("proofRecipient").addEventListener("input", () => verifySoon());

if (fromFragment()) verifyProofForm();
else {
  const h = new URLSearchParams(location.search).get("h");
  if (h) {
    $("q").value = h;
    busy($("lookupForm"), () => lookup(h));
  }
}
