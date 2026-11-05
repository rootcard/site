// Public card lookup: resolve a handle ([HDL-3]), fetch the log and verify it ([LOG-12]), then the profile ([DAT-2]).

import { REALM, busy, explain, fetchLog, groups, http, instanceTime, rc, renderCard, status, tilt } from "/js/common.js";

const $ = (id) => document.getElementById(id);
const card = $("card");
renderCard(card, { username: "Astra", realm: REALM });
card.classList.add("placeholder");
tilt(card);

function fact(dl, k, v, mono) {
  const dt = document.createElement("dt");
  dt.textContent = k;
  const dd = document.createElement("dd");
  dd.textContent = v;
  if (mono) dd.className = "mono";
  dl.append(dt, dd);
}

function li(text) {
  const e = document.createElement("li");
  e.textContent = text;
  return e;
}

async function resolve(q) {
  const t = q.trim().replace(/\s+/g, "");
  if (/^[0-9A-Za-z]{52}$/.test(t) && !t.includes("#")) {
    const account = t.toUpperCase();
    return account;
  }
  rc.parseHandle(q.trim());
  const found = await http("GET", `/id/lookup?realm=${encodeURIComponent(REALM)}&handle=${encodeURIComponent(q.trim())}`);
  return found.account;
}

async function lookup(q) {
  const st = $("lookupStatus");
  status(st, "busy", "Fetching and verifying…");
  $("result").hidden = true;
  try {
    await rc.checkSupport();
    const account = await resolve(q);
    const { log, state } = await fetchLog(account);
    let data = {};
    let profileOk = false;
    if (state.instance && !state.retired) {
      try {
        const pub = await http("GET", `/id/${account}/public`);
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
    });
    card.classList.remove("placeholder");
    $("cardNote").textContent = state.retired ? "This identity is retired." : "Verified against its public log.";
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
    fact(dl, "Recovery key", state.recovery, true);
    const checks = $("rChecks");
    checks.replaceChildren(
      li("The account id is the SHA-256 of the inception, which the recovery key signed."),
      li(`Every one of the ${log.length} log events links to the one before and carries the signatures it needs.`),
    );
    if (state.instance) checks.append(li("The current instance carries the home's receipt."));
    if (profileOk) checks.append(li("The public profile is signed by the current account key."));
    checks.append(li("Anything the profile says was written by the identity's owner, not checked by anyone."));
    $("result").hidden = false;
    status(st, "", "");
    history.replaceState(null, "", `/card?h=${encodeURIComponent(state.handle)}`);
  } catch (e) {
    if (e.code === "ambiguous_handle" && Array.isArray(e.body?.candidates)) {
      status(st, "warn", `Several identities match: ${e.body.candidates.map((c) => c.handle).join(", ")}. Use the longer tag.`);
    } else status(st, "error", explain(e));
  }
}

$("lookupForm").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("lookupForm"), () => lookup($("q").value));
});
const h = new URLSearchParams(location.search).get("h");
if (h) {
  $("q").value = h;
  busy($("lookupForm"), () => lookup(h));
}
