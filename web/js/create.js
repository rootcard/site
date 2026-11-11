// Registration with this home ([CLT-1], HOST_PROTOCOL.md §7 "Registration"):
//   GET /host → build the inception, the pending instance (home = this host), the vault and an empty profile in the
//   browser → the user saves the recovery card → POST /id/register → fetch the log back and verify it.

import { BASE, HOME, REALM, busy, download, explain, fetchLog, http, instanceTime, now, rc, renderCard, status, tilt, work } from "/js/common.js";
import { checkPassword } from "/vendor/rootcard/src/vault.js";

const $ = (id) => document.getElementById(id);
const preview = $("preview");
let reg = null; // { card, account, text }
let done = null; // { state, log, public, vault }
let cardSaved = false;
let built = null; // { r, at }: a built registration, resent unchanged on a retry ([HST-20])
let registered = null; // { account, public, vault }: accepted by the host; only the check of its log is left

function showPreview(extra = {}) {
  const username = $("username").value.trim() || "you";
  renderCard(preview, { username, realm: REALM, home: BASE, ...extra });
}
showPreview();
tilt(preview);

function step(n) {
  for (const li of $("wizard").children) {
    const s = Number(li.dataset.step);
    li.classList.toggle("active", s === n);
    li.classList.toggle("done", s < n);
  }
  $("step1").hidden = n !== 1;
  $("step2").hidden = n !== 2;
  $("step3").hidden = n !== 3;
  $("wizard").scrollIntoView({ block: "nearest", behavior: "smooth" });
}

$("username").addEventListener("input", () => {
  const u = $("username").value.trim();
  $("handlePreview").textContent = `${u || "you"}#····`;
  showPreview();
});

function strength(pw) {
  const n = [...pw.normalize("NFC")].length;
  let score = Math.min(n / 20, 1) * 70;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 10;
  if (/\d/.test(pw)) score += 10;
  if (/[^A-Za-z0-9]/.test(pw)) score += 10;
  if (n < 12) score = Math.min(score, 30);
  return Math.round(Math.min(score, 100));
}
$("password").addEventListener("input", () => {
  const s = strength($("password").value);
  const m = $("meter");
  m.style.width = `${s}%`;
  m.style.background = s < 40 ? "var(--danger)" : s < 70 ? "var(--warn)" : "var(--ok)";
});

function checkInputs() {
  const username = $("username").value.trim();
  const password = $("password").value;
  for (const id of ["username", "password", "password2"]) $(id).removeAttribute("aria-invalid");
  try {
    rc.checkUsername(username);
    if (!rc.defaultUsernamePolicy(username)) throw new rc.RootcardError("username_policy");
  } catch (e) {
    $("username").setAttribute("aria-invalid", "true");
    throw e;
  }
  try {
    checkPassword(password, username);
  } catch (e) {
    $("password").setAttribute("aria-invalid", "true");
    throw e;
  }
  if ($("password2").value !== password) {
    $("password2").setAttribute("aria-invalid", "true");
    throw new Error("The passwords do not match.");
  }
  return { username, password };
}

$("step1").addEventListener("submit", (e) => {
  e.preventDefault();
  const form = $("step1");
  busy(form, async () => {
    try {
      const { username } = checkInputs();
      status($("status1"), "busy", "Generating your recovery key…");
      await rc.checkSupport();
      const p = await work("prepare", REALM, username);
      reg = { ...p, text: await rc.cardText(p.card) };
      built = null;
      cardSaved = false;
      $("saved").checked = false;
      $("activate").disabled = true;
      $("cardText").textContent = reg.text;
      const printArea = $("printArea");
      printArea.replaceChildren();
      const h = document.createElement("h1");
      h.textContent = "rootcard recovery card";
      const body = document.createElement("div");
      body.textContent = reg.text.replace(/^rootcard recovery card\n\n/, "");
      printArea.append(h, body);
      renderCard(preview, { username, account: p.account, realm: REALM, recovery: true, key: reg.text.match(/RCR [^\n]+/)?.[0] });
      $("previewNote").textContent = "Your recovery card. Save it before you continue.";
      status($("status1"), "", "");
      step(2);
    } catch (err) {
      status($("status1"), "error", explain(err));
    }
  });
});

function updateActivate() {
  $("activate").disabled = !($("saved").checked && cardSaved);
  if ($("saved").checked && !cardSaved) status($("status2"), "warn", "Download or print the card first.");
  else status($("status2"), "", "");
}
$("saved").addEventListener("change", updateActivate);
$("saveCard").addEventListener("click", () => {
  download(`${reg.card.username}-${rc.tag(reg.account)}.card.json`, reg.card);
  cardSaved = true;
  updateActivate();
});
$("printCard").addEventListener("click", () => {
  window.print();
  cardSaved = true;
  updateActivate();
});
async function startOver() {
  await work("forget");
  reg = null;
  built = null;
  registered = null;
  $("restart").hidden = false;
  $("activate").textContent = "Activate my ID card";
  showPreview();
  $("previewNote").textContent = "A preview. The tag and the account id come from your key.";
  step(1);
}
$("restart").addEventListener("click", () => startOver());

$("activate").addEventListener("click", () => {
  const panel = $("step2");
  busy(panel, async () => {
    try {
      if (!registered) {
        const { password } = checkInputs();
        status($("status2"), "busy", `Asking ${HOME.name} for its host key…`);
        const d = await http("GET", "/host");
        rc.parseKey(d.key, "ed25519");
        if (!Array.isArray(d.urls) || !d.urls.includes(BASE)) {
          throw new Error(`This page is served from ${BASE}, which is not one of the host's addresses.`);
        }
        if (!d.realms?.some((r) => r.realm === REALM)) throw new rc.RootcardError("realm_not_accepted");
        // A retry resends exactly what was built, so a registration that arrived but whose answer was lost is
        // recognized ([HST-20]). Only a stale build is rebuilt: the host receipts instances from the last 10 minutes.
        if (!built || now() - built.at > 300) {
          status($("status2"), "busy", "Sealing your vault with your password (Argon2id, 64 MiB). This takes a few seconds…");
          const at = now();
          built = { r: await work("register", password, { key: d.key, url: BASE }, at, rc.KDF_DEFAULT), at };
        }
        const r = built.r;
        status($("status2"), "busy", `Registering with ${HOME.name}…`);
        await http("POST", "/id/register", { log: r.log, vault: r.vault, public: r.public });
        // From here on the identity exists: the recovery key is erased and the card the user saved is the only copy.
        // Whatever fails next, this page must not offer to start over, which would make a second identity.
        registered = { account: r.account, public: r.public, vault: r.vault };
        built = null;
        await work("forget");
        $("restart").hidden = true;
        $("activate").textContent = "Check my ID card again";
      }
      status($("status2"), "busy", "Verifying your identity's log…");
      let fetched;
      try {
        fetched = await fetchLog(registered.account);
      } catch (err) {
        throw new Error(`Your identity is registered with ${HOME.name} and your recovery card is valid, but checking its log failed. ${explain(err)}`);
      }
      const { log, state } = fetched;
      done = { log, state, public: registered.public, vault: registered.vault };
      $("password").value = "";
      $("password2").value = "";
      renderCard(preview, {
        username: state.username,
        account: state.account,
        realm: state.realm,
        home: state.instance?.home.url,
        since: instanceTime(log, state),
        verified: true,
      });
      $("previewNote").textContent = "Your ID card. Anyone can verify it against your public log.";
      $("doneHandle").textContent = state.handle;
      $("signin").href = `/account?h=${encodeURIComponent(state.handle)}`;
      $("viewCard").href = `/card?h=${encodeURIComponent(state.handle)}`;
      step(3);
    } catch (err) {
      if (err?.code === "handle_taken") {
        // The tag comes from the recovery key, so only a new key gives a new handle. The saved card is for a key that
        // was never registered.
        await startOver();
        status($("status1"), "error", "That exact handle is taken by another identity. Delete or shred the recovery card you just saved: it belongs to a key that was not registered. Create a new card to get a new tag.");
        return;
      }
      status($("status2"), "error", explain(err));
    }
  });
});

$("saveAccount").addEventListener("click", () => {
  if (!done) return;
  download(rc.accountFileName(done.state), rc.exportAccount(done.state, done.log, done.public, done.vault));
});
