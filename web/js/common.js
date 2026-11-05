// Shared helpers of the site's pages: talking to this home, explaining errors, rendering ID cards.

import * as rc from "/vendor/rootcard/src/index.js";

export { rc };

/** The realm this home serves. */
export const REALM = "global";

/**
 * The base URL of this home. The pages are served by the host itself, so the address the client signs is the origin
 * it is talking to (HOST_PROTOCOL.md §1, address binding).
 */
export const BASE = location.origin;

export const now = () => Math.floor(Date.now() / 1000);
export const random = (n) => crypto.getRandomValues(new Uint8Array(n));

/** The URL of an endpoint under the API root `<base URL>/v0`. */
export function api(path) {
  return `${BASE}/${rc.API_VERSION}${path}`;
}

/** An error answer of the host that is not one of the specification's codes. */
export class HttpError extends Error {
  constructor(status, body) {
    super(`HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

/** A request to this home. Errors with a code of SPEC §20 become RootcardError, carrying the answer as `body`. */
export async function http(method, path, body, token) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(api(path), {
      method,
      headers,
      body: body === undefined ? undefined : rc.canonicalString(body),
      credentials: "omit",
      cache: "no-store",
    });
  } catch {
    throw new Error("Could not reach rootcard.org. Check your connection and try again.");
  }
  const text = await res.text();
  let value = null;
  if (text) {
    try {
      value = rc.parseJson(new TextEncoder().encode(text));
    } catch {
      value = null;
    }
  }
  if (!res.ok) {
    const code = value?.error;
    if (code && rc.ERROR_CODES.includes(code)) {
      const e = new rc.RootcardError(code);
      e.body = value;
      throw e;
    }
    throw new HttpError(res.status, value);
  }
  return value;
}

const WHY = {
  weak_password: "The password is too weak: use at least 12 characters, and not your username.",
  bad_username: "Usernames are 3–20 letters, digits, - or _, starting with a letter.",
  username_policy: "Usernames are 3–20 letters, digits, - or _, starting with a letter.",
  handle_taken: "That exact handle is taken. Try again: a new card gets a new tag.",
  bad_handle: "That does not look like a handle. It is the name, a # and the 4-character tag, like Astra#3F9C.",
  unknown_account: "No identity with that handle is known here.",
  ambiguous_handle: "Several identities share that handle. Use the longer tag shown on the card.",
  unauthorized: "Wrong password, or the session has ended.",
  unlock_failed: "Wrong password.",
  not_home: "This identity's home is another server. Sign in there.",
  rate_limited: "Too many attempts. Wait a little and try again.",
  account_retired: "This identity has been retired by its owner.",
  unsupported_browser: "This browser lacks WebCrypto Ed25519 and X25519. Use a current Chrome, Edge, Firefox or Safari.",
  stale_version: "The identity changed meanwhile. Reload and try again.",
  challenge_expired: "That took too long. Try again.",
  wrong_host: "This home does not hold that identity's current instance.",
  wrong_recipient: "The proof is addressed to someone else.",
  wrong_challenge: "The proof was made for another challenge.",
  bad_signature: "A signature does not verify.",
  too_large: "That is too large.",
  bad_data_key: "That profile field is not allowed.",
};

/** A sentence for an error. */
export function explain(e) {
  if (e instanceof rc.RootcardError || (e && typeof e.code === "string" && rc.ERROR_CODES.includes(e.code))) {
    return `${WHY[e.code] ?? "Something went wrong."} (${e.code})`;
  }
  if (e instanceof HttpError) return e.status >= 500 ? "The server had a problem. Try again in a moment." : e.message;
  return String(e?.message ?? e);
}

/** Show a notice in `el`: kind is "ok", "warn", "error", "info" or "busy". */
export function status(el, kind, text) {
  el.replaceChildren();
  if (!text) return;
  const n = document.createElement("div");
  n.className = kind === "busy" ? "notice" : `notice ${kind === "info" ? "" : kind}`;
  if (kind === "busy") {
    n.classList.add("busy");
    const s = document.createElement("span");
    s.className = "spinner";
    n.append(s);
  }
  const p = document.createElement("p");
  p.textContent = text;
  n.append(p);
  el.append(n);
}

/** Run `f` with the buttons of `form` disabled. */
export async function busy(form, f) {
  const buttons = [...form.querySelectorAll("button")];
  buttons.forEach((b) => (b.disabled = true));
  try {
    return await f();
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

/** Save `value` as a JSON file. */
export function download(name, value, type = "application/json") {
  const text = typeof value === "string" ? value : rc.canonicalString(value) + "\n";
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

let worker;
let next = 0;
const pending = new Map();

/** Run an operation of js/worker.js (Argon2id off the main thread). */
export function work(op, ...args) {
  if (!worker) {
    worker = new Worker("/js/worker.js", { type: "module" });
    worker.onmessage = ({ data }) => {
      const p = pending.get(data.id);
      if (!p) return;
      pending.delete(data.id);
      if (data.error) {
        const e = data.error.code ? new rc.RootcardError(data.error.code) : new Error(data.error.message);
        p.reject(e);
      } else p.resolve(data.result);
    };
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(e.message || "worker failed"));
      pending.clear();
    };
  }
  const id = ++next;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}

/** The account id in groups of four. */
export function groups(account) {
  return account.match(/.{1,4}/g).join(" ");
}

function h(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/**
 * Render an ID card into `el`. `c`: `{ username, account, realm, home?, since?, display?, verified?, recovery?, key? }`.
 * Every value is set as text, never as markup: profile data is written by the identity's owner.
 */
export function renderCard(el, c) {
  el.replaceChildren();
  el.classList.add("idcard");
  el.classList.toggle("recovery", Boolean(c.recovery));
  const top = h("div", "ic-top");
  const brand = h("div", "ic-brand");
  const logo = document.createElement("img");
  logo.src = "/img/logo.svg";
  logo.alt = "";
  brand.append(logo, h("span", "", "rootcard"));
  const right = h("span", "ic-right");
  if (c.verified) {
    const v = h("span", "ic-verified");
    v.append(h("span", "dot"), document.createTextNode("Verified"));
    right.append(v);
  }
  right.append(h("span", "ic-kind", c.recovery ? "Recovery card" : `Identity · ${c.realm ?? REALM}`));
  top.append(brand, right);

  const mid = h("div", "ic-mid");
  const chip = document.createElement("img");
  chip.src = "/img/chip.svg";
  chip.alt = "";
  chip.className = "ic-chip";
  const name = h("div", "ic-name");
  name.append(h("div", "ic-label", c.recovery ? "Keep offline · controls the identity" : "Handle"));
  const handle = h("div", "ic-handle");
  handle.append(document.createTextNode(c.username ?? "you"), h("span", "tag", `#${c.account ? rc.tag(c.account) : "····"}`));
  name.append(handle);
  if (c.display) name.append(h("div", "ic-display", c.display));
  mid.append(chip, name);

  const bottom = h("div", "ic-bottom");
  if (c.recovery && c.key) {
    bottom.append(h("div", "ic-key", c.key));
  } else {
    const id = h("div", "ic-id");
    id.append(h("div", "ic-label", "Account id"), document.createTextNode(c.account ? groups(c.account) : "···· ···· ···· ····"));
    bottom.append(id);
  }
  const meta = h("div", "ic-meta");
  if (!c.recovery) {
    meta.append(h("span", "ic-label", "Home"), h("b", "", c.home ? hostOf(c.home) : "—"));
    if (c.since) meta.append(h("span", "ic-label", `Since ${new Date(c.since * 1000).toISOString().slice(0, 10)}`));
  } else {
    meta.append(h("span", "ic-label", c.realm ?? REALM));
  }
  bottom.append(meta);
  el.append(top, mid, bottom);
}

/** A subtle 3D tilt that follows the pointer. */
export function tilt(el, base = "") {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  el.addEventListener("pointermove", (e) => {
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    el.style.transform = `${base} rotateY(${x * 14}deg) rotateX(${-y * 14}deg)`;
    el.style.setProperty("--sheen", `${100 - (x + 0.5) * 100}%`);
  });
  el.addEventListener("pointerleave", () => {
    el.style.transform = base;
    el.style.removeProperty("--sheen");
  });
}

/** The time of the event that made the current instance, for "since". */
export function instanceTime(log, state) {
  const e = state.instance ? log[state.instance.seq] : undefined;
  return e?.time ?? log.find((x) => Number.isInteger(x?.time))?.time;
}

/** Fetch and verify an identity's log from this home ([LOG-12]). */
export async function fetchLog(account) {
  const v = await http("GET", `/id/${account}/log`);
  const state = await rc.verifyLog(v.events, { realms: [REALM], now: now() });
  if (state.account !== account) throw new rc.RootcardError("account_mismatch");
  return { log: v.events, state };
}
