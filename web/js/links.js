// Linked accounts (SPEC §12.3), shared by the card page and the account page.
//
// The core says what to fetch (linkRequests) and decides from the answers (checkLink); this module does the fetching,
// under the rules of [LNK-9]: HTTPS, no redirects, no credentials, at most RESPONSE_LIMIT bytes, FETCH_TIMEOUT_SECS.
// TXT records come from the DNS-over-HTTPS resolver of home.toml. Answers are data: they are parsed or searched for the
// token, never rendered. A check runs only when the user asks for one, because it contacts the linked service from the
// user's browser. A result is this browser's own ([LNK-11]), shown with the time it was checked.

import { HOME, rc } from "/js/common.js";

/** The bundled service registry ([LNK-19]): never loaded from anywhere else. */
export const REGISTRY = rc.registry();

/** What the pages say about each service of the registry; a service not listed here is shown with generic words. */
const HELP = {
  github: {
    label: "GitHub",
    name: "GitHub username",
    uid: "GitHub user id",
    uidHint: "The number GitHub keeps when a username changes. Filled in from the username.",
    forms: {
      bio: { label: "In my GitHub profile bio", where: () => "Put the token in your GitHub profile bio (Settings → Public profile → Bio)." },
      gist: {
        label: "In a public gist",
        value: "Gist id",
        valueHint: "The hex part of the gist's address, gist.github.com/you/<id>.",
        where: () => "Create a public gist whose content holds the token, and enter its id.",
      },
    },
  },
  web: {
    label: "Website",
    name: "Domain",
    nameHint: "Lower-case, without https:// (for example example.com). Internationalized names in their xn-- form.",
    where: (l) =>
      `Serve the token as text at https://${l.name || "<domain>"}/.well-known/rootcard-link, without a redirect and with the header “Access-Control-Allow-Origin: *”, so that browsers can check it.`,
  },
  dns: {
    label: "Domain (DNS)",
    name: "Domain",
    nameHint: "Lower-case, without https:// (for example example.com).",
    where: (l) => `Add a TXT record at _rootcard.${l.name || "<domain>"} whose text holds the token.`,
  },
};

/** The services a user can add: those of the registry that are not retired. */
export const SERVICES = REGISTRY.filter((d) => !d.retired);

export function help(service) {
  return HELP[service] ?? {};
}

export function serviceLabel(service) {
  return HELP[service]?.label ?? service;
}

/** Where the token goes for a link, as a sentence. */
export function whereToken(link) {
  const h = help(link.service);
  const form = link.ref === undefined ? undefined : link.ref.split(":")[0];
  if (form !== undefined) return h.forms?.[form]?.where?.(link) ?? `Put the token where the service's “${form}” check reads it.`;
  return h.where?.(link) ?? "Put the token where only the account's owner can write.";
}

/** Read at most RESPONSE_LIMIT bytes of a 200 answer; null for anything else ([LNK-9]). */
async function body(res) {
  if (res.status !== 200 || !res.body) return null;
  const reader = res.body.getReader();
  const parts = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > rc.RESPONSE_LIMIT) {
      reader.cancel().catch(() => {});
      return null;
    }
    parts.push(value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** A GET under [LNK-9]: the body of a 200 answer, or null. */
async function get(url, accept) {
  if (!url.startsWith("https://")) return null;
  const signal = AbortSignal.timeout(rc.FETCH_TIMEOUT_SECS * 1000);
  try {
    const res = await fetch(url, {
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      headers: accept ? { Accept: accept } : undefined,
      signal,
    });
    return await body(res);
  } catch {
    return null;
  }
}

/**
 * The strings of a TXT record in a DNS-over-HTTPS JSON answer: quoted character strings (`"a" "b"`, with `\"`, `\\` and
 * `\DDD` escapes), or one unquoted string as some resolvers give it.
 */
export function txtStrings(data) {
  const enc = new TextEncoder();
  if (!data.startsWith('"')) return [enc.encode(data)];
  const out = [];
  let i = 0;
  while (i < data.length) {
    if (data[i] === " ") {
      i++;
      continue;
    }
    if (data[i] !== '"') throw new rc.RootcardError("bad_field");
    i++;
    const bytes = [];
    for (;;) {
      if (i >= data.length) throw new rc.RootcardError("bad_field");
      const c = data[i];
      if (c === '"') {
        i++;
        break;
      }
      if (c === "\\") {
        const d = data.slice(i + 1, i + 4);
        if (/^[0-9]{3}$/.test(d) && Number(d) < 256) {
          bytes.push(Number(d));
          i += 4;
        } else if (i + 1 < data.length) {
          bytes.push(...enc.encode(data[i + 1]));
          i += 2;
        } else throw new rc.RootcardError("bad_field");
        continue;
      }
      const cp = data.codePointAt(i);
      const ch = String.fromCodePoint(cp);
      bytes.push(...enc.encode(ch));
      i += ch.length;
    }
    out.push(new Uint8Array(bytes));
  }
  return out;
}

/** The TXT records of `name` from the resolver, as lists of strings; null when the lookup failed. */
async function resolveTxt(name) {
  const url = `${HOME.dnsResolver}?name=${encodeURIComponent(name)}&type=TXT`;
  const b = await get(url, "application/dns-json");
  if (!b) return null;
  try {
    const v = rc.parseResponseJson(b);
    if (v === null || typeof v !== "object") return null;
    if (v.Status === 3) return []; // NXDOMAIN: no record, so no token
    if (v.Status !== 0) return null;
    const answers = Array.isArray(v.Answer) ? v.Answer : [];
    return answers.filter((a) => a?.type === 16 && typeof a.data === "string").map((a) => txtStrings(a.data));
  } catch {
    return null;
  }
}

/** The answer to one request of linkRequests: null (failed), `{ body }` or `{ txt }`. */
async function answer(req) {
  if (req.kind === "dns-txt") {
    const txt = await resolveTxt(req.name);
    return txt === null ? null : { txt };
  }
  const b = await get(req.url);
  return b === null ? null : { body: b };
}

/** The hosts a check of `link` contacts, for the page to say before it checks. */
export function contacts(link) {
  const d = rc.findDescriptor(REGISTRY, link.service);
  if (!d) return [];
  const hosts = new Set();
  for (const r of rc.linkRequests(link, d)) {
    if (r.kind === "dns-txt") hosts.add(new URL(HOME.dnsResolver).host);
    else hosts.add(new URL(r.url).host);
  }
  return [...hosts];
}

/**
 * Check a link in this browser ([LNK-10]): `{ result, at }`, where result is "verified" or the error code
 * (wrong_owner, token_missing, fetch_failed, …).
 */
export async function check(link, account) {
  const d = rc.findDescriptor(REGISTRY, link.service);
  if (!d) return { result: "unsupported", at: new Date() };
  try {
    const answers = await Promise.all(rc.linkRequests(link, d).map(answer));
    rc.checkLink(link, account, d, answers);
    return { result: "verified", at: new Date() };
  } catch (e) {
    if (e instanceof rc.RootcardError) return { result: e.code, at: new Date() };
    throw e;
  }
}

/** GitHub's stable id and current login for a username, for the account page to fill in; null when not found. */
export async function githubUser(name) {
  if (!/^[A-Za-z0-9-]{1,39}$/.test(name)) return null;
  const b = await get(`https://api.github.com/users/${encodeURIComponent(name)}`);
  if (!b) return null;
  try {
    const v = rc.parseResponseJson(b);
    if (!Number.isSafeInteger(v?.id) || typeof v?.login !== "string") return null;
    return { uid: String(v.id), name: v.login };
  } catch {
    return null;
  }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function when(d) {
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** The status of a link as LNK-12 names them: `{ level, badge, text }`. */
export function statusOf(entry, outcome) {
  if (entry.status === "unsupported") {
    return { level: "", badge: "unsupported", text: `Unsupported: ${HOME.name} cannot check this service. Shown as text only.` };
  }
  if (entry.status !== "ok") {
    return { level: "bad", badge: "invalid", text: "Invalid: this link breaks the rules of its service, and is not shown to others." };
  }
  if (!outcome) return { level: "", badge: "not checked", text: "Not checked yet." };
  const at = when(outcome.at);
  switch (outcome.result) {
    case "verified":
      return { level: "ok", badge: "verified", text: `Verified by this browser, ${at}: the token is where only the account's owner can write.` };
    case "wrong_owner":
      return { level: "bad", badge: "not verified", text: `Not verified (${at}): the account there now belongs to someone else, or its name changed.` };
    case "token_missing":
      return { level: "warn", badge: "not verified", text: `Not verified (${at}): the token is not where the link says.` };
    case "fetch_failed":
      return {
        level: "warn",
        badge: "not checked",
        text: `Not checked (${at}): the service did not answer this browser (unreachable, a redirect, refused, or rate limited). Try again later.`,
      };
    default:
      return { level: "bad", badge: "not verified", text: `Not verified (${at}): ${outcome.result}.` };
  }
}

/**
 * Render links into `ul`. `entries` are parseLinks' `{ link?, status }`; `outcomes` a Map from entry to the last check.
 * `owner`: invalid links are shown (to their owner only, [LNK-12]) and get a Remove button calling `onRemove(i)`.
 * `onCheck(i)` checks one link. Names, uids and refs are set as text, never as markup ([DAT-8]); the display URL comes
 * from the bundled descriptor, never from profile data ([LNK-8]).
 */
export function renderLinks(ul, entries, outcomes, { owner = false, onCheck, onRemove } = {}) {
  ul.replaceChildren();
  entries.forEach((entry, i) => {
    if (!owner && entry.status === "bad_link") return;
    const li = el("li", "link-item");
    const head = el("div", "link-head");
    const link = entry.link;
    const d = link && entry.status === "ok" ? rc.findDescriptor(REGISTRY, link.service) : undefined;
    head.append(el("span", "link-service", link ? serviceLabel(link.service) : "Invalid link"));
    if (link) {
      if (d) {
        const a = el("a", "link-name", link.name);
        a.href = rc.linkDisplay(link, d);
        a.rel = "noopener noreferrer nofollow ugc";
        a.target = "_blank";
        head.append(a);
      } else head.append(el("span", "link-name", link.name));
    }
    const s = statusOf(entry, outcomes.get(entry));
    head.append(el("span", `badge ${s.level}`, s.badge));
    li.append(head, el("p", "link-detail muted", s.text));
    const row = el("div", "btn-row link-actions");
    if (entry.status === "ok" && onCheck) {
      const b = el("button", "btn btn-sm", outcomes.get(entry) ? "Check again" : "Check");
      b.type = "button";
      b.title = `Contacts ${contacts(link).join(", ")} from this browser`;
      b.addEventListener("click", () => onCheck(i));
      row.append(b);
    }
    if (owner && onRemove) {
      const b = el("button", "btn btn-sm btn-ghost", "Remove");
      b.type = "button";
      b.addEventListener("click", () => onRemove(i));
      row.append(b);
    }
    if (row.childElementCount) li.append(row);
    ul.append(li);
  });
}
