// The HTTP binding's version and base URLs (HOST_PROTOCOL.md §1, §1.3; SPEC [HST-22]). The core makes no requests;
// these let hosts, clients and the key tool agree on where endpoints live. Mirrors `rootcard::binding`.

import { fail } from "./errors.js";
import { validate } from "./json.js";
import * as s from "./keys.js";
import { checkUrl } from "./log.js";

/**
 * The version segment of the HTTP binding: every endpoint is under `<base URL>/v0` until 1.0.0, then under `/v1`.
 * It is never part of a base URL, `home.url` or anything signed.
 */
export const API_VERSION = "v0";

/** Whether a path segment has the form of an API version (`v0`, `V12`). */
export function isVersionSegment(segment) {
  return /^[vV][0-9]+$/.test(segment);
}

// A base URL path segment ([HST-22]): non-empty, only unreserved characters (no percent-encoding), not a dot segment.
function isPathSegment(segment) {
  return /^[A-Za-z0-9\-._~]+$/.test(segment) && segment !== "." && segment !== "..";
}

function authorityHost(rest) {
  const authority = rest.split("/")[0];
  if (authority.startsWith("[")) {
    const i = authority.indexOf("]");
    return i < 0 ? "" : authority.slice(0, i + 1);
  }
  return authority.split(":")[0];
}

/**
 * Check a base URL ([HST-22]): `https://` and a host, an optional port and an optional path without a trailing slash,
 * query, fragment or user info; plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`; path segments of
 * unreserved characters only, never `.` or `..`; and its last path segment is not an API version segment. → `bad_field`
 */
export function checkBaseUrl(url) {
  checkUrl(url);
  let rest;
  if (url.startsWith("https://")) rest = url.slice(8);
  else if (url.startsWith("http://")) {
    rest = url.slice(7);
    if (!["localhost", "127.0.0.1", "[::1]"].includes(authorityHost(rest))) fail("bad_field");
  } else fail("bad_field");
  if (/[?#@\\]/.test(rest)) fail("bad_field");
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  if (authorityHost(authority) === "" || !/^[A-Za-z0-9.\-:[\]]+$/.test(authority)) fail("bad_field");
  if (slash >= 0) {
    const segments = rest.slice(slash + 1).split("/");
    if (!segments.every(isPathSegment)) fail("bad_field");
    if (isVersionSegment(segments[segments.length - 1])) fail("bad_field");
  }
}

/**
 * The well-known path of a host pointer ([HST-23], RFC 8615), at the root of an origin. It carries no API version: the
 * pointer lists the versions the host serves.
 */
export const WELL_KNOWN_PATH = "/.well-known/rootcard";

/** The largest host pointer a client reads, in bytes ([HST-23]); pass it to `parseLimited`. */
export const WELL_KNOWN_LIMIT = 4096;

/** The most API versions a host pointer may list ([HST-23]). */
export const MAX_WELL_KNOWN_APIS = 16;

/**
 * Whether a base URL ([HST-22]) is an origin: a base URL without a path. Only an origin is resolved through
 * `WELL_KNOWN_PATH` ([HST-23]); an address with a path is already a base URL.
 */
export function isOrigin(url) {
  try {
    checkBaseUrl(url);
  } catch {
    return false;
  }
  return !url.slice(url.indexOf("://") + 3).includes("/");
}

/**
 * Resolve a host pointer ([HST-23]): the document served at `<origin>/.well-known/rootcard`, which names the host's base
 * URL on that origin. `origin` is the address the client fetched it from, as the user typed it, never a value received.
 * Checks, in order: `origin` is an origin → `bad_field`; the schema `{ v: 1, base, api }` → `bad_field`,
 * `unsupported_version`; `base` is a base URL ([HST-22]) and `api` is 1 to 16 distinct API version segments →
 * `bad_field`; `base` is on `origin` (the same scheme, host and port, the host compared without regard to ASCII case)
 * → `wrong_host`; `api` lists `API_VERSION` → `unsupported_version`. Returns `base`, the address to use and to put into
 * an instance's `home.url`.
 */
export function wellKnownBase(origin, document) {
  if (!isOrigin(origin)) fail("bad_field");
  validate(document);
  const m = s.object(document);
  s.version(m);
  s.members(m, ["v", "base", "api"]);
  const base = s.string(m, "base");
  checkBaseUrl(base);
  const api = s.array(m, "api");
  if (api.length === 0 || api.length > MAX_WELL_KNOWN_APIS) fail("bad_field");
  const versions = [];
  for (const v of api) {
    if (typeof v !== "string" || !isVersionSegment(v) || versions.includes(v)) fail("bad_field");
    versions.push(v);
  }
  const start = base.indexOf("://") + 3;
  const slash = base.indexOf("/", start);
  const baseOrigin = slash < 0 ? base : base.slice(0, slash);
  if (!asciiEqualIgnoreCase(baseOrigin, origin)) fail("wrong_host");
  if (!versions.includes(API_VERSION)) fail("unsupported_version");
  return base;
}

function asciiEqualIgnoreCase(a, b) {
  const lower = (x) => x.replace(/[A-Z]/g, (c) => c.toLowerCase());
  return a.length === b.length && lower(a) === lower(b);
}
