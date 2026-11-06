// The HTTP binding's version and base URLs (HOST_PROTOCOL.md §1, §1.3; SPEC [HST-22]). The core makes no requests;
// these let hosts, clients and the key tool agree on where endpoints live. Mirrors `rootcard::binding`.

import { fail } from "./errors.js";
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
