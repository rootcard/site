// Error codes (SPEC §20).

/** Every error code of SPEC §20, in its order. */
export const ERROR_CODES = Object.freeze([
  "bad_json", "bad_field", "unsupported_version", "too_large", "bad_base64", "bad_base32", "bad_checksum", "bad_key",
  "bad_signature", "bad_realm", "realm_not_accepted", "bad_username", "username_policy", "bad_handle", "handle_taken",
  "ambiguous_handle", "account_mismatch", "wrong_recovery_key", "too_many_events", "bad_kind", "bad_seq", "bad_prev",
  "time_backwards", "future_time", "bad_time", "wrong_signer", "key_reuse", "bad_receipt", "bad_reason",
  "account_retired", "no_instance", "stale_version", "fork", "wrong_instance", "stale_rev", "stale_locks", "bad_locks",
  "kdf_params", "weak_password", "unlock_failed", "wrong_account_key", "bad_data_key", "wrong_challenge",
  "wrong_recipient", "challenge_unknown", "challenge_expired", "not_home", "wrong_host", "unknown_account",
  "unauthorized", "rate_limited", "unsupported_browser",
]);

/** A rootcard error. `code` is one of the stable codes of SPEC §20. */
export class RootcardError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "RootcardError";
    this.code = code;
  }
}

/** Throw the error `code`. @param {string} code @returns {never} */
export function fail(code) {
  throw new RootcardError(code);
}

/** Run `f`, replacing any RootcardError by `code`. */
export function remap(code, f) {
  try {
    return f();
  } catch (e) {
    if (e instanceof RootcardError) fail(code);
    throw e;
  }
}
