// rootcard: a portable, self-certifying identity for online logins.
//
// This package mirrors the `rootcard` Rust crate byte for byte. The normative format is spec/SPEC.md in the repository,
// and spec/vectors/ holds the shared test vectors both implementations reproduce. This module is the verification
// core; the vault cryptography (passwords, Argon2id, encryption) is in "rootcard/vault".
//
// Status: 0.x. Nothing here is stable before 1.0.0.

export { FORMAT_VERSION, LABEL_PREFIX, label } from "./labels.js";
export { API_VERSION, checkBaseUrl, isVersionSegment } from "./binding.js";
export { ERROR_CODES, RootcardError } from "./errors.js";
export { canonical, canonicalString, parseJson, parseLimited, validate } from "./json.js";
export {
  base64urlEncode, base64urlDecode, base32Encode, base32Decode, base32DecodeLenient, hexEncode, hexDecode,
} from "./encoding.js";
export { checkSupport, sha256, ed25519Public, ed25519PublicIs, ed25519Sign, ed25519Verify, ed25519SigningKey, usableSeed } from "./crypto.js";
export { formatKey, parseKey } from "./keys.js";
export { formatRecoveryKey, parseRecoveryKey, deriveRecoveryKeys, newRecoveryKey, checkNewRecoveryKey } from "./recovery.js";
export {
  checkRealm, checkUsername, defaultUsernamePolicy, similarUsernames, accountId, inception, tag, handle, parseHandle,
  handleMatches, extendedTags,
} from "./id.js";
export {
  MAX_EVENTS, verifyLog, extendLog, verifyPending, compareLogs, eventHash, eventMessage, receiptMessage, unsignedEvent,
  signEvent, addReceipt, pendingInstance, rotateRecoveryEvent, retireEvent, checkRecoveryKey, checkUrl,
} from "./log.js";
export { verifyVault, vaultChange, KDF_DEFAULT, KDF_MIN } from "./vaultcheck.js";
export { checkDataKey, setData, removeData, signPublic, verifyPublic } from "./profile.js";
export {
  parseChallenge, loginMessage, fetchMessage, changeMessage, signLogin, parseLoginRequest, verifyLogin,
} from "./messages.js";
export { statementChallenge, prove, verifyProof } from "./proof.js";
export { exportAccount, importAccount, accountFileName, recoveryCard, readCard, cardText } from "./file.js";
export { systemRandom } from "./testing.js";
