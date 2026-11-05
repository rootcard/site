// rootcard/vault: password locks, Argon2id, vault encryption and the high-level flows that need them.

export {
  checkPassword, deriveLockSecrets, wrapVaultKey, unwrapVaultKey, checkContents, unlockVault, signGrant, sealVault,
  newPasswordLock, instanceVault, carriedLocks, updateContents, changePassword, addSlot, regrant,
} from "./vault.js";
export { register, newInstance, rotateRecovery } from "./account.js";
export { argon2id } from "./argon2.js";
export { x25519, x25519Public } from "./crypto.js";
