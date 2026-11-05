// A deterministic byte stream for tests and vectors. Never use it for keys or nonces.
// The stream is SHA-256(seed ‖ be32(0)) ‖ SHA-256(seed ‖ be32(1)) ‖ …, consumed byte by byte, the same as the Rust
// crate's `testing::TestRandom`, so both implementations draw identical bytes (SPEC §21).

/**
 * A deterministic `random(n)` function for tests. It is synchronous; it needs `sha256Sync`, a synchronous SHA-256,
 * which the tests take from `node:crypto`.
 * @param {Uint8Array} seed
 * @param {(m: Uint8Array) => Uint8Array} sha256Sync
 */
export function testRandom(seed, sha256Sync) {
  let counter = 0;
  let buf = new Uint8Array(0);
  let pos = 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      if (pos === buf.length) {
        const m = new Uint8Array(seed.length + 4);
        m.set(seed);
        new DataView(m.buffer).setUint32(seed.length, counter++);
        buf = sha256Sync(m);
        pos = 0;
      }
      out[i] = buf[pos++];
    }
    return out;
  };
}

/** Random bytes from the platform's secure generator, for applications ([CRY-1]). Not used by the core itself. */
export function systemRandom(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
