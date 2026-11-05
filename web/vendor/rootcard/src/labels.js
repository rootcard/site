// Domain separation labels (SPEC §5).

/** Version of the wire and storage format described by the specification. */
export const FORMAT_VERSION = 1;

/** Prefix of every domain-separation label (`rootcard/<purpose>/v<n>`). */
export const LABEL_PREFIX = "rootcard/";

/**
 * Build a domain-separation label, e.g. `label("id", 1) === "rootcard/id/v1"`.
 * @param {string} purpose
 * @param {number} [version]
 * @returns {string}
 */
export function label(purpose, version = FORMAT_VERSION) {
  return `${LABEL_PREFIX}${purpose}/v${version}`;
}
