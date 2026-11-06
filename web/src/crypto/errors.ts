/**
 * Error types for the Dropr crypto core.
 *
 * Two classes on purpose:
 *
 * - {@link DecryptionError}: an authenticated decryption (or HPKE open, or key
 *   unwrap) failed. The message is constant and carries no detail (no segment
 *   index, no "tag mismatch" vs "bad length" distinction) so that it cannot be
 *   used as an oracle. Callers should show a generic "the file is damaged or
 *   the link is wrong" message.
 * - {@link FormatError}: a caller-supplied value is malformed *before* any
 *   secret is involved (bad base64url, impossible ciphertext size, wrong key
 *   length, out-of-range index). These describe public facts only.
 *
 * @module
 */

/** Authenticated decryption failed. Deliberately detail-free. */
export class DecryptionError extends Error {
  constructor() {
    super("decryption failed");
    this.name = "DecryptionError";
  }
}

/** A public input does not conform to the Dropr format. */
export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FormatError";
  }
}
