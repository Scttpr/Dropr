-- Dropr schema v2: passkey ceremonies and files. See docs/ARCHITECTURE.md §4.

-- Stable random WebAuthn user handle (user.id). It is also the HKDF salt of
-- the client-side KEK, so it is created once and never changes, not even on
-- `dropr user reset-keys`.
ALTER TABLE users ADD COLUMN webauthn_handle BLOB
    CHECK (webauthn_handle IS NULL OR length(webauthn_handle) = 32);
CREATE UNIQUE INDEX users_webauthn_handle ON users (webauthn_handle) WHERE webauthn_handle IS NOT NULL;

-- One pending WebAuthn ceremony per session. Bound to the session row: it
-- disappears with the session, including when the session ID rotates.
CREATE TABLE webauthn_ceremonies (
    session_hash BLOB    NOT NULL PRIMARY KEY REFERENCES sessions (id_hash) ON DELETE CASCADE,
    kind         TEXT    NOT NULL CHECK (kind IN ('register', 'unlock')),
    data         BLOB    NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX webauthn_ceremonies_expires_at ON webauthn_ceremonies (expires_at);

-- Owner-only label (HPKE-sealed, set after creation) and the time a
-- single-use request link closed (first finalized file).
ALTER TABLE requests ADD COLUMN label_meta BLOB
    CHECK (label_meta IS NULL OR length(label_meta) BETWEEN 49 AND 512);
ALTER TABLE requests ADD COLUMN closed_at INTEGER;

-- Download tokens slide (1 h after last use) within a 24 h absolute
-- lifetime measured from created_at.
ALTER TABLE dl_tokens ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
