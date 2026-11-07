-- Dropr schema v3: fixes from the 2026-11 security audit. See
-- docs/ARCHITECTURE.md §4.

-- Passkey management grants (audit M-1). A fresh user-verified assertion
-- made for a specific purpose ("add" a passkey, "delete" one given passkey)
-- leaves one single-use grant on the session that made it. It expires 5
-- minutes after the assertion and dies with the session, including when the
-- session ID rotates.
CREATE TABLE passkey_grants (
    session_hash BLOB    NOT NULL PRIMARY KEY REFERENCES sessions (id_hash) ON DELETE CASCADE,
    purpose      TEXT    NOT NULL CHECK (purpose IN ('add', 'delete')),
    target       BLOB    CHECK (target IS NULL OR length(target) BETWEEN 16 AND 1023),
    expires_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX passkey_grants_expires_at ON passkey_grants (expires_at);

-- Set when the account lost access at the identity provider (role or
-- required claim missing at revalidation, or `dropr user revoke`); cleared
-- by the next successful login. Request links of such an account stop
-- accepting uploads (audit I-3).
ALTER TABLE users ADD COLUMN access_lost_at INTEGER;

-- Ciphertext bytes a download token has served (reserved when a response
-- starts, unsent bytes refunded when it ends). Capped at
-- 2 × size + min(size, 1 MiB) (audit L-2).
ALTER TABLE dl_tokens ADD COLUMN served_bytes INTEGER NOT NULL DEFAULT 0 CHECK (served_bytes >= 0);
