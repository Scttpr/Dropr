-- Dropr schema v1. See docs/ARCHITECTURE.md §4.
-- Times are Unix seconds. Secrets are SHA-256 hashes or AES-256-GCM
-- ciphertext; nothing in this database is a usable bearer credential.

CREATE TABLE users (
    id           TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 22),
    issuer       TEXT    NOT NULL CHECK (issuer <> ''),
    subject      TEXT    NOT NULL CHECK (subject <> ''),
    display_name TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    disabled_at  INTEGER,
    quota_bytes  INTEGER CHECK (quota_bytes IS NULL OR quota_bytes >= 0),
    UNIQUE (issuer, subject)
) STRICT;

CREATE TABLE sessions (
    id_hash           BLOB    NOT NULL PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id           TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_token_enc BLOB,
    oidc_sid          TEXT,
    created_at        INTEGER NOT NULL,
    last_seen_at      INTEGER NOT NULL,
    revalidated_at    INTEGER NOT NULL,
    unlocked_at       INTEGER,
    rotated_from      BLOB CHECK (rotated_from IS NULL OR length(rotated_from) = 32)
) STRICT;
CREATE INDEX sessions_user_id      ON sessions (user_id);
CREATE INDEX sessions_oidc_sid     ON sessions (oidc_sid) WHERE oidc_sid IS NOT NULL;
CREATE INDEX sessions_last_seen_at ON sessions (last_seen_at);
CREATE INDEX sessions_created_at   ON sessions (created_at);

CREATE TABLE passkeys (
    id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 16 AND 1023),
    user_id         TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential      BLOB    NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    wrapped_privkey BLOB    NOT NULL,
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
) STRICT;
CREATE INDEX passkeys_user_id ON passkeys (user_id);

CREATE TABLE user_keys (
    user_id TEXT NOT NULL PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    pubkey  BLOB NOT NULL CHECK (length(pubkey) = 32)
) STRICT;

-- Blob files live on disk under data_dir; rows removed by cascade leave
-- orphaned files that `dropr gc` reconciles.
CREATE TABLE blobs (
    id                TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 22),
    owner_id          TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    parts             INTEGER NOT NULL CHECK (parts BETWEEN 1 AND 3200),
    size              INTEGER NOT NULL CHECK (size > 0),
    complete          INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
    upload_token_hash BLOB    CHECK (upload_token_hash IS NULL OR length(upload_token_hash) = 32),
    created_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX blobs_owner_id   ON blobs (owner_id);
CREATE INDEX blobs_incomplete ON blobs (created_at) WHERE complete = 0;

CREATE TABLE shares (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 22),
    owner_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blob_id        TEXT    NOT NULL UNIQUE REFERENCES blobs (id) ON DELETE CASCADE,
    size           INTEGER NOT NULL CHECK (size > 0),
    meta           BLOB    NOT NULL CHECK (length(meta) BETWEEN 1 AND 4096),
    expires_at     INTEGER NOT NULL,
    max_downloads  INTEGER CHECK (max_downloads IS NULL OR max_downloads > 0),
    download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    created_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX shares_owner_id   ON shares (owner_id);
CREATE INDEX shares_expires_at ON shares (expires_at);

CREATE TABLE requests (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 22),
    owner_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at     INTEGER NOT NULL,
    max_files      INTEGER NOT NULL CHECK (max_files > 0),
    max_bytes      INTEGER NOT NULL CHECK (max_bytes > 0),
    single_use     INTEGER NOT NULL DEFAULT 0 CHECK (single_use IN (0, 1)),
    files_received INTEGER NOT NULL DEFAULT 0 CHECK (files_received >= 0),
    bytes_received INTEGER NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
    created_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX requests_owner_id   ON requests (owner_id);
CREATE INDEX requests_expires_at ON requests (expires_at);

CREATE TABLE inbox (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) = 22),
    request_id  TEXT    NOT NULL REFERENCES requests (id) ON DELETE CASCADE,
    owner_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blob_id     TEXT    NOT NULL UNIQUE REFERENCES blobs (id) ON DELETE CASCADE,
    size        INTEGER NOT NULL CHECK (size > 0),
    meta        BLOB    NOT NULL CHECK (length(meta) BETWEEN 1 AND 4096),
    wrapped_key BLOB    NOT NULL CHECK (length(wrapped_key) = 80),
    created_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX inbox_owner_id   ON inbox (owner_id);
CREATE INDEX inbox_request_id ON inbox (request_id);

CREATE TABLE dl_tokens (
    token_hash BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    blob_id    TEXT    NOT NULL REFERENCES blobs (id) ON DELETE CASCADE,
    share_id   TEXT    REFERENCES shares (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    counted    INTEGER NOT NULL DEFAULT 0 CHECK (counted IN (0, 1))
) STRICT;
CREATE INDEX dl_tokens_expires_at ON dl_tokens (expires_at);
CREATE INDEX dl_tokens_blob_id    ON dl_tokens (blob_id);
CREATE INDEX dl_tokens_share_id   ON dl_tokens (share_id) WHERE share_id IS NOT NULL;
