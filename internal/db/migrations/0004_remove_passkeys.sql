-- Dropr schema v4: request links carry their own key pair, kept in the
-- owner's browser; passkeys are gone. See docs/ARCHITECTURE.md §2 and §4.

DROP TABLE passkey_grants;
DROP TABLE webauthn_ceremonies;
DROP TABLE passkeys;
DROP TABLE user_keys;

DROP INDEX users_webauthn_handle;
ALTER TABLE users DROP COLUMN webauthn_handle;
ALTER TABLE sessions DROP COLUMN unlocked_at;
-- Only the passkey unlock rotation wrote it.
ALTER TABLE sessions DROP COLUMN rotated_from;

-- Every request link and received file was sealed to the account key, whose
-- private half was wrapped by the passkeys dropped above: nobody can open
-- them any more. Deleting the blob rows cascades to the inbox and download
-- tokens; the orphan sweep then removes the blob files. Share links are kept.
DELETE FROM blobs WHERE id IN (SELECT blob_id FROM inbox);
DELETE FROM requests;
