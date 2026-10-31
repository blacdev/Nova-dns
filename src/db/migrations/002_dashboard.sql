-- A second factor being set up: the secret waits here (encrypted) until a code confirms it.
ALTER TABLE sessions ADD COLUMN pending_totp_enc TEXT;
