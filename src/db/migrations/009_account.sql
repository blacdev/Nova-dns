-- Two-step recovery codes: single use, only their SHA-256 kept. A new set replaces the old.
CREATE TABLE recovery_codes (
    id         BIGSERIAL   PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

-- A person changing their own email: the link goes to the new address, which is kept here until it is opened.
ALTER TABLE email_tokens DROP CONSTRAINT email_tokens_kind_check;
ALTER TABLE email_tokens ADD CONSTRAINT email_tokens_kind_check CHECK (kind IN ('verify', 'reset', 'email_change'));
ALTER TABLE email_tokens ADD COLUMN new_email TEXT;
