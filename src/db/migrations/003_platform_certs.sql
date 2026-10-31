-- The platform's own certificates (turn.ROOT_DOMAIN for coturn), issued by the worker.
CREATE TABLE platform_certs (
    name        TEXT        PRIMARY KEY,           -- the label, e.g. 'turn'
    key_enc     TEXT        NOT NULL,              -- AES-256-GCM, key from SESSION_SECRET
    cert_pem    TEXT,                              -- full chain
    expires_at  TIMESTAMPTZ,
    error       TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
