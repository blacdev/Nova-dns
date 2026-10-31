-- Nova platform: station subdomains, studios, certificates, TURN usage (spec Part 2, section 7).
-- Additive migrations only: later changes go in new files.

CREATE TABLE users (
    id                BIGSERIAL PRIMARY KEY,
    email             TEXT        NOT NULL,
    password_hash     TEXT        NOT NULL,                       -- Argon2id
    role              TEXT        NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status            TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    email_verified_at TIMESTAMPTZ,
    totp_secret_enc   TEXT,                                       -- AES-256-GCM, key from SESSION_SECRET
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email ON users (lower(email));

-- Dashboard sign-ins. Only the token's SHA-256 is kept.
CREATE TABLE sessions (
    token_hash   TEXT        PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf         TEXT        NOT NULL,
    -- Password accepted, second factor still to come.
    needs_totp   BOOLEAN     NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    ip           TEXT
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Email verification and password reset links. Only the token's SHA-256 is kept.
CREATE TABLE email_tokens (
    token_hash  TEXT        PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL CHECK (kind IN ('verify', 'reset')),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);

CREATE TABLE subdomains (
    id          BIGSERIAL PRIMARY KEY,
    label       TEXT        NOT NULL,
    user_id     BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The race between two people claiming one name is settled here, not in code.
CREATE UNIQUE INDEX subdomains_label ON subdomains (label);
CREATE INDEX subdomains_user ON subdomains (user_id);

CREATE TABLE studios (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subdomain_id      BIGINT      NOT NULL UNIQUE REFERENCES subdomains (id) ON DELETE CASCADE,
    access_code_hash  TEXT        NOT NULL,                       -- Argon2id
    install_id        TEXT,
    last_ip           TEXT,
    last_port         INTEGER,
    last_seen_at      TIMESTAMPTZ,
    app_version       TEXT,
    online            BOOLEAN     NOT NULL DEFAULT false,
    last_probe_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE studio_tokens (
    id          BIGSERIAL PRIMARY KEY,
    studio_id   UUID        NOT NULL REFERENCES studios (id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX studio_tokens_studio ON studio_tokens (studio_id);

-- What the DNS provider holds for each station name, so it is called only on a change.
CREATE TABLE dns_records (
    name         TEXT        NOT NULL,                          -- fully qualified
    type         TEXT        NOT NULL CHECK (type IN ('A', 'AAAA', 'TXT')),
    value        TEXT        NOT NULL,
    provider_id  TEXT,
    status       TEXT        NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'pending')),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (name, type, value)
);

CREATE TABLE certificates (
    id                 BIGSERIAL PRIMARY KEY,
    subdomain_id       BIGINT      NOT NULL REFERENCES subdomains (id) ON DELETE CASCADE,
    fqdn               TEXT        NOT NULL,
    status             TEXT        NOT NULL CHECK (status IN ('pending', 'issued', 'failed', 'superseded', 'revoked')),
    csr_pem            TEXT        NOT NULL,
    serial             TEXT,
    issued_at          TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ,
    cert_pem           TEXT,
    chain_pem          TEXT,
    error              TEXT,
    ari_renewal_after  TIMESTAMPTZ,
    -- New orders wait here when the weekly limit is near (queued, not failed).
    next_attempt_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts           INTEGER     NOT NULL DEFAULT 0,
    -- A renewal of an earlier certificate (exempt from limits when ARI says so).
    renews_id          BIGINT REFERENCES certificates (id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX certificates_subdomain ON certificates (subdomain_id, created_at DESC);
CREATE INDEX certificates_queue ON certificates (status, next_attempt_at);

CREATE TABLE name_cooldowns (
    label            TEXT        PRIMARY KEY,
    available_after  TIMESTAMPTZ NOT NULL
);

-- Reserved names (the platform's own) and blocked names (admin, profanity).
CREATE TABLE reserved_names (
    label       TEXT        PRIMARY KEY,
    kind        TEXT        NOT NULL DEFAULT 'reserved' CHECK (kind IN ('reserved', 'blocked')),
    reason      TEXT,
    created_by  BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO reserved_names (label, reason) VALUES
    ('www', 'platform'), ('api', 'platform'), ('app', 'platform'), ('admin', 'platform'),
    ('mail', 'platform'), ('smtp', 'platform'), ('ftp', 'platform'), ('turn', 'platform'),
    ('stun', 'platform'), ('ns1', 'platform'), ('ns2', 'platform'), ('status', 'platform'),
    ('support', 'platform'), ('help', 'platform'), ('billing', 'platform'), ('root', 'platform'),
    ('dashboard', 'platform'), ('cdn', 'platform'), ('static', 'platform'), ('assets', 'platform');

CREATE TABLE turn_usage (
    studio_id      UUID   NOT NULL,
    day            DATE   NOT NULL,
    bytes_relayed  BIGINT NOT NULL DEFAULT 0,
    sessions       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (studio_id, day)
);

CREATE TABLE audit_log (
    id             BIGSERIAL PRIMARY KEY,
    actor_user_id  BIGINT REFERENCES users (id) ON DELETE SET NULL,
    action         TEXT        NOT NULL,
    target         TEXT,
    ip             TEXT,
    metadata       JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_created ON audit_log (created_at DESC);

-- Fixed-window counters for every rate limit (shared by all API instances).
CREATE TABLE rate_limits (
    key           TEXT        PRIMARY KEY,
    window_start  TIMESTAMPTZ NOT NULL,
    count         INTEGER     NOT NULL
);

-- DNS and ACME problems, for the admin dashboard and the daily alert.
CREATE TABLE ops_events (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT        NOT NULL CHECK (kind IN ('dns', 'acme', 'probe', 'mail', 'job')),
    level       TEXT        NOT NULL DEFAULT 'error' CHECK (level IN ('info', 'error')),
    target      TEXT,
    message     TEXT        NOT NULL,
    alerted_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ops_events_created ON ops_events (created_at DESC);

-- Certificates to revoke with the CA (a deleted station's), done by the worker.
CREATE TABLE revoke_queue (
    id          BIGSERIAL PRIMARY KEY,
    fqdn        TEXT        NOT NULL,
    cert_pem    TEXT        NOT NULL,
    done_at     TIMESTAMPTZ,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The platform's one ACME account (its key encrypted with SESSION_SECRET's key).
CREATE TABLE acme_account (
    directory_url  TEXT        PRIMARY KEY,
    key_enc        TEXT        NOT NULL,
    account_url    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
