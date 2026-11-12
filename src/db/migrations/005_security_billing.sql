-- Security: sessions a person can see and end, "sudo mode" (identity confirmed again for
-- a few minutes before sensitive changes), last sign-in. Billing: plan prices, the payment
-- switch and provider, encrypted provider keys, payments and webhook deduplication.

-- ------------------------------------------------------------------ sessions

ALTER TABLE sessions ADD COLUMN id BIGSERIAL;
CREATE UNIQUE INDEX sessions_id ON sessions (id);
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
-- Until when this session may make sensitive changes without confirming again.
ALTER TABLE sessions ADD COLUMN elevated_until TIMESTAMPTZ;

ALTER TABLE users ADD COLUMN last_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN last_login_ip TEXT;

-- Admins who could change settings may also manage billing.
UPDATE users SET permissions = array_append(permissions, 'billing.manage')
 WHERE role = 'admin' AND 'settings.manage' = ANY (permissions) AND NOT 'billing.manage' = ANY (permissions);

-- ------------------------------------------------------------------ plans for sale

-- NULL: not sold (an admin assigns it). In the currency's smallest unit (cents, kobo).
ALTER TABLE plans ADD COLUMN price_minor BIGINT CHECK (price_minor > 0);
ALTER TABLE plans ADD COLUMN currency TEXT CHECK (currency ~ '^[A-Z]{3}$');
ALTER TABLE plans ADD COLUMN period TEXT NOT NULL DEFAULT 'month' CHECK (period IN ('month', 'year'));
ALTER TABLE plans ADD COLUMN description TEXT;
ALTER TABLE plans ADD CONSTRAINT plans_priced CHECK ((price_minor IS NULL) = (currency IS NULL));

-- A paid plan lasts until then; NULL: no end (an admin set it).
ALTER TABLE users ADD COLUMN plan_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN plan_reminded_at TIMESTAMPTZ;

-- ------------------------------------------------------------------ billing

-- One row: payments on or off, and which provider takes them.
CREATE TABLE billing (
    one         BOOLEAN     PRIMARY KEY DEFAULT true CHECK (one),
    enabled     BOOLEAN     NOT NULL DEFAULT false,
    provider    TEXT        CHECK (provider IN ('stripe', 'paystack', 'flutterwave')),
    updated_by  BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO billing DEFAULT VALUES;

-- Each provider's keys, kept when another provider is chosen. AES-256-GCM (SESSION_SECRET's key).
CREATE TABLE payment_providers (
    provider            TEXT        PRIMARY KEY CHECK (provider IN ('stripe', 'paystack', 'flutterwave')),
    secret_key_enc      TEXT,
    webhook_secret_enc  TEXT,
    updated_by          BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payments (
    id            BIGSERIAL   PRIMARY KEY,
    reference     TEXT        NOT NULL UNIQUE,
    user_id       BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    email         TEXT        NOT NULL,
    plan_id       BIGINT      REFERENCES plans (id) ON DELETE SET NULL,
    plan_name     TEXT        NOT NULL,
    period        TEXT        NOT NULL CHECK (period IN ('month', 'year')),
    provider      TEXT        NOT NULL,
    live          BOOLEAN     NOT NULL,
    amount_minor  BIGINT      NOT NULL,
    currency      TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'failed', 'abandoned')),
    provider_ref  TEXT,
    error         TEXT,
    paid_at       TIMESTAMPTZ,
    period_end    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX payments_user ON payments (user_id, created_at DESC);
CREATE INDEX payments_pending ON payments (created_at) WHERE status = 'pending';

-- A provider may send an event more than once: each is handled once.
CREATE TABLE webhook_events (
    provider     TEXT        NOT NULL,
    event_id     TEXT        NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, event_id)
);
