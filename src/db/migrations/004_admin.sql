-- Admin control: named plans with a per-person override, a super admin who sets every
-- other admin's permissions, and platform settings (credentials) kept in the database.

-- ------------------------------------------------------------------ plans

CREATE TABLE plans (
    id             BIGSERIAL   PRIMARY KEY,
    name           TEXT        NOT NULL,
    station_limit  INTEGER     NOT NULL CHECK (station_limit >= 0),
    is_default     BOOLEAN     NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX plans_name ON plans (lower(name));
-- At most one default plan (the one people without a plan are on).
CREATE UNIQUE INDEX plans_one_default ON plans (is_default) WHERE is_default;

-- No plan: the default plan. An override, when set, wins over any plan.
ALTER TABLE users ADD COLUMN plan_id BIGINT REFERENCES plans (id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN station_limit_override INTEGER CHECK (station_limit_override >= 0);

-- ------------------------------------------------------------------ roles and permissions

ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'superadmin'));
-- What an admin may do (see src/lib/rbac.ts). The super admin may do everything.
ALTER TABLE users ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{}';
-- Exactly one super admin, at most.
CREATE UNIQUE INDEX users_one_superadmin ON users ((true)) WHERE role = 'superadmin';

-- Admins that exist already keep doing what they did.
UPDATE users SET permissions = ARRAY['users.view', 'users.manage', 'stations.view', 'stations.manage', 'names.manage', 'plans.manage', 'settings.manage', 'logs.view']
 WHERE role = 'admin';
-- The super admin of a platform already running: its first admin, or else its first account.
UPDATE users SET role = 'superadmin', permissions = '{}'
 WHERE id = (SELECT id FROM users ORDER BY (role = 'admin') DESC, id LIMIT 1);

-- ------------------------------------------------------------------ settings

-- Values set in Admin > Settings. They win over .env; without one, .env's value is used.
-- Secret values are AES-256-GCM encrypted (key from SESSION_SECRET) and never shown again.
CREATE TABLE settings (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    secret      BOOLEAN     NOT NULL DEFAULT false,
    updated_by  BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
