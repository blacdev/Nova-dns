-- The admin lists page through and filter these: newest first, by area or person.
CREATE INDEX users_created ON users (created_at DESC);
CREATE INDEX payments_created ON payments (created_at DESC);
CREATE INDEX audit_log_actor ON audit_log (actor_user_id, created_at DESC);
CREATE INDEX audit_log_area ON audit_log (split_part(action, '.', 1), created_at DESC);
CREATE INDEX ops_events_kind ON ops_events (kind, created_at DESC);
