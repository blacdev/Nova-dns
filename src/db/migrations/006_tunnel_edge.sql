-- The tunnel's edge (Nova's docs/TUNNEL.md): how each station's name is pointed now, so
-- admins can see which stations come in through the edge.
ALTER TABLE studios ADD COLUMN via TEXT NOT NULL DEFAULT 'direct' CHECK (via IN ('direct', 'tunnel'));
-- edge.ROOT_DOMAIN is the platform's: no station may take it.
INSERT INTO reserved_names (label, reason) VALUES ('edge', 'platform') ON CONFLICT (label) DO NOTHING;
