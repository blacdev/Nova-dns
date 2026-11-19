-- When an admin added the person (they choose their password from an emailed link):
-- until they first sign in, the account shows as invited and the link can be sent again.
ALTER TABLE users ADD COLUMN invited_at TIMESTAMPTZ;
