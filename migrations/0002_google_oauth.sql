ALTER TABLE users ADD COLUMN google_subject TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS users_google_subject_idx
  ON users(google_subject)
  WHERE google_subject IS NOT NULL;

CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
