CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, auth_hash TEXT NOT NULL, version INTEGER NOT NULL, blob TEXT NOT NULL);
-- Failed-auth backoff. Workers have no shared memory between requests, so it lives here.
CREATE TABLE IF NOT EXISTS throttle (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL);
