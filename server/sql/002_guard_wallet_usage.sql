-- A single persistent counter per owner and UTC month, shared by every key.
-- Initial counters are imported lazily from existing keys (including revoked
-- keys). No data backfill or production startup DDL is needed on Publish.
CREATE TABLE IF NOT EXISTS guard_wallet_usage (
  owner TEXT NOT NULL,
  period TEXT NOT NULL,
  keys_created INTEGER NOT NULL DEFAULT 0 CHECK (keys_created >= 0),
  used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
  PRIMARY KEY (owner, period)
);
CREATE INDEX IF NOT EXISTS guard_keys_owner_idx ON guard_keys(owner);
