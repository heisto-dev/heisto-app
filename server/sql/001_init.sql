-- Heisto schema v1
CREATE TABLE IF NOT EXISTS sentinels (
  id              TEXT PRIMARY KEY,            -- u64 id used in the PDA seed
  pda             TEXT UNIQUE NOT NULL,
  owner           TEXT NOT NULL,
  name            TEXT NOT NULL,
  persona         TEXT NOT NULL,               -- public instructions
  private_enc     TEXT NOT NULL,               -- AES-GCM encrypted private instructions
  goal            TEXT NOT NULL,
  jury            TEXT NOT NULL,
  canary_enc      TEXT,                        -- optional exact secret, encrypted
  model           TEXT NOT NULL,               -- claude | gpt | custom
  custom_base_url TEXT,
  custom_key_enc  TEXT,
  custom_model    TEXT,
  difficulty      TEXT NOT NULL DEFAULT 'Medium',
  icon            TEXT NOT NULL DEFAULT 'shield_person',
  instructions_hash TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'draft', -- draft | live | breached | deactivated
  base_fee        BIGINT NOT NULL,
  pool            BIGINT NOT NULL DEFAULT 0,
  fees            BIGINT NOT NULL DEFAULT 0,
  attack_count    BIGINT NOT NULL DEFAULT 0,
  lock_until      BIGINT NOT NULL DEFAULT 0,
  winner          TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sentinels_owner_idx ON sentinels(owner);
CREATE INDEX IF NOT EXISTS sentinels_status_idx ON sentinels(status);

CREATE TABLE IF NOT EXISTS attacks (
  pda          TEXT PRIMARY KEY,
  sentinel_id  TEXT NOT NULL REFERENCES sentinels(id),
  attacker     TEXT NOT NULL,
  seq          BIGINT NOT NULL,
  fee          BIGINT NOT NULL DEFAULT 0,
  prompt       TEXT NOT NULL,
  response     TEXT,
  judges       JSONB,
  success      BOOLEAN,
  score        INTEGER,
  technique    TEXT,
  owasp        TEXT,
  payout       BIGINT NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'pending', -- pending | judging | judged | settled | refunded | failed
  error        TEXT,
  request_sig  TEXT,
  settle_sig   TEXT,
  attempts     INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  settled_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS attacks_sentinel_idx ON attacks(sentinel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS attacks_attacker_idx ON attacks(attacker);
CREATE INDEX IF NOT EXISTS attacks_status_idx ON attacks(status);

CREATE TABLE IF NOT EXISTS guard_keys (
  id         SERIAL PRIMARY KEY,
  key_hash   TEXT UNIQUE NOT NULL,
  key_hint   TEXT NOT NULL,
  owner      TEXT NOT NULL,
  quota      INTEGER NOT NULL DEFAULT 10000,
  used       INTEGER NOT NULL DEFAULT 0,
  period     TEXT NOT NULL DEFAULT to_char(now(), 'YYYY-MM'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS guard_logs (
  id         SERIAL PRIMARY KEY,
  key_id     INTEGER REFERENCES guard_keys(id),
  score      REAL NOT NULL,
  action     TEXT NOT NULL,
  categories JSONB,
  latency_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE guard_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- No prompts, replies, wallet signatures, or raw wallet addresses are retained.
CREATE TABLE IF NOT EXISTS practice_usage (
  day DATE PRIMARY KEY,
  used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
  wallets JSONB NOT NULL DEFAULT '{}'::jsonb
);
