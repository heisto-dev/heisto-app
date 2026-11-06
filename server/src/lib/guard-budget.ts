import type { Db } from '../db.js';

export const GUARD_MONTHLY_QUOTA = 10_000;
export const GUARD_MONTHLY_KEYS = 5;
const month = () => new Date().toISOString().slice(0, 7);

// Each write uses one atomic statement. ON CONFLICT locks the owner/month row,
// so separate processes and rotating/revoking keys cannot create fresh quota.
// Existing legacy usage is included on the first write after schema upgrade.
const LEGACY = `
  SELECT
    count(*) FILTER (WHERE to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM')=$2)::int AS keys_created,
    coalesce(sum(CASE WHEN period=$2 THEN used ELSE 0 END),0)::int AS used
  FROM guard_keys WHERE owner=$1
`;

export async function issueGuardKey(db: Db, wallet: string, hash: string, hint: string) {
  const period = month();
  const { rows } = await db.query(`
    WITH legacy AS (${LEGACY}),
    budget AS (
      INSERT INTO guard_wallet_usage(owner,period,keys_created,used)
      SELECT $1,$2,keys_created+1,used FROM legacy WHERE keys_created < $5
      ON CONFLICT(owner,period) DO UPDATE SET keys_created=guard_wallet_usage.keys_created+1
        WHERE guard_wallet_usage.keys_created < $5
      RETURNING owner
    )
    INSERT INTO guard_keys(key_hash,key_hint,owner,period)
      SELECT $3,$4,owner,$2 FROM budget RETURNING id,quota
  `, [wallet, period, hash, hint, GUARD_MONTHLY_KEYS]);
  return rows[0] ?? null;
}

export async function reserveGuardRequest(db: Db, key: { id: number; owner: string }) {
  const period = month();
  const { rows } = await db.query(`
    WITH legacy AS (${LEGACY}),
    eligible AS (
      SELECT id FROM guard_keys WHERE id=$3 AND owner=$1 AND revoked_at IS NULL
        AND (period<>$2 OR used<quota)
    ),
    budget AS (
      INSERT INTO guard_wallet_usage(owner,period,keys_created,used)
      SELECT $1,$2,legacy.keys_created,legacy.used+1 FROM legacy
        WHERE legacy.used < $4 AND EXISTS(SELECT 1 FROM eligible)
      ON CONFLICT(owner,period) DO UPDATE SET used=guard_wallet_usage.used+1
        WHERE guard_wallet_usage.used < $4
      RETURNING owner
    )
    UPDATE guard_keys SET used=CASE WHEN period=$2 THEN used+1 ELSE 1 END,period=$2
      WHERE id=$3 AND revoked_at IS NULL AND (period<>$2 OR used<quota)
        AND EXISTS(SELECT 1 FROM budget)
      RETURNING id
  `, [key.owner, period, key.id, GUARD_MONTHLY_QUOTA]);
  // Reservations are deliberately conservative on a concurrent revocation or
  // processing failure: never refund a shared slot and risk quota overspending.
  return rows.length > 0;
}

export async function guardWalletUsage(db: Db, wallet: string) {
  const period = month();
  const { rows } = await db.query(`
    WITH legacy AS (${LEGACY})
    SELECT coalesce(b.used,l.used)::int AS used,
      coalesce(b.keys_created,l.keys_created)::int AS keys_created
    FROM legacy l LEFT JOIN guard_wallet_usage b ON b.owner=$1 AND b.period=$2
  `, [wallet, period]);
  return {
    period, used: rows[0].used, quota: GUARD_MONTHLY_QUOTA,
    keysCreated: rows[0].keys_created, keyLimit: GUARD_MONTHLY_KEYS,
  };
}
