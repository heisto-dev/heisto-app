/**
 * Mainnet readiness check. Run before every launch / redeploy:
 *   npm run preflight            (uses .env)
 * Exits non-zero if anything required is missing.
 */
import 'dotenv/config';
import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { loadConfig } from '../src/config.js';
import { keypairFromBase58 } from '../src/lib/chain.js';
import { configPda, decodeConfig, lamportsToSol } from '../src/lib/sdk.js';
import { createPgDb } from '../src/db.js';

const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const results: [string, boolean, string][] = [];
const check = (name: string, ok: boolean, detail = '') => results.push([name, ok, detail]);

let cfg;
try { cfg = loadConfig(); check('Environment variables', true); }
catch (e) { check('Environment variables', false, (e as Error).message); report(); }
const c = cfg!;

const conn = new Connection(c.SOLANA_RPC_URL, 'confirmed');
try {
  const genesis = await conn.getGenesisHash();
  const isMain = genesis === MAINNET_GENESIS;
  check('RPC reachable', true);
  check('Cluster matches CLUSTER', (c.CLUSTER === 'mainnet-beta') === isMain, `CLUSTER=${c.CLUSTER}, RPC genesis ${isMain ? 'mainnet' : 'not mainnet'}`);
} catch { check('RPC reachable', false, 'RPC request failed; verify the secret and network access.'); }

const programId = new PublicKey(c.PROGRAM_ID);
try {
  const info = await conn.getAccountInfo(programId);
  check('Program deployed', !!info?.executable, info ? `owner ${info.owner.toBase58()}` : 'no account at PROGRAM_ID');
} catch { check('Program deployed', false, 'Unable to read the program account.'); }

const judge = keypairFromBase58(c.JUDGE_SECRET_KEY).publicKey;
const relayer = keypairFromBase58(c.RELAYER_SECRET_KEY).publicKey;
try {
  const info = await conn.getAccountInfo(configPda(programId));
  if (!info) check('Config initialised', false, 'run npm run init-config');
  else {
    const cf = decodeConfig(info.data);
    check('Config initialised', true, `admin ${cf.admin.toBase58()}`);
    check('Judge key matches on-chain', cf.judge.equals(judge), `env ${judge.toBase58()} / chain ${cf.judge.toBase58()}`);
    check('Not paused', !cf.paused || process.argv.includes('--allow-paused'), cf.paused ? 'config is paused; activation check only' : '');
    check('Pool cap is conservative (≤ 5 SOL before audit)', cf.maxPoolLamports <= 5n * BigInt(LAMPORTS_PER_SOL), `${lamportsToSol(cf.maxPoolLamports)} SOL`);
    check('Treasury / burn are separate from relayer', !cf.treasury.equals(relayer) && !cf.burnVault.equals(relayer));
  }
} catch { check('Config initialised', false, 'Unable to read the on-chain configuration.'); }

try {
  const bal = await conn.getBalance(relayer);
  check('Relayer operating balance (≥ 0.005 SOL)', bal >= 0.005 * LAMPORTS_PER_SOL, `${relayer.toBase58()} has ${bal / LAMPORTS_PER_SOL} SOL`);
} catch { check('Relayer funded', false, 'Unable to read the relayer balance.'); }

check('AI providers configured', !!(c.ANTHROPIC_API_KEY || c.OPENAI_API_KEY) && !c.JUDGE_MOCK, [c.ANTHROPIC_API_KEY && 'Anthropic', c.OPENAI_API_KEY && 'OpenAI'].filter(Boolean).join(' + '));
const keyChecks: Promise<[string, boolean]>[] = [];
async function modelsAvailable(url: string, headers: Record<string, string>, models: string[]) {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
  if (!response.ok) return false;
  const body = await response.json() as { data?: { id: string }[] };
  return models.every(model => body.data?.some(entry => entry.id === model));
}
if (c.ANTHROPIC_API_KEY) keyChecks.push(modelsAvailable('https://api.anthropic.com/v1/models?limit=1000',
  { 'x-api-key': c.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
  [c.ANTHROPIC_SENTINEL_MODEL, c.ANTHROPIC_JUDGE_MODEL, c.ANTHROPIC_JUDGE_MODEL_2])
  .then(ok => ['Anthropic key and configured models', ok] as [string, boolean])
  .catch(() => ['Anthropic key and configured models', false]));
if (c.OPENAI_API_KEY) keyChecks.push(modelsAvailable('https://api.openai.com/v1/models',
  { authorization: `Bearer ${c.OPENAI_API_KEY}` }, [c.OPENAI_SENTINEL_MODEL, c.OPENAI_JUDGE_MODEL])
  .then(ok => ['OpenAI key and configured models', ok] as [string, boolean])
  .catch(() => ['OpenAI key and configured models', false]));
for (const [name, ok] of await Promise.all(keyChecks)) check(name, ok);

try { const db = createPgDb(c.DATABASE_URL); try { await db.query('SELECT 1 FROM sentinels LIMIT 1'); await db.query('SELECT 1 FROM guard_wallet_usage LIMIT 1'); check('Database reachable + migrated', true); } finally { await db.end(); } }
catch { check('Database reachable + migrated', false, 'Database connection or schema check failed.'); }

check('CORS origin is the production domain', c.CORS_ORIGIN.startsWith('https://'), c.CORS_ORIGIN);
check('Public links set (X, GitHub)', !!(c.X_URL && c.GITHUB_URL), 'optional, shown as "Soon" if empty');
report();

function report(): never {
  let failed = 0;
  for (const [name, ok, detail] of results) {
    const optional = name.startsWith('Public links');
    if (!ok && !optional) failed++;
    console.log(`${ok ? '✔' : optional ? '•' : '✘'} ${name}${detail ? `  — ${detail}` : ''}`);
  }
  console.log(failed ? `\n${failed} check(s) failed. Not ready for mainnet.` : '\nAll required checks passed. Ready for mainnet.');
  process.exit(failed ? 1 : 0);
}
