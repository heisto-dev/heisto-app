import { loadConfig } from './config.js';
import { createPgDb } from './db.js';
import { createSolanaChain } from './lib/chain.js';
import { anthropic, openaiCompatible, type LlmClient } from './lib/llm.js';
import { mockJury, type Jury } from './lib/judge.js';
import { buildApp, createOps } from './app.js';

const cfg = loadConfig();
const db = createPgDb(cfg.DATABASE_URL);
// Apply reviewed database migrations explicitly before starting this service.
// Never run schema DDL on production startup.
await db.query('SELECT 1 FROM sentinels LIMIT 1');
await db.query('SELECT 1 FROM guard_wallet_usage LIMIT 1');

const chain = createSolanaChain({
  rpcUrl: cfg.SOLANA_RPC_URL, programId: cfg.PROGRAM_ID,
  judgeSecret: cfg.JUDGE_SECRET_KEY, relayerSecret: cfg.RELAYER_SECRET_KEY,
  priorityFeeMicroLamports: cfg.PRIORITY_FEE_MICROLAMPORTS,
});

function buildJury(): Jury {
  if (cfg.JUDGE_MOCK) return mockJury();
  const a = cfg.ANTHROPIC_API_KEY, o = cfg.OPENAI_API_KEY;
  // Three judges from the providers you have: Claude (primary), GPT, and a second Claude model.
  const judges: LlmClient[] = [];
  if (a) judges.push(anthropic(a, cfg.ANTHROPIC_JUDGE_MODEL));
  if (o) judges.push(openaiCompatible(o, cfg.OPENAI_JUDGE_MODEL));
  if (a) judges.push(anthropic(a, cfg.ANTHROPIC_JUDGE_MODEL_2));
  while (judges.length < 3) judges.push(a ? anthropic(a, cfg.ANTHROPIC_JUDGE_MODEL) : openaiCompatible(o!, cfg.OPENAI_JUDGE_MODEL));
  return {
    judges,
    sentinelClient(model, custom) {
      if ((model === 'custom' || model === 'llama') && custom) return openaiCompatible(custom.apiKey, custom.model, custom.baseUrl);
      if (model === 'gpt') {
        if (!o) throw new Error('OpenAI provider is unavailable.');
        return openaiCompatible(o, cfg.OPENAI_SENTINEL_MODEL);
      }
      if (!a) throw new Error('Anthropic provider is unavailable.');
      return anthropic(a, cfg.ANTHROPIC_SENTINEL_MODEL);
    },
  };
}

const services = {
  db, chain, jury: buildJury(),
  practiceDailyLimit: cfg.PRACTICE_DAILY_LIMIT,
  practiceWalletDailyLimit: cfg.PRACTICE_WALLET_DAILY_LIMIT,
  advisor: cfg.ANTHROPIC_API_KEY && !cfg.JUDGE_MOCK ? anthropic(cfg.ANTHROPIC_API_KEY, cfg.ANTHROPIC_JUDGE_MODEL) : undefined,
  encryptionKey: cfg.ENCRYPTION_KEY, cluster: cfg.CLUSTER,
  links: { tokenMint: cfg.TOKEN_MINT, x: cfg.X_URL, github: cfg.GITHUB_URL }, corsOrigin: cfg.CORS_ORIGIN, webDir: cfg.WEB_DIR, logger: true,
};
const app = await buildApp(services);
const ops = createOps(services);

let sweeping = false;
setInterval(async () => {
  if (sweeping) return; sweeping = true;
  try { await ops.sweep(); } catch (e) { app.log.error(e, 'sweep failed'); } finally { sweeping = false; }
}, 15_000);

await app.listen({ port: cfg.PORT, host: cfg.HOST });
app.log.info(`Heisto API on ${cfg.CLUSTER} · program ${cfg.PROGRAM_ID} · judge ${chain.judgePublicKey.toBase58()}`);

for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, async () => { await app.close(); await db.end(); process.exit(0); });
