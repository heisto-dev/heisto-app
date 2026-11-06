import { z } from 'zod';
import { buildApp } from './app.js';
import { createPgDb } from './db.js';
import { createReadOnlyChain } from './lib/chain.js';
import { createJury } from './jury.js';

const env = z.object({
  DATABASE_URL: z.string().min(1), SOLANA_RPC_URL: z.string().url(),
  ENCRYPTION_KEY: z.string().regex(/^[0-9a-f]{64}$/i),
  PROGRAM_ID: z.string().default('FxqFvpptTRCeKCxCuxt86AJze6v16Vk9M8UZCQ8tJvbi'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  PRACTICE_DAILY_LIMIT: z.coerce.number().int().min(1).max(1000).default(5),
  PRACTICE_WALLET_DAILY_LIMIT: z.coerce.number().int().min(1).max(100).default(3),
}).parse(process.env);
const db = createPgDb(env.DATABASE_URL);
// Development migrations and Publish own schema changes; no startup DDL.
await db.query('SELECT 1 FROM sentinels LIMIT 1');
await db.query('SELECT 1 FROM guard_wallet_usage LIMIT 1');
const { chain, status } = createReadOnlyChain(env.SOLANA_RPC_URL, env.PROGRAM_ID);
if (!(await status()).mainnet) throw new Error('Solana Mainnet RPC is required.');
const app = await buildApp({
  db, chain, jury: createJury({ ...process.env, JUDGE_MOCK: 'false' }), readOnly: true, publicPreview: true, nonFinancialEnabled: true, chainStatus: status,
  practiceDailyLimit: env.PRACTICE_DAILY_LIMIT, practiceWalletDailyLimit: env.PRACTICE_WALLET_DAILY_LIMIT,
  encryptionKey: env.ENCRYPTION_KEY, cluster: 'mainnet-beta',
  corsOrigin: process.env.CORS_ORIGIN ?? '',
  links: { tokenMint: process.env.TOKEN_MINT, x: process.env.X_URL, github: process.env.GITHUB_URL },
  webDir: process.env.WEB_DIR,
  logger: { level: 'info', redact: ['req.headers.authorization', 'req.headers.x-heisto-auth'], serializers: { req: req => ({ id: req.id, method: req.method }) } },
});
await app.listen({ port: env.PORT, host: '0.0.0.0' });
app.log.info({ event: 'heisto_started', mode: 'read-only', timezone: 'UTC', transactionsEnabled: false });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => {
  await app.close();
  await db.end();
  process.exit(0);
});
