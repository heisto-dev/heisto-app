import 'dotenv/config';
import { z } from 'zod';

const bool = z.enum(['true', 'false', '1', '0']).optional().transform(v => v === 'true' || v === '1');

const schema = z.object({
  PORT: z.coerce.number().default(8080),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  CLUSTER: z.enum(['mainnet-beta', 'devnet', 'localnet']).default('devnet'),
  SOLANA_RPC_URL: z.string().url(),
  PROGRAM_ID: z.string().min(32),
  JUDGE_SECRET_KEY: z.string().min(40, 'JUDGE_SECRET_KEY (base58, 64 bytes) is required'),
  RELAYER_SECRET_KEY: z.string().min(40, 'RELAYER_SECRET_KEY (base58, 64 bytes) is required'),
  ENCRYPTION_KEY: z.string().regex(/^[0-9a-f]{64}$/i, 'ENCRYPTION_KEY must be 32 bytes hex'),
  PRIORITY_FEE_MICROLAMPORTS: z.coerce.number().default(20000),

  ANTHROPIC_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
  ANTHROPIC_SENTINEL_MODEL: z.string().default('claude-sonnet-5-5'),
  ANTHROPIC_JUDGE_MODEL: z.string().default('claude-opus-5-5'),
  ANTHROPIC_JUDGE_MODEL_2: z.string().default('claude-haiku-5-5'),
  OPENAI_SENTINEL_MODEL: z.string().default('gpt-5'),
  OPENAI_JUDGE_MODEL: z.string().default('gpt-5'),
  PRACTICE_DAILY_LIMIT: z.coerce.number().int().min(1).max(1000).default(5),
  PRACTICE_WALLET_DAILY_LIMIT: z.coerce.number().int().min(1).max(100).default(3),
  JUDGE_MOCK: bool,

  CORS_ORIGIN: z.string().default('https://heisto.xyz'),
  TOKEN_MINT: z.string().optional(),
  X_URL: z.string().url().optional(),
  GITHUB_URL: z.string().url().optional(),
  ADMIN_TOKEN: z.string().min(24).optional(),
  WEB_DIR: z.string().default('../web'),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const msg = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${msg}`);
  }
  const c = parsed.data;
  if (c.JUDGE_MOCK && c.CLUSTER === 'mainnet-beta') {
    throw new Error('JUDGE_MOCK cannot be enabled on mainnet-beta: a mock jury could release real funds.');
  }
  if (!c.JUDGE_MOCK && !c.ANTHROPIC_API_KEY && !c.OPENAI_API_KEY) {
    throw new Error('Set ANTHROPIC_API_KEY and/or OPENAI_API_KEY, or JUDGE_MOCK=true on devnet/localnet.');
  }
  return c;
}
