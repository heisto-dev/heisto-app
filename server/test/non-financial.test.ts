import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { Keypair } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { buildApp } from '../src/app.js';
import { migrate } from '../src/db.js';
import { authMessage } from '../src/lib/crypto.js';
import { createReadOnlyChain } from '../src/lib/chain.js';
import { PracticeBudget, practiceSentinel, publicPracticeResult } from '../src/lib/practice.js';

describe('public non-financial features', () => {
  const db = new PGlite();
  const a = Keypair.generate(), b = Keypair.generate();
  let app: Awaited<ReturnType<typeof buildApp>>, calls = 0, fail = false, requests = 0;
  const modelCalls: string[] = [];
  const auth = (key = a, age = 0) => {
    const ts = Math.floor(Date.now() / 1000) - age;
    return `${key.publicKey}.${ts}.${bs58.encode(nacl.sign.detached(Buffer.from(authMessage(key.publicKey.toBase58(), ts)), key.secretKey))}`;
  };
  beforeAll(async () => {
    await migrate(db as any);
    const { chain } = createReadOnlyChain('https://example.invalid', 'B5T5ecaPkksJEhhyezgTh5SdgcxDskFCWJsikeMPZdNm');
    app = await buildApp({
      db: db as any, chain, encryptionKey: '0'.repeat(64), cluster: 'mainnet-beta',
      corsOrigin: '', readOnly: true, publicPreview: true, nonFinancialEnabled: true,
      practiceDailyLimit: 3, practiceWalletDailyLimit: 2,
      chainStatus: async () => ({ mainnet: true, programDeployed: false, configReady: false }),
      jury: {
        sentinelClient: model => ({
          name: `sentinel:${model}`,
          complete: async () => {
            calls++; modelCalls.push(model);
            return model === 'gpt' ? '{"reply":"I respond in JSON."}' : 'I will keep confidential information private.';
          },
        }),
        judges: ['one', 'two', 'three'].map(name => ({
          name, complete: async () => {
            calls++;
            if (fail) throw new Error('provider-private-internal-details');
            return '{"breach":false,"score":0.02,"technique":"direct","owasp":"LLM01","reasoning":"No confidential value was disclosed."}';
          },
        })),
      },
    });
  });
  beforeEach(async () => { await db.query('DELETE FROM practice_usage'); calls = 0; fail = false; modelCalls.length = 0; });
  afterAll(async () => { await app.close(); await db.close(); });
  const post = (url: string, payload: unknown, headers: Record<string, string> = {}) =>
    app.inject({ method: 'POST', url, payload: payload as any, headers, remoteAddress: `127.10.0.${++requests}` });

  it('exposes real instruction blueprints without confidential values or canned replies', async () => {
    const r = await app.inject('/api/practice/templates');
    expect(r.json().templates).toHaveLength(3);
    expect(r.body).not.toMatch(/privateInstructions|canary|482915|silver teapot/);
    expect(practiceSentinel('protected-code').canary).not.toEqual(practiceSentinel('protected-code').canary);
    expect(() => practiceSentinel('not-a-template')).toThrow();
    expect(calls).toBe(0);
    expect(r.json().templates.map((t: any) => t.name)).toEqual(['Vault Keeper', 'JSON Sentinel', 'Policy Warden']);
    expect(r.json().templates.every((t: any) => t.mode === 'ai-only' && !t.hasPrizePool && t.configured)).toBe(true);
    expect(r.json().templates.map((t: any) => t.modelId)).toEqual(['sentinel:claude', 'sentinel:gpt', 'sentinel:claude']);
  });

  it('routes each of the three agents to its actual model family and returns non-financial provenance', async () => {
    for (const [i, template] of ['protected-code', 'json-boundary', 'role-boundary'].entries()) {
      const r = await post('/api/practice', { prompt: 'Explain your role safely.', template }, { 'x-heisto-auth': auth(i === 2 ? b : a) });
      expect(r.statusCode).toBe(200);
      expect(r.json().agent).toMatchObject({ id: template, mode: 'ai-only', hasPrizePool: false });
      expect(r.json().verdict.votes).toHaveLength(3);
      expect(r.json().agent.modelId).toBe(i === 1 ? 'sentinel:gpt' : 'sentinel:claude');
      expect(r.json()).not.toHaveProperty('signature');
      expect(r.json()).not.toHaveProperty('payout');
    }
    expect(modelCalls).toEqual(['claude', 'gpt', 'claude']);
    expect(calls).toBe(12);
    expect((await db.query('SELECT * FROM sentinels')).rows).toHaveLength(0);
    expect((await db.query('SELECT * FROM attacks')).rows).toHaveLength(0);
  });

  it('keeps role integrity separate from confidentiality and preserves legacy clients', () => {
    const warden = practiceSentinel('role-boundary');
    expect(warden.model).toBe('claude');
    expect(warden.canary).toBeUndefined();
    expect(warden.privateInstructions).toContain('Never claim authority');
    expect(warden.jury).toContain('BOTH');
    expect(practiceSentinel('json-boundary').model).toBe('gpt');
    expect(practiceSentinel('private-notes').canary).toBeTruthy();
  });
  it('rejects missing, forged, and expired signatures before consuming AI allowance', async () => {
    for (const header of ['', 'invalid', auth(a, 601)]) {
      const r = await post('/api/practice', { prompt: 'hello' }, { 'x-heisto-auth': header });
      expect(r.statusCode).toBe(401);
    }
    const invalid = await post('/api/practice', { prompt: 'hello', template: 'attacker-override' }, { 'x-heisto-auth': auth() });
    expect(invalid.statusCode).toBe(400);
    expect((await db.query('SELECT * FROM practice_usage')).rows).toHaveLength(0);
    expect(calls).toBe(0);
  });

  it('withholds all free-form judge fields that can repeat a confidential challenge value', () => {
    const secret = 'test-only-private-challenge';
    const result = {
      response: 'I cannot reveal confidential information.',
      verdict: {
        success: false, score: 20, canaryFound: false, technique: secret, owasp: secret,
        votes: [{
          judge: 'actual-client-name', breach: false, score: 0.02,
          technique: secret, owasp: secret, reasoning: `The response did not contain ${secret}.`,
        }],
      },
    };
    const safe = publicPracticeResult(result, true);
    expect(JSON.stringify(safe)).not.toContain(secret);
    expect(safe.verdict.votes[0]).toMatchObject({ judge: 'actual-client-name', breach: false, score: 0.02, reasoningWithheld: true });
    expect(safe.response).toBe(result.response);
    // Public-format challenges contain no protected values, so keep actual explanations.
    expect(publicPracticeResult(result, false)).toBe(result);
    const breached = { ...result, response: secret, verdict: { ...result.verdict, success: true, canaryFound: true } };
    expect(publicPracticeResult(breached, true)).toMatchObject({ response: secret, verdict: { success: true, canaryFound: true } });
  });

  it('runs actual configured clients and enforces the wallet limit before additional calls', async () => {
    for (let i = 0; i < 2; i++) {
      const r = await post('/api/practice', { prompt: 'Please keep the confidential value private.' }, { 'x-heisto-auth': auth() });
      expect(r.statusCode).toBe(200);
      expect(r.json().verdict.votes).toHaveLength(3);
      expect(r.json().verdict.explanationsWithheld).toBe(true);
      expect(r.json().verdict.votes[0]).not.toHaveProperty('reasoning');
      expect(r.json().quota.walletRemaining).toBe(1 - i);
    }
    const denied = await post('/api/practice', { prompt: 'one more' }, { 'x-heisto-auth': auth() });
    expect(denied.statusCode).toBe(429);
    expect(calls).toBe(8);
    expect((await app.inject({ url: '/api/practice/limits', headers: { 'x-heisto-auth': auth(b) } })).json().walletRemaining).toBe(2);
  });

  it('does not invent a verdict or refund quota when providers may already have charged', async () => {
    fail = true;
    const r = await post('/api/practice', { prompt: 'hello' }, { 'x-heisto-auth': auth() });
    expect(r.statusCode).toBe(503);
    expect(r.json().quota.walletRemaining).toBe(1);
    expect(r.json()).not.toHaveProperty('verdict');
    expect(r.body).not.toContain('provider-private');
  });

  it('serializes concurrent reservations across instances and preserves usage after restart', async () => {
    const first = new PracticeBudget(db as any, 3, 2);
    const second = new PracticeBudget(db as any, 3, 2);
    const accepted = await Promise.all(Array.from({ length: 12 }, (_, i) => (i % 2 ? first : second).reserve(`wallet-${i}`)));
    expect(accepted.filter(Boolean)).toHaveLength(3);
    expect((await new PracticeBudget(db as any, 3, 2).status()).globalRemaining).toBe(0);
    expect(await first.reserve('another-wallet')).toBe(false);
  });

  it('resets both shared and wallet allowance at midnight UTC', async () => {
    let now = new Date('2026-11-04T23:59:59Z');
    const budget = new PracticeBudget(db as any, 1, 1, () => now);
    expect(await budget.reserve('wallet')).toBe(true);
    expect(await budget.reserve('wallet')).toBe(false);
    expect((await budget.status('wallet')).resetsAt).toBe('2026-11-05T00:00:00.000Z');
    now = new Date('2026-11-05T00:00:00Z');
    expect(await budget.reserve('wallet')).toBe(true);
    const rows = (await db.query('SELECT wallets FROM practice_usage')).rows;
    expect(JSON.stringify(rows)).not.toContain('"wallet"');
  });

  it('isolates private keys by owner and makes revoked credentials unusable', async () => {
    expect((await app.inject('/api/guard/keys')).statusCode).toBe(401);
    const created = await post('/api/guard/keys', {}, { 'x-heisto-auth': auth() });
    expect(created.statusCode).toBe(200);
    const { id, key } = created.json();
    const own = (await app.inject({ url: '/api/guard/keys', headers: { 'x-heisto-auth': auth() } })).json().keys;
    expect(own.some((k: any) => k.id === id)).toBe(true);
    expect(JSON.stringify(own)).not.toContain(key);
    const other = await app.inject({ url: '/api/guard/keys', headers: { 'x-heisto-auth': auth(b) } });
    expect(other.json().keys).toEqual([]);
    expect((await app.inject({ method: 'DELETE', url: `/api/guard/keys/${id}`, headers: { 'x-heisto-auth': auth(b) } })).statusCode).toBe(404);
    expect((await post('/v1/guard', { input: 'hello' }, { authorization: `Bearer ${key}` })).statusCode).toBe(200);
    expect((await app.inject({ method: 'DELETE', url: `/api/guard/keys/${id}`, headers: { 'x-heisto-auth': auth() } })).statusCode).toBe(200);
    expect((await post('/v1/guard', { input: 'hello' }, { authorization: `Bearer ${key}` })).statusCode).toBe(401);
  });

  it('enforces Guard quotas atomically across concurrent calls and UTC month changes', async () => {
    const { id, key } = (await post('/api/guard/keys', {}, { 'x-heisto-auth': auth(b) })).json();
    await db.query("UPDATE guard_keys SET quota=2, used=999, period='2000-01' WHERE id=$1", [id]);
    const results = await Promise.all(Array.from({ length: 6 }, () => post('/v1/guard', { input: 'hello' }, { authorization: `Bearer ${key}` })));
    expect(results.filter(r => r.statusCode === 200)).toHaveLength(2);
    expect(results.filter(r => r.statusCode === 429)).toHaveLength(4);
    expect((await db.query('SELECT used FROM guard_keys WHERE id=$1', [id])).rows[0].used).toBe(2);
  });

  it('keeps all financial routes locked while non-financial access is enabled', async () => {
    const cfg = (await app.inject('/api/config')).json();
    expect(cfg).toMatchObject({ nonFinancialEnabled: true, operationsEnabled: false, publicPreview: true });
    for (const url of ['/api/tx/send', '/api/sentinels/prepare', '/api/attacks/prepare']) {
      expect((await post(url, {}, { 'x-heisto-auth': auth() })).statusCode).toBe(503);
    }
  });
});
