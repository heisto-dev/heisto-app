/**
 * In-memory emulator of the Heisto program for API tests. It decodes the real
 * instruction bytes produced by src/lib/sdk.ts and applies the same rules as
 * programs/heisto/src/lib.rs, so a wrong account order or Borsh layout fails here.
 */
import { Keypair, PublicKey, type TransactionInstruction } from '@solana/web3.js';
import nacl from 'tweetnacl';
import {
  STATUS, attackPda, currentFee, ixDisc, mulBps, sentinelPda, verdictMessage,
  type AttackAccount, type ConfigAccount, type SentinelAccount,
} from '../src/lib/sdk.js';
import type { Chain } from '../src/lib/chain.js';

const MIN_POOL = 500_000_000n;
const LOCK = 7n * 24n * 3600n;

export class FakeChain implements Chain {
  programId = new PublicKey('B5T5ecaPkksJEhhyezgTh5SdgcxDskFCWJsikeMPZdNm');
  judge = Keypair.generate();
  judgePublicKey = this.judge.publicKey;
  treasury = Keypair.generate().publicKey;
  burnVault = Keypair.generate().publicKey;
  config: ConfigAccount = { admin: Keypair.generate().publicKey, judge: this.judge.publicKey, treasury: this.treasury, burnVault: this.burnVault, maxPoolLamports: 10n * 10n ** 9n, paused: false, poolBps: 5000, defenderBps: 3500, treasuryBps: 1000, burnBps: 500, bump: 255 };
  sentinels = new Map<string, SentinelAccount>();
  attacks = new Map<string, AttackAccount>();
  balances = new Map<string, bigint>();
  now = 1_800_000_000n;
  private txs = new Map<string, { payer: PublicKey; ixs: TransactionInstruction[] }>();
  private executed = new Set<string>();
  private n = 0;
  settleCalls = 0;

  bal(k: PublicKey | string) { return this.balances.get(k.toString()) ?? 0n; }
  private add(k: PublicKey | string, v: bigint) { this.balances.set(k.toString(), this.bal(k) + v); }

  async getConfig() { return this.config; }
  async getSentinel(pda: PublicKey) { return this.sentinels.get(pda.toBase58()) ?? null; }
  async getAttack(pda: PublicKey) { return this.attacks.get(pda.toBase58()) ?? null; }
  async buildUserTx(payer: PublicKey, ixs: TransactionInstruction[]) {
    const id = `tx${++this.n}`; this.txs.set(id, { payer, ixs }); return Buffer.from(id).toString('base64');
  }
  async sendRaw(): Promise<string> { throw new Error('sendRaw is not supported by the emulator'); }
  async confirm(signature: string) { if (!this.executed.has(signature)) throw new Error('unknown signature'); }

  /** What a wallet does: "sign and send" the tx returned by the API. */
  execute(txBase64: string, signer: PublicKey): string {
    const id = Buffer.from(txBase64, 'base64').toString();
    const tx = this.txs.get(id); if (!tx) throw new Error('unknown tx');
    if (!tx.payer.equals(signer)) throw new Error('wrong signer');
    for (const ix of tx.ixs) this.apply(ix, signer);
    const sig = `sig_${id}_${'x'.repeat(48)}`; this.executed.add(sig); return sig;
  }

  private apply(ix: TransactionInstruction, signer: PublicKey) {
    if (!ix.programId.equals(this.programId)) throw new Error('wrong program');
    const d = Buffer.from(ix.data), disc = d.subarray(0, 8), k = ix.keys.map(x => x.pubkey);
    const is = (n: string) => disc.equals(ixDisc(n));
    const signed = (i: number) => { if (!ix.keys[i].isSigner || !k[i].equals(signer)) throw new Error(`account ${i} must sign`); };
    if (is('create_sentinel')) {
      signed(2);
      const id = d.readBigUInt64LE(8), base = d.readBigUInt64LE(16), pool = d.readBigUInt64LE(24), hash = Buffer.from(d.subarray(32, 64));
      if (!k[1].equals(sentinelPda(this.programId, k[2], id))) throw new Error('bad sentinel pda');
      if (this.config.paused || pool < MIN_POOL || pool > this.config.maxPoolLamports || base <= 0n || base * 100n > pool) throw new Error('create_sentinel rejected');
      if (this.sentinels.has(k[1].toBase58())) throw new Error('already exists');
      this.add(k[2], -pool);
      this.sentinels.set(k[1].toBase58(), { owner: k[2], id, baseFee: base, attackCount: 0n, poolLamports: pool, feesLamports: 0n, status: STATUS.ACTIVE, lockUntil: this.now + LOCK, deactivatedAt: 0n, createdAt: this.now, instructionsHash: hash, winner: PublicKey.default, bump: 255 });
    } else if (is('request_attack')) {
      signed(3);
      const s = this.sentinels.get(k[1].toBase58()); if (!s || s.status !== STATUS.ACTIVE) throw new Error('not active');
      if (!k[2].equals(attackPda(this.programId, k[1], s.attackCount))) throw new Error('bad attack pda (seq moved)');
      const hash = Buffer.from(d.subarray(8, 40)), maxFee = d.readBigUInt64LE(40);
      const fee = currentFee(s.baseFee, s.attackCount); if (fee > maxFee) throw new Error('fee above max');
      this.add(k[3], -fee);
      this.attacks.set(k[2].toBase58(), { sentinel: k[1], attacker: k[3], seq: s.attackCount, fee, promptHash: hash, createdAt: this.now, bump: 255 });
      s.attackCount += 1n;
    } else if (is('fund_sentinel')) {
      signed(2);
      const s = this.sentinels.get(k[1].toBase58())!; const amt = d.readBigUInt64LE(8);
      if (s.status !== STATUS.ACTIVE || s.poolLamports + amt > this.config.maxPoolLamports) throw new Error('fund rejected');
      this.add(k[2], -amt); s.poolLamports += amt; s.lockUntil = this.now + LOCK;
    } else if (is('claim_fees') || is('deactivate_sentinel') || is('withdraw')) {
      signed(1);
      const s = this.sentinels.get(k[0].toBase58())!; if (!s.owner.equals(k[1])) throw new Error('not owner');
      if (is('claim_fees')) { if (!s.feesLamports) throw new Error('nothing'); this.add(k[1], s.feesLamports); s.feesLamports = 0n; }
      else if (is('deactivate_sentinel')) { s.status = STATUS.DEACTIVATED; s.deactivatedAt = this.now; }
      else { if (s.status !== STATUS.DEACTIVATED || this.now < s.lockUntil) throw new Error('locked'); this.add(k[1], s.poolLamports + s.feesLamports); s.poolLamports = 0n; s.feesLamports = 0n; }
    } else if (is('refund_attack')) {
      signed(1);
      const a = this.attacks.get(k[0].toBase58())!; if (this.now < a.createdAt + 900n) throw new Error('too early');
      this.add(k[1], a.fee); this.attacks.delete(k[0].toBase58());
    } else throw new Error('unknown instruction');
  }

  async settle(a: { sentinel: PublicKey; attack: PublicKey; attacker: PublicKey; seq: bigint; success: boolean; score: number; responseHash: Buffer }) {
    this.settleCalls++;
    const msg = verdictMessage(a.sentinel, a.attack, a.seq, a.success, a.score, a.responseHash);
    const sig = nacl.sign.detached(msg, this.judge.secretKey);
    if (!nacl.sign.detached.verify(msg, sig, this.config.judge.toBytes())) throw new Error('judge mismatch');
    const att = this.attacks.get(a.attack.toBase58()); if (!att) throw new Error('attack gone');
    if (!att.attacker.equals(a.attacker) || att.seq !== a.seq) throw new Error('verdict mismatch');
    const s = this.sentinels.get(a.sentinel.toBase58())!;
    this.attacks.delete(a.attack.toBase58());
    if (s.status !== STATUS.ACTIVE) { this.add(a.attacker, att.fee); return 'settle_refund_sig'; }
    const p = mulBps(att.fee, 5000), d = mulBps(att.fee, 3500), t = mulBps(att.fee, 1000), b = att.fee - p - d - t;
    s.poolLamports += p; s.feesLamports += d; this.add(this.treasury, t); this.add(this.burnVault, b);
    if (a.success && a.score >= 800) { this.add(a.attacker, s.poolLamports); s.poolLamports = 0n; s.status = STATUS.BREACHED; s.winner = a.attacker; }
    return `settle_sig_${this.settleCalls}`;
  }
}
