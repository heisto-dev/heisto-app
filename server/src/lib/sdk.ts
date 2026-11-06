/**
 * Hand-written client for the Heisto Anchor program. Byte layouts mirror
 * programs/heisto/src/lib.rs exactly (Anchor discriminators + Borsh).
 */
import { createHash } from 'node:crypto';
import {
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from '@solana/web3.js';

export const LAMPORTS_PER_SOL = 1_000_000_000n;
export const MIN_POOL_LAMPORTS = LAMPORTS_PER_SOL / 2n;
export const WIN_SCORE = 800;
export const STATUS = { ACTIVE: 0, BREACHED: 1, DEACTIVATED: 2 } as const;
export const STATUS_NAME = ['live', 'breached', 'deactivated'] as const;

const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest();
export const ixDisc = (name: string) => sha256(`global:${name}`).subarray(0, 8);
export const accDisc = (name: string) => sha256(`account:${name}`).subarray(0, 8);

/* ---------------- PDAs ---------------- */
const u64le = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b; };
export const configPda = (programId: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('config')], programId)[0];
export const programDataPda = (programId: PublicKey) => PublicKey.findProgramAddressSync(
  [programId.toBuffer()], new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111'),
)[0];
export const sentinelPda = (programId: PublicKey, owner: PublicKey, id: bigint) =>
  PublicKey.findProgramAddressSync([Buffer.from('sentinel'), owner.toBuffer(), u64le(id)], programId)[0];
export const attackPda = (programId: PublicKey, sentinel: PublicKey, seq: bigint) =>
  PublicKey.findProgramAddressSync([Buffer.from('attack'), sentinel.toBuffer(), u64le(seq)], programId)[0];

/* ---------------- fee math (matches current_fee / mul_bps) ---------------- */
export function currentFee(baseFee: bigint, attackCount: bigint): bigint {
  const scaled = (baseFee * (100n + attackCount)) / 100n;
  const cap = baseFee * 3n;
  return scaled < cap ? scaled : cap;
}
export const mulBps = (amount: bigint, bps: number) => (amount * BigInt(bps)) / 10_000n;

/* ---------------- verdict message ---------------- */
export function verdictMessage(sentinel: PublicKey, attack: PublicKey, seq: bigint, success: boolean, score: number, responseHash: Buffer): Buffer {
  if (responseHash.length !== 32) throw new Error('responseHash must be 32 bytes');
  if (!Number.isInteger(score) || score < 0 || score > 1000) throw new Error('score must be 0..1000');
  const score2 = Buffer.alloc(2); score2.writeUInt16LE(score);
  return Buffer.concat([Buffer.from('HEISTO_V1'), sentinel.toBuffer(), attack.toBuffer(), u64le(seq), Buffer.from([success ? 1 : 0]), score2, responseHash]);
}

/* ---------------- borsh writer ---------------- */
class W {
  parts: Buffer[] = [];
  u8(v: number) { this.parts.push(Buffer.from([v])); return this; }
  bool(v: boolean) { return this.u8(v ? 1 : 0); }
  u16(v: number) { const b = Buffer.alloc(2); b.writeUInt16LE(v); this.parts.push(b); return this; }
  u64(v: bigint) { this.parts.push(u64le(v)); return this; }
  bytes(v: Buffer) { this.parts.push(v); return this; }
  pk(v: PublicKey) { this.parts.push(v.toBuffer()); return this; }
  opt<T>(v: T | null | undefined, f: (x: T) => void) { if (v === null || v === undefined) this.u8(0); else { this.u8(1); f(v); } return this; }
  done(disc: Buffer) { return Buffer.concat([disc, ...this.parts]); }
}

const meta = (pubkey: PublicKey, isSigner: boolean, isWritable: boolean) => ({ pubkey, isSigner, isWritable });

/* ---------------- instructions ---------------- */
export const ix = {
  initializeConfig(programId: PublicKey, admin: PublicKey, a: { judge: PublicKey; treasury: PublicKey; burnVault: PublicKey; maxPoolLamports: bigint }) {
    return new TransactionInstruction({
      programId,
      keys: [
        meta(configPda(programId), false, true), meta(admin, true, true), meta(SystemProgram.programId, false, false),
        meta(programId, false, false), meta(programDataPda(programId), false, false),
      ],
      data: new W().pk(a.judge).pk(a.treasury).pk(a.burnVault).u64(a.maxPoolLamports).done(ixDisc('initialize_config')),
    });
  },
  updateConfig(programId: PublicKey, admin: PublicKey, a: { judge?: PublicKey; treasury?: PublicKey; burnVault?: PublicKey; maxPoolLamports?: bigint; paused?: boolean; newAdmin?: PublicKey }) {
    const w = new W();
    w.opt(a.judge, v => w.pk(v)).opt(a.treasury, v => w.pk(v)).opt(a.burnVault, v => w.pk(v))
      .opt(a.maxPoolLamports, v => w.u64(v)).opt(a.paused, v => w.bool(v)).opt(a.newAdmin, v => w.pk(v));
    return new TransactionInstruction({ programId, keys: [meta(configPda(programId), false, true), meta(admin, true, false)], data: w.done(ixDisc('update_config')) });
  },
  createSentinel(programId: PublicKey, owner: PublicKey, a: { id: bigint; baseFee: bigint; poolLamports: bigint; instructionsHash: Buffer }) {
    return new TransactionInstruction({
      programId,
      keys: [meta(configPda(programId), false, false), meta(sentinelPda(programId, owner, a.id), false, true), meta(owner, true, true), meta(SystemProgram.programId, false, false)],
      data: new W().u64(a.id).u64(a.baseFee).u64(a.poolLamports).bytes(a.instructionsHash).done(ixDisc('create_sentinel')),
    });
  },
  fundSentinel(programId: PublicKey, sentinel: PublicKey, funder: PublicKey, amount: bigint) {
    return new TransactionInstruction({
      programId,
      keys: [meta(configPda(programId), false, false), meta(sentinel, false, true), meta(funder, true, true), meta(SystemProgram.programId, false, false)],
      data: new W().u64(amount).done(ixDisc('fund_sentinel')),
    });
  },
  requestAttack(programId: PublicKey, sentinel: PublicKey, attack: PublicKey, attacker: PublicKey, promptHash: Buffer, maxFee: bigint) {
    return new TransactionInstruction({
      programId,
      keys: [meta(configPda(programId), false, false), meta(sentinel, false, true), meta(attack, false, true), meta(attacker, true, true), meta(SystemProgram.programId, false, false)],
      data: new W().bytes(promptHash).u64(maxFee).done(ixDisc('request_attack')),
    });
  },
  settleAttack(programId: PublicKey, a: { sentinel: PublicKey; attack: PublicKey; attacker: PublicKey; treasury: PublicKey; burnVault: PublicKey; relayer: PublicKey; success: boolean; score: number; responseHash: Buffer }) {
    return new TransactionInstruction({
      programId,
      keys: [
        meta(configPda(programId), false, false), meta(a.sentinel, false, true), meta(a.attack, false, true), meta(a.attacker, false, true),
        meta(a.treasury, false, true), meta(a.burnVault, false, true), meta(SYSVAR_INSTRUCTIONS_PUBKEY, false, false), meta(a.relayer, true, false),
      ],
      data: new W().bool(a.success).u16(a.score).bytes(a.responseHash).done(ixDisc('settle_attack')),
    });
  },
  refundAttack(programId: PublicKey, attack: PublicKey, attacker: PublicKey) {
    return new TransactionInstruction({ programId, keys: [meta(attack, false, true), meta(attacker, true, true)], data: ixDisc('refund_attack') });
  },
  ownerAction(programId: PublicKey, name: 'claim_fees' | 'deactivate_sentinel' | 'withdraw', sentinel: PublicKey, owner: PublicKey) {
    return new TransactionInstruction({ programId, keys: [meta(sentinel, false, true), meta(owner, true, true)], data: ixDisc(name) });
  },
};

/* ---------------- account decoders ---------------- */
class R {
  o = 8;
  constructor(public b: Buffer) {}
  pk() { const v = new PublicKey(this.b.subarray(this.o, this.o + 32)); this.o += 32; return v; }
  u64() { const v = this.b.readBigUInt64LE(this.o); this.o += 8; return v; }
  i64() { const v = this.b.readBigInt64LE(this.o); this.o += 8; return v; }
  u16() { const v = this.b.readUInt16LE(this.o); this.o += 2; return v; }
  u8() { return this.b[this.o++]; }
  bool() { return this.u8() === 1; }
  bytes(n: number) { const v = Buffer.from(this.b.subarray(this.o, this.o + n)); this.o += n; return v; }
}
function checkDisc(data: Buffer, name: string) {
  if (data.length < 8 || !data.subarray(0, 8).equals(accDisc(name))) throw new Error(`Account is not a ${name}`);
}

export type ConfigAccount = ReturnType<typeof decodeConfig>;
export function decodeConfig(data: Buffer) {
  checkDisc(data, 'Config'); const r = new R(data);
  return { admin: r.pk(), judge: r.pk(), treasury: r.pk(), burnVault: r.pk(), maxPoolLamports: r.u64(), paused: r.bool(), poolBps: r.u16(), defenderBps: r.u16(), treasuryBps: r.u16(), burnBps: r.u16(), bump: r.u8() };
}
export type SentinelAccount = ReturnType<typeof decodeSentinel>;
export function decodeSentinel(data: Buffer) {
  checkDisc(data, 'Sentinel'); const r = new R(data);
  return { owner: r.pk(), id: r.u64(), baseFee: r.u64(), attackCount: r.u64(), poolLamports: r.u64(), feesLamports: r.u64(), status: r.u8(), lockUntil: r.i64(), deactivatedAt: r.i64(), createdAt: r.i64(), instructionsHash: r.bytes(32), winner: r.pk(), bump: r.u8() };
}
export type AttackAccount = ReturnType<typeof decodeAttack>;
export function decodeAttack(data: Buffer) {
  checkDisc(data, 'Attack'); const r = new R(data);
  return { sentinel: r.pk(), attacker: r.pk(), seq: r.u64(), fee: r.u64(), promptHash: r.bytes(32), createdAt: r.i64(), bump: r.u8() };
}

/* ---------------- encoders for tests / fixtures ---------------- */
export function encodeSentinel(s: SentinelAccount): Buffer {
  const w = new W();
  w.pk(s.owner).u64(s.id).u64(s.baseFee).u64(s.attackCount).u64(s.poolLamports).u64(s.feesLamports).u8(s.status);
  const i = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigInt64LE(v); w.bytes(b); };
  i(s.lockUntil); i(s.deactivatedAt); i(s.createdAt);
  w.bytes(s.instructionsHash).pk(s.winner).u8(s.bump);
  return w.done(accDisc('Sentinel'));
}
export function encodeAttack(a: AttackAccount): Buffer {
  const w = new W(); w.pk(a.sentinel).pk(a.attacker).u64(a.seq).u64(a.fee).bytes(a.promptHash);
  const b = Buffer.alloc(8); b.writeBigInt64LE(a.createdAt); w.bytes(b); w.u8(a.bump);
  return w.done(accDisc('Attack'));
}
export function encodeConfig(c: ConfigAccount): Buffer {
  return new W().pk(c.admin).pk(c.judge).pk(c.treasury).pk(c.burnVault).u64(c.maxPoolLamports).bool(c.paused)
    .u16(c.poolBps).u16(c.defenderBps).u16(c.treasuryBps).u16(c.burnBps).u8(c.bump).done(accDisc('Config'));
}

export const lamportsToSol = (l: bigint) => Number(l) / 1e9;
export const solToLamports = (sol: number | string) => {
  const [i, f = ''] = String(sol).split('.');
  return BigInt(i || '0') * LAMPORTS_PER_SOL + BigInt((f + '000000000').slice(0, 9));
};
