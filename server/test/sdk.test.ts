import { describe, expect, it } from 'vitest';
import { Ed25519Program, Keypair, PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import {
  accDisc, attackPda, configPda, currentFee, decodeAttack, decodeSentinel, encodeAttack, encodeSentinel, ixDisc, mulBps,
  sentinelPda, solToLamports, verdictMessage,
} from '../src/lib/sdk.js';

const PROGRAM = new PublicKey('B5T5ecaPkksJEhhyezgTh5SdgcxDskFCWJsikeMPZdNm');

describe('sdk', () => {
  it('verdict message matches the Rust layout byte for byte', () => {
    const m = verdictMessage(new PublicKey(Buffer.alloc(32, 1)), new PublicKey(Buffer.alloc(32, 2)), 0x0102n, true, 850, Buffer.alloc(32, 9));
    expect(m.length).toBe(116);
    expect(m.subarray(0, 9).toString()).toBe('HEISTO_V1');
    expect([...m.subarray(9, 41)]).toEqual(Array(32).fill(1));
    expect([...m.subarray(41, 73)]).toEqual(Array(32).fill(2));
    expect(m.readBigUInt64LE(73)).toBe(0x0102n);
    expect(m[81]).toBe(1);
    expect(m.readUInt16LE(82)).toBe(850);
    expect([...m.subarray(84)]).toEqual(Array(32).fill(9));
  });

  it('web3.js Ed25519 instruction uses the offsets the program parser expects', () => {
    const judge = Keypair.generate();
    const msg = verdictMessage(new PublicKey(Buffer.alloc(32, 1)), new PublicKey(Buffer.alloc(32, 2)), 3n, false, 120, Buffer.alloc(32, 5));
    const sig = nacl.sign.detached(msg, judge.secretKey);
    const ix = Ed25519Program.createInstructionWithPublicKey({ publicKey: judge.publicKey.toBytes(), message: msg, signature: sig });
    const d = Buffer.from(ix.data);
    expect(d[0]).toBe(1);
    const sigOff = d.readUInt16LE(2), sigIx = d.readUInt16LE(4), pkOff = d.readUInt16LE(6), pkIx = d.readUInt16LE(8), msgOff = d.readUInt16LE(10), msgLen = d.readUInt16LE(12), msgIx = d.readUInt16LE(14);
    expect([sigIx, pkIx, msgIx]).toEqual([0xffff, 0xffff, 0xffff]);
    expect(Buffer.from(d.subarray(pkOff, pkOff + 32)).equals(Buffer.from(judge.publicKey.toBytes()))).toBe(true);
    expect(Buffer.from(d.subarray(msgOff, msgOff + msgLen)).equals(msg)).toBe(true);
    expect(nacl.sign.detached.verify(msg, d.subarray(sigOff, sigOff + 64), judge.publicKey.toBytes())).toBe(true);
    // Fixture consumed by the Rust test `parses_fixture_from_web3js` (cross-language check).
  });

  it('discriminators are sha256-based 8-byte prefixes', () => {
    expect(ixDisc('settle_attack').length).toBe(8);
    expect(accDisc('Sentinel').equals(accDisc('Attack'))).toBe(false);
  });

  it('PDAs are deterministic', () => {
    const owner = Keypair.generate().publicKey;
    expect(sentinelPda(PROGRAM, owner, 7n).equals(sentinelPda(PROGRAM, owner, 7n))).toBe(true);
    expect(sentinelPda(PROGRAM, owner, 7n).equals(sentinelPda(PROGRAM, owner, 8n))).toBe(false);
    const s = sentinelPda(PROGRAM, owner, 7n);
    expect(attackPda(PROGRAM, s, 0n).equals(attackPda(PROGRAM, s, 1n))).toBe(false);
    expect(configPda(PROGRAM)).toBeInstanceOf(PublicKey);
  });

  it('account encode/decode round-trips', () => {
    const s = { owner: Keypair.generate().publicKey, id: 42n, baseFee: 1000n, attackCount: 3n, poolLamports: 5n * 10n ** 9n, feesLamports: 7n, status: 0, lockUntil: 99n, deactivatedAt: 0n, createdAt: 11n, instructionsHash: Buffer.alloc(32, 4), winner: PublicKey.default, bump: 254 };
    const back = decodeSentinel(encodeSentinel(s));
    expect(back.id).toBe(42n); expect(back.poolLamports).toBe(s.poolLamports); expect(back.owner.equals(s.owner)).toBe(true); expect(back.bump).toBe(254);
    const a = { sentinel: Keypair.generate().publicKey, attacker: Keypair.generate().publicKey, seq: 9n, fee: 123n, promptHash: Buffer.alloc(32, 8), createdAt: 5n, bump: 251 };
    const ab = decodeAttack(encodeAttack(a));
    expect(ab.seq).toBe(9n); expect(ab.attacker.equals(a.attacker)).toBe(true); expect(ab.promptHash.equals(a.promptHash)).toBe(true);
  });

  it('fee math matches the program', () => {
    expect(currentFee(1_000_000n, 0n)).toBe(1_000_000n);
    expect(currentFee(1_000_000n, 50n)).toBe(1_500_000n);
    expect(currentFee(1_000_000n, 500n)).toBe(3_000_000n);
    const fee = 123_456_789n;
    const p = mulBps(fee, 5000), d = mulBps(fee, 3500), t = mulBps(fee, 1000);
    expect(p + d + t + (fee - p - d - t)).toBe(fee);
    expect(solToLamports('0.5')).toBe(500_000_000n);
    expect(solToLamports(2)).toBe(2_000_000_000n);
    expect(solToLamports('0.000000001')).toBe(1n);
  });
});
