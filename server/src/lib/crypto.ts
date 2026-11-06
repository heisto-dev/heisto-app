import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { PublicKey } from '@solana/web3.js';

export const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest();
export const sha256hex = (data: string | Buffer) => sha256(data).toString('hex');

/** AES-256-GCM. Output: base64(iv | tag | ciphertext). */
export function encrypt(plain: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex');
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
export function decrypt(blob: string, keyHex: string): string {
  const raw = Buffer.from(blob, 'base64');
  const d = createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
}

/** Wallet sign-in: the wallet signs `Heisto auth\n<wallet>\n<unix seconds>`; valid for 10 minutes. */
export function authMessage(wallet: string, ts: number) {
  return `Heisto auth\n${wallet}\n${ts}`;
}
export function verifyWalletAuth(header: string | undefined, nowSec = Math.floor(Date.now() / 1000)): string | null {
  if (!header) return null;
  const [wallet, tsStr, sig] = header.split('.');
  const ts = Number(tsStr);
  if (!wallet || !sig || !Number.isFinite(ts) || Math.abs(nowSec - ts) > 600) return null;
  try {
    const ok = nacl.sign.detached.verify(Buffer.from(authMessage(wallet, ts)), bs58.decode(sig), new PublicKey(wallet).toBytes());
    return ok ? wallet : null;
  } catch { return null; }
}

export function newApiKey() {
  const key = `hst_live_${randomBytes(24).toString('base64url')}`;
  return { key, hash: sha256hex(key) };
}
export function safeEqual(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
