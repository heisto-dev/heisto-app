import {
  ComputeBudgetProgram,
  Connection,
  Ed25519Program,
  Keypair,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import {
  configPda, decodeAttack, decodeConfig, decodeSentinel, ix, verdictMessage,
  type AttackAccount, type ConfigAccount, type SentinelAccount,
} from './sdk.js';

/** Everything the API needs from Solana. Swappable for a fake in tests. */
export interface Chain {
  programId: PublicKey;
  judgePublicKey: PublicKey;
  getConfig(): Promise<ConfigAccount>;
  getSentinel(pda: PublicKey): Promise<SentinelAccount | null>;
  getAttack(pda: PublicKey): Promise<AttackAccount | null>;
  /** Unsigned v0 transaction (base64) for a wallet to sign and send. */
  buildUserTx(payer: PublicKey, instructions: TransactionInstruction[]): Promise<string>;
  /** Wait until a user-sent signature is confirmed; throws if it failed. */
  confirm(signature: string): Promise<void>;
  /** Broadcast a wallet-signed transaction (fallback for wallets without signAndSendTransaction). */
  sendRaw(txBase64: string): Promise<string>;
  /** Sign the verdict with the judge key and submit settle_attack as relayer. */
  settle(a: { sentinel: PublicKey; attack: PublicKey; attacker: PublicKey; seq: bigint; success: boolean; score: number; responseHash: Buffer }): Promise<string>;
}

export const keypairFromBase58 = (s: string) => Keypair.fromSecretKey(bs58.decode(s.trim()));

/** A real RPC connection with no signing key and no transaction capability. */
export function createReadOnlyChain(rpcUrl: string, id: string) {
  const connection = new Connection(rpcUrl, { commitment: 'confirmed', disableRetryOnRateLimit: true });
  const programId = new PublicKey(id);
  const blocked = async (): Promise<never> => { throw new Error('Mainnet transactions are not enabled.'); };
  const chain: Chain = {
    programId,
    get judgePublicKey(): PublicKey { throw new Error('Read-only mode has no signing wallet.'); },
    async getConfig() {
      const account = await connection.getAccountInfo(configPda(programId));
      if (!account?.owner.equals(programId)) throw new Error('Program configuration is not available.');
      return decodeConfig(account.data);
    },
    async getSentinel(pda) {
      const account = await connection.getAccountInfo(pda);
      return account?.owner.equals(programId) ? decodeSentinel(account.data) : null;
    },
    async getAttack(pda) {
      const account = await connection.getAccountInfo(pda);
      return account?.owner.equals(programId) ? decodeAttack(account.data) : null;
    },
    buildUserTx: blocked, confirm: blocked, sendRaw: blocked, settle: blocked,
  };
  let cached: { at: number; value: { mainnet: boolean; programDeployed: boolean; configReady: boolean } } | undefined;
  async function status() {
    if (cached && Date.now() - cached.at < 10_000) return cached.value;
    const [genesis, accounts] = await Promise.all([
      connection.getGenesisHash(),
      connection.getMultipleAccountsInfo([programId, configPda(programId)]),
    ]);
    const value = {
      mainnet: genesis === '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
      programDeployed: accounts[0]?.executable === true,
      configReady: accounts[1]?.owner.equals(programId) === true,
    };
    if (value.configReady) decodeConfig(accounts[1]!.data);
    cached = { at: Date.now(), value };
    return value;
  }
  return { chain, status };
}

export function createSolanaChain(opts: { rpcUrl: string; programId: string; judgeSecret: string; relayerSecret: string; priorityFeeMicroLamports: number }): Chain {
  const connection = new Connection(opts.rpcUrl, 'confirmed');
  const programId = new PublicKey(opts.programId);
  const judge = keypairFromBase58(opts.judgeSecret);
  const relayer = keypairFromBase58(opts.relayerSecret);
  let configCache: { at: number; value: ConfigAccount } | null = null;

  const priority = () => [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: opts.priorityFeeMicroLamports }),
  ];

  async function getConfig() {
    if (configCache && Date.now() - configCache.at < 30_000) return configCache.value;
    const info = await connection.getAccountInfo(configPda(programId));
    if (!info) throw new Error('Heisto config account not found. Run `npm run init-config` first.');
    const value = decodeConfig(info.data);
    configCache = { at: Date.now(), value };
    return value;
  }

  return {
    programId,
    judgePublicKey: judge.publicKey,
    getConfig,
    async getSentinel(pda) {
      const info = await connection.getAccountInfo(pda);
      return info && info.owner.equals(programId) ? decodeSentinel(info.data) : null;
    },
    async getAttack(pda) {
      const info = await connection.getAccountInfo(pda);
      return info && info.owner.equals(programId) ? decodeAttack(info.data) : null;
    },
    async buildUserTx(payer, instructions) {
      const { blockhash } = await connection.getLatestBlockhash('confirmed');
      const msg = new TransactionMessage({ payerKey: payer, recentBlockhash: blockhash, instructions: [...priority(), ...instructions] }).compileToV0Message();
      return Buffer.from(new VersionedTransaction(msg).serialize()).toString('base64');
    },
    async sendRaw(txBase64) {
      const tx = VersionedTransaction.deserialize(Buffer.from(txBase64, 'base64'));
      if (!tx.message.staticAccountKeys.some(k => k.equals(programId)) && !tx.message.compiledInstructions.length) throw new Error('Empty transaction');
      return connection.sendRawTransaction(tx.serialize(), { maxRetries: 3 });
    },
    async confirm(signature) {
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline) {
        const { value } = await connection.getSignatureStatuses([signature], { searchTransactionHistory: true });
        const st = value[0];
        if (st?.err) throw new Error(`Transaction failed: ${JSON.stringify(st.err)}`);
        if (st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized')) return;
        await new Promise(r => setTimeout(r, 1200));
      }
      throw new Error('Timed out waiting for confirmation');
    },
    async settle(a) {
      const cfg = await getConfig();
      if (!cfg.judge.equals(judge.publicKey)) throw new Error('JUDGE_SECRET_KEY does not match the on-chain judge key');
      const message = verdictMessage(a.sentinel, a.attack, a.seq, a.success, a.score, a.responseHash);
      const signature = nacl.sign.detached(message, judge.secretKey);
      const instructions = [
        ...priority(),
        Ed25519Program.createInstructionWithPublicKey({ publicKey: judge.publicKey.toBytes(), message, signature }),
        ix.settleAttack(programId, { sentinel: a.sentinel, attack: a.attack, attacker: a.attacker, treasury: cfg.treasury, burnVault: cfg.burnVault, relayer: relayer.publicKey, success: a.success, score: a.score, responseHash: a.responseHash }),
      ];
      const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
      const tx = new VersionedTransaction(new TransactionMessage({ payerKey: relayer.publicKey, recentBlockhash: blockhash, instructions }).compileToV0Message());
      tx.sign([relayer]);
      const sig = await connection.sendTransaction(tx, { maxRetries: 3 });
      const res = await connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, 'confirmed');
      if (res.value.err) throw new Error(`settle failed: ${JSON.stringify(res.value.err)}`);
      return sig;
    },
  };
}
