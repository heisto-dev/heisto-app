# Heisto App

The original Heisto web interface and Node/Fastify/Postgres service for an AI red-teaming arena on Solana.

**Website:** https://heisto.xyz · **Support/security:** support@heisto.xyz

## Scope and layout
- `web/`: the existing interface and visual assets, including Arena, Deploy, Practice, Guard, Shield and profile controls.
- `server/src/`: API, chain integration, providers, three-judge evaluation, quota accounting and cryptography.
- `server/sql/`: explicit schema migrations, no database data.
- `server/test/`: offline tests with generated identities and clearly labelled test doubles. They are not production balances or live verdict evidence.
- `server/scripts/`: explicit migration and read-only readiness checks. No live deployment signer or funded owner key is included.

## Build and test (no production credentials required)
```sh
corepack enable
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
pnpm test
```
Use Node 22+ and pnpm 10.26.1. The lockfile is an isolated projection of the original dependency graph, not a lock for unrelated projects.

## Running your own service
Build/test success alone does not make a new service production-ready. Provision your own Postgres database and RPC/provider access. Configure the names shown in `.env.example` through a secret manager; there are no usable values in this repository. Load the environment into the process before starting. Never commit a filled-in environment file.

Set the database URL for your intended environment, review migrations, and run `pnpm migrate` explicitly before startup. Startup checks existing tables rather than running schema DDL. Preserve the original encryption key when opening existing encrypted records. Run `pnpm preflight` before a Mainnet launch, then `pnpm start`; binding is 0.0.0.0 and timestamps use UTC.

The official program has a configured judge signer. Your own service cannot settle on its behalf without that authority. Local/devnet work needs a separately configured program and test-only roles. Do not reuse production admin/owner keys or infer permission to deploy, upgrade or spend from this quick start. Mock judging is forbidden on Mainnet.

## Trust and data
Private challenge configuration and custom provider keys are encrypted at rest. Wallet authorization, Guard API keys and on-chain transaction authority serve different purposes. AI requests leave the service for the configured providers. The on-chain program verifies the trusted judge signature, not an AI inference. Mainnet contract authority remains upgradeable.

## Documentation and evidence
- [heisto-app](https://github.com/heisto-dev/heisto-app)
- [heisto-contracts](https://github.com/heisto-dev/heisto-contracts)
- [heisto-sdk](https://github.com/heisto-dev/heisto-sdk)
- [heisto-docs](https://github.com/heisto-dev/heisto-docs)
- [heisto-mainnet-proof](https://github.com/heisto-dev/heisto-mainnet-proof)

See the docs repository for architecture, route inventory, flows, user guide, privacy boundaries and current limitations. Creation/funding proof does not claim an end-to-end paid attack or prize payout. Tests are not an independent security audit.

## Dependencies and license
Direct dependency versions are pinned. The current reviewed graph has no known high/critical dependency findings in the source scan but retains moderate advisories; review `pnpm audit` before a production release. Do not upgrade the chain SDK or contract dependencies blindly. MIT; third-party assets/marks retain their original rights (NOTICE).
