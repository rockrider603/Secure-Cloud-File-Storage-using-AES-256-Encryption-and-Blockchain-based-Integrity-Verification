# Secure Cloud File Storage

Client-side encrypted file storage prototype. The browser encrypts each file with a fresh AES-256-GCM key and nonce, hashes the serialized ciphertext, and only then sends ciphertext to private object storage. Downloads fail closed unless the downloaded bytes match the configured chain record.

## Local setup

Requirements: Node.js 20+, Python 3.11+, and Docker Desktop with Compose. Copy `.env.example` to `.env` and replace `JWT_SECRET` with a long random value before startup. Run `docker compose up --build`; visit http://localhost:5173. The compose stack starts PostgreSQL, MinIO, a local Hardhat chain, API and browser app. In a second terminal, `cd contracts && npm install && npx hardhat compile && npx hardhat run scripts/deploy.ts --network localhost`, then copy the deployed address into `CHAIN_CONTRACT_ADDRESS` and the first Hardhat account's printed development key into `CHAIN_PRIVATE_KEY` in your ignored `.env`. Recreate the API with `docker compose up -d --force-recreate api`. Deploy before the first upload. Never use a Hardhat development key outside the local chain.

The MVP intentionally uses one local provider and owner-only access. It has no sharing, multi-cloud failover, or anomaly model. A random master key is encrypted with a passphrase-derived PBKDF2 key; the API stores only that wrapped master key and each version's DEK wrapped by the master key. Losing the passphrase means losing access. Use only synthetic files in development. Do not expose these development services to the internet.

## Checks

`cd frontend && npm install && npm test && npm run build`
`cd backend && python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt && pytest`
`cd contracts && npm install && npx hardhat test`

## Security notes

Envelope bytes: ASCII `SCFS`, one-byte format version `1`, 12-byte nonce, followed by Web Crypto AES-GCM output (ciphertext plus 16-byte tag). SHA-256 covers every serialized byte. A random 32-byte DEK is created for each version. The API receives only encrypted object bytes and opaque random IDs; password hashes, metadata, wrapped DEKs and audit entries live server side. Chain IDs, filenames, users, and access policy are never published on-chain.

The chain anchors the submitted ciphertext digest; it does not prove a file is benign or prevent deletion, denial of service, stolen credentials, malicious authorized users, browser compromise, key loss, or metadata correlation. Local-chain performance does not predict public-chain costs or latency. Use TLS, a reviewed production key recovery design, strict CSP, secret management, backups, and operational security review before deployment.

## Demo

Register two accounts, upload and download a synthetic file as the first user, then use the local MinIO console to alter/remove an object and confirm the browser refuses to decrypt. Sign in as the second user and confirm only their own files appear. Never use real user content in this demo.
"# Secure-Cloud-File-Storage-using-AES-256-Encryption-and-Blockchain-based-Integrity-Verification" 
