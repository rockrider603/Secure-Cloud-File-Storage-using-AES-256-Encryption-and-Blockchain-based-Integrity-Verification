# Threat model

## Assets

Plaintext file contents; passphrase, master key, per-version DEKs and transient plaintext; account credentials; owner/file/version metadata; ciphertext availability; integrity evidence.

## Trust boundaries and attacker capabilities

- The browser is trusted with plaintext and keys. An attacker controlling the browser, extensions, device, or script origin can steal them.
- The API/database are trusted to authenticate and authorize, but must not learn plaintext, passphrases, or unwrapped keys. A malicious API can deny access or alter metadata; the chain digest check catches ciphertext substitution when the browser reaches the correct configured chain.
- Object storage can return modified, substituted, truncated, or missing ciphertext. Hash mismatch blocks decryption; absence remains an availability failure.
- Chain/RPC can be unavailable or misconfigured. Chain ID is checked on API access and failure blocks completion/download verification. Production must additionally validate the trustworthiness/finality of its RPC.

## Abuse cases and controls

Cross-user ID guessing is rejected by owner scoped queries. Ciphertext modification is detected before key unwrapping. GCM tag/key failure cannot produce a download. Duplicate contract registration reverts; API retries read before write. User-controlled filenames are never used as object keys or published on-chain. Audit records retain actor, event, resource, and outcome without secrets or contents.

## Residual risks

Denial of service, deletion, stolen credentials, malicious authorized users, browser compromise, passphrase loss, metadata/access-pattern correlation, local chain limitations, and malicious source files remain possible. A lost passphrase is unrecoverable. The chain proves only that a digest was registered at a time, not that content is safe, owned lawfully, or available.
