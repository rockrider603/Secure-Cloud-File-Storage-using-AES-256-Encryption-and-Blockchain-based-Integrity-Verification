# API v1

All routes use `/api/v1`; protected endpoints use `Authorization: Bearer <short-lived token>`. JSON errors use FastAPI's `detail` string.

| Method | Route | Purpose |
|---|---|---|
| POST | `/auth/register` | Create account; returns access token and safe profile |
| POST | `/auth/login` | Authenticate; returns token and encrypted key backup if configured |
| POST | `/auth/logout` | Revoke the active access session and record logout event |
| GET | `/auth/me` | Safe profile and encrypted backup metadata |
| PUT | `/auth/crypto-backup` | Store passphrase-encrypted master key only |
| GET | `/files` | List only caller-owned ready and pending versions |
| GET | `/files/{file_id}` | Return one caller-owned file and its versions |
| POST | `/files` | Create first pending version and short-lived size constrained upload policy |
| POST | `/files/{file_id}/versions` | Create a new immutable pending version and upload policy |
| POST | `/files/{file_id}/versions/{version_id}/complete` | Verify stored bytes, register/read chain, mark ready |
| POST | `/files/{file_id}/versions/{version_id}/download-url` | Owner check and short-lived GET URL |
| PUT | `/files/{file_id}/versions/{version_id}/key-backup` | Store the DEK wrapped by the locally unlocked master key |
| GET | `/files/{file_id}/versions/{version_id}/key-backup` | Retrieve the encrypted DEK wrapper after owner check |
| GET | `/files/{file_id}/versions/{version_id}/integrity` | Read digest from configured registry |
| POST | `/files/{file_id}/versions/{version_id}/integrity/report` | Record an owner-scoped client verification failure (`digest_mismatch`, `object_missing`, or `decrypt_failed`) |
| DELETE | `/files/{file_id}` | Archive metadata; immutable chain entries remain |

The frontend hashes ciphertext before requesting an upload. The returned S3 form policy constrains the exact content size and media type. `complete` independently reads the uploaded object and verifies its size and digest before registering it. A response is ready only after chain read-back matches. Errors for missing object, size/digest mismatch, missing chain entry, and unavailable registry are non-success responses. Authentication uses Argon2id password hashes, short-lived database-backed access sessions, logout revocation, and a process-local 10-failure-per-minute limiter for development. Signed URL query strings must never be logged.
