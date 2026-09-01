# Security Model

## Protected values

Under the intended client workflow:

| Value | Reaches server | Written to `vault.json` |
|---|---:|---:|
| Plaintext vault and password entries | No | No |
| Master password | No | No |
| Ed25519 private key | No | No |
| AES encryption key | No | No |
| Email address | Yes | Yes |
| Ed25519 public key | Yes | Yes |
| Encrypted vault | Yes | Yes |
| Verification-token hash | Yes | Yes until verification |

The server cannot decrypt the vault. Losing the master password makes recovery impossible.

## Cryptographic choices

### Scrypt

Scrypt turns the master password and a deterministic email-derived salt into 64 bytes. Parameters are `N=2^14`, `r=8`, `p=1`.

This setting uses approximately 16 MiB per derivation and keeps the demonstration responsive on ordinary assessment hardware. It is lower than stronger modern production recommendations. A deployed system should benchmark a higher work factor and store a KDF version and parameters with the encrypted vault so settings can be upgraded without making existing vaults unrecoverable.

The registered public key permits offline guessing after a server-data compromise: an attacker can derive a candidate public key from a guessed master password and compare it with the stored public key. The email-derived salt prevents one computation being reused for every account, but it does not protect a weak individual password. Users should choose a unique master passphrase of at least 16 characters.

The signing and encryption keys are separate halves of one Scrypt result. A production design could derive labelled subkeys from a root secret using HKDF for more explicit domain separation.

### Ed25519

Ed25519 signs each authenticated envelope. The signature covers the canonical email, exact Base64 payload text and API nonce. Changing any signed field invalidates the signature.

The private key exists only on the client. The public key is expected to be public and is stored by the server.

### AES-GCM

AES-GCM encrypts the vault locally with a 256-bit key. Every encryption uses a random 96-bit nonce from `os.urandom`. The encrypted blob is:

```text
version byte || 12-byte AES nonce || ciphertext and authentication tag
```

Fixed authenticated additional data binds the ciphertext to this application's vault format. Modification, the wrong key or the wrong tag makes decryption fail.

The AES nonce and API nonce are unrelated. The AES nonce makes encryptions unique; the API nonce prevents signed-request replay.

## Verification tokens

Verification tokens are created with Python's `secrets` module, expire after 15 minutes and are stored only as SHA-256 hashes. Comparisons use `hmac.compare_digest`.

For this exercise, the token is returned in the registration response to mock email delivery. That demonstrates the state transition but does not prove ownership of a real mailbox. Production would deliver a single-use token through an email provider and include a safe resend process.

## Replay protection

The server stores one monotonic `lastNonce` per account. Nonces are updated in the same locked persistence transaction as successful operations. Correctly signed operations that return an API error also consume their nonce, so submitting the exact request again is classified as a replay.

Invalid signatures do not consume a nonce. This prevents unauthenticated attackers from advancing another account's nonce.

The current client uses nanosecond wall-clock values and local monotonic increments. This is simple and supports fresh-client recovery, but a device whose clock moves far backwards may need to wait or learn a newer nonce. Multiple devices can invalidate one another's lower outstanding requests. Production could use server-issued challenges, per-device counters or sessions.

## Transport security

Local development uses HTTP on `127.0.0.1`. This is acceptable only for a local demonstration.

Production requires HTTPS. A typical deployment would:

1. Run the Python service on a private loopback or internal address.
2. Place Nginx, Caddy, a cloud load balancer or an API gateway in front of it.
3. Terminate TLS 1.2 or newer at that trusted proxy using a managed certificate.
4. Redirect or reject plaintext HTTP.
5. Restrict direct access to the Python service.
6. Configure the client with an `https://` base URL.

TLS remains necessary even though the vault is encrypted. It protects email addresses, verification tokens, metadata and availability, and it prevents network attackers from replaying or blocking traffic.

## Persistence security

Temporary files are created with restrictive operating-system permissions and atomically replace the storage file. The repository ignores `data/*.json` to prevent accidental commits.

Limitations:

- The lock coordinates threads in one process, not two server processes sharing the file.
- The server validates required nested account fields and basic types at startup, but it does not re-parse timestamps or cryptographically revalidate every stored public key and encrypted vault.
- AES-GCM detects modified ciphertext but cannot detect a server returning an older valid ciphertext.
- JSON storage has no backup, replication or disaster-recovery process.

A production service would use a transactional database, encryption and access control for server metadata, managed backups, single-writer guarantees or database concurrency, schema migrations, audit logging and a signed vault revision to detect rollback.

## Operational limitations

- The standard-library threaded server is for demonstration, not Internet exposure.
- There is no rate limiting for registration, verification or signature failures.
- There is no verification-token resend endpoint.
- There is no account deletion, key rotation or master-password migration.
- One latest vault is stored per account.
- Submitting `MAX_NONCE` makes it impossible to submit a larger future nonce.

These choices keep the assessment implementation small and inspectable and should be addressed before production use.
