# Architecture and Design Decisions

## Objective

The system provides backup and recovery for an encrypted password-vault JSON document. All plaintext and private cryptographic operations remain on the client. The server associates an email address with a public signing key and stores only an opaque encrypted blob.

## Components

### Client cryptography

`secure_vault/client/crypto.py` derives keys and encrypts or decrypts vaults.

Scrypt derives 64 bytes from the master password using a deterministic, domain-separated hash of the normalised email as the salt. The first 32 bytes seed an Ed25519 private key and the final 32 bytes form the AES-256 key.

The deterministic process enables recovery on a new client using only the same email and master password. The master password, derived private key and AES key remain in client memory and are never serialised or transmitted.

### Client API

`secure_vault/client/api.py` builds the specified authenticated envelope. It canonicalises and Base64-encodes operation payloads, creates a monotonic request nonce, signs the email, exact payload text and nonce, and sends JSON over HTTP.

### HTTP server

`secure_vault/server.py` handles transport concerns: media type, body length, request-size limits, JSON decoding, routing and consistent JSON errors. Business rules do not live in the request handler.

The default is a threaded standard-library development server bound to loopback. The host, port and data path are configurable.

### Service

`secure_vault/service.py` contains the use cases:

- Register an email and public key.
- Complete mocked email verification.
- Authenticate and store an opaque encrypted vault.
- Authenticate and retrieve the encrypted vault.
- Atomically enforce persistent request nonces.

### Protocol and authentication

`secure_vault/protocol.py` provides strict field, email, Base64, payload, size and nonce validation.

`secure_vault/authentication.py` creates and hashes verification tokens, constructs the canonical signed message and verifies Ed25519 signatures with the stored public key.

### Persistence

`secure_vault/storage.py` maintains a versioned JSON state. Each transaction:

1. Takes a process-local re-entrant lock.
2. Deep-copies the current state.
3. Applies one change callback.
4. Writes the entire next state to a restrictive temporary file.
5. Flushes and calls `fsync`.
6. Atomically replaces the previous file.
7. Publishes the new in-memory state.

This prevents readers from seeing partial in-process changes and reduces corruption risk if a write is interrupted.

## Registration flow

```text
Master password + email
        |
        v
Client derives Ed25519 private/public key
        |
        v
POST /v1/register with email + public key
        |
        v
Server stores public key + token hash
        |
        v
POST /v1/verify-email with mock token
        |
        v
Account becomes eligible for store/retrieve
```

## Store flow

```text
Plaintext vault
        |
        v
Client AES-GCM encryption
        |
        v
Opaque encrypted Base64 vault
        |
        v
Signed store envelope
        |
        v
Server verifies signature and nonce
        |
        v
Server stores opaque text
```

## Recovery flow

```text
Same email + same master password
        |
        v
Same signing and encryption keys
        |
        v
Signed retrieve envelope
        |
        v
Server returns opaque ciphertext
        |
        v
Client decrypts and recovers JSON vault
```

## Replay design

The account stores the last consumed API nonce. A new authenticated request must have a strictly larger nonce. Signature verification happens before any nonce change so an attacker without the private key cannot exhaust another account's nonce space.

After a valid signature and replay check, the nonce update and operation result are handled in one storage transaction. If the operation produces an API-level error, the nonce is still committed and the error is returned afterwards. Repeating that signed request therefore produces `NONCE_REPLAYED`.

## Why separate files

The division makes responsibilities easier to test and discuss:

- HTTP code does not perform cryptography.
- Storage code does not understand operations.
- Server code never imports AES decryption.
- Client code does not directly edit server state.
- Protocol rules are shared where exact representations must match.

## Deliberate scope

The exercise asks for a small coherent solution, not production infrastructure. JSON persistence and the standard-library HTTP server keep the implementation inspectable. Production alternatives and limitations are recorded in `SECURITY.md`.
