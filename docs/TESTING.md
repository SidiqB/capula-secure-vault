# Testing Guide

## Run everything

From the repository root with the virtual environment active:

```bash
python -m unittest discover -s tests -v
```

The suite contains 30 tests and uses only temporary files and temporary loopback ports. It does not modify `data/vault.json`.

## Run one group

```bash
python -m unittest tests.test_protocol -v
python -m unittest tests.test_crypto -v
python -m unittest tests.test_integration -v
```

## What is covered

### Protocol

- Email normalisation and canonical email enforcement
- Canonical and invalid Base64
- Valid and invalid nonce types and ranges

### Client cryptography

- Repeatable key recovery from the same email and master password
- AES-GCM encryption and decryption round trip
- Wrong-password decryption failure
- Different ciphertext from repeated encryption of the same vault
- Ciphertext-tag tampering rejection

### HTTP integration

- Registration and mocked verification
- Store, retrieve and local decryption
- Persistent file reload
- Genuine HTTP server stop/start and fresh-client recovery
- Unverified store and retrieve rejection
- Successful-request replay rejection
- Replay rejection after an authenticated operation error
- Altered payload and altered nonce rejection
- Signature from another private key rejection
- Incorrect, expired and reused verification tokens
- Duplicate registration
- Missing, negative and oversized `Content-Length`
- Unsupported media type
- Complete sample demonstration client

### Storage

- Invalid top-level storage rejection
- Invalid nested-account rejection
- Atomic persistence produces reloadable JSON

## Manual examiner workflow

1. Start the server with `python -m secure_vault.server`.
2. Run `python -m secure_vault.client.demo demo --email <new-email>`.
3. Enter a master password when prompted and confirm `"matched": true`.
4. Stop and restart the server.
5. Run `python -m secure_vault.client.demo recover --email <same-email>`.
6. Enter the same master password and confirm that the vault is recovered.
7. Enter a different password and confirm that the signed retrieve request is rejected.

## Boundaries of the suite

The suite does not claim production readiness. It does not stress-test many concurrent clients or separate server processes, benchmark KDF settings, test a real TLS proxy, exercise real email delivery, detect rollback to an older valid encrypted vault or simulate disk and operating-system failures. These are documented production improvements rather than requirements of the take-home implementation.
