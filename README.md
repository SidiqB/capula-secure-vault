# Capula Secure Password Vault Backup API

This project implements the Capula software developer take-home exercise as a small Python service and client. A user can derive cryptographic keys from an email address and master password, register the public key, complete mocked email verification, encrypt a vault locally, store the opaque ciphertext, retrieve it after a server restart, and decrypt it locally.

The server never receives the master password, private signing key, encryption key or plaintext vault.

## Requirements

- Python 3.11 or newer
- macOS, Linux or Windows
- Internet access during the initial dependency installation

Only one third-party package is used: `cryptography==50.0.1`.

## Quick start

From the repository root, create an isolated environment and install the dependency:

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the automated suite:

```bash
python -m unittest discover -s tests -v
```

The expected result is 30 passing tests followed by `OK`.

## Run the complete demonstration

Start the service in the first terminal:

```bash
python -m secure_vault.server
```

It listens on `http://127.0.0.1:3000` and stores local state in `data/vault.json`.

Open a second terminal, activate the same virtual environment, and run the demonstration with an email that is not already registered:

```bash
python -m secure_vault.client.demo demo --email candidate.demo@example.com
```

The client securely prompts for a master password without displaying or placing it in shell history. It then:

1. Derives the signing and encryption keys.
2. Registers the public key.
3. Completes mocked email verification.
4. Encrypts a sample vault locally.
5. Stores the encrypted vault.
6. Retrieves and decrypts it locally.
7. Confirms that the recovered vault matches the original.

A successful run ends with JSON containing `"matched": true`.

## Demonstrate recovery after restart

After a successful demonstration, stop the server with `Control+C` and start it again:

```bash
python -m secure_vault.server
```

In the client terminal, use the same email and master password:

```bash
python -m secure_vault.client.demo recover --email candidate.demo@example.com
```

This recovery command does not register again. It recreates the same keys from the email and master password, authenticates a retrieve request, downloads the existing ciphertext and decrypts it locally.

If the password or email differs, the derived signing key will not match the registered public key and the server rejects the request.

## Server options

The local defaults can be overridden:

```bash
python -m secure_vault.server \
  --host 127.0.0.1 \
  --port 3000 \
  --data ./data/vault.json
```

The default storage path is resolved relative to the project package, not the shell's current directory.

The built-in server is intended for local assessment. A production deployment would bind it to a private interface behind a TLS-terminating reverse proxy or load balancer. See [Security](docs/SECURITY.md#transport-security).

## Repository structure

```text
secure_vault/
├── authentication.py   Ed25519 verification and verification tokens
├── errors.py           Stable API errors
├── protocol.py         Input, Base64, payload and nonce validation
├── server.py           HTTP handling and route dispatch
├── service.py          Registration, verification, store and retrieve rules
├── storage.py          Locked and atomic JSON persistence
└── client/
    ├── api.py          Signed HTTP client
    ├── crypto.py       Scrypt key derivation and AES-GCM encryption
    └── demo.py         Complete demonstration and recovery commands
tests/
├── test_crypto.py
├── test_integration.py
├── test_protocol.py
└── test_storage.py
docs/
├── API.md
├── ARCHITECTURE.md
├── SECURITY.md
└── TESTING.md
```

## Documentation

- [API contract](docs/API.md)
- [Architecture and design decisions](docs/ARCHITECTURE.md)
- [Security model, TLS and limitations](docs/SECURITY.md)
- [Testing guide and coverage](docs/TESTING.md)

## Important assumptions

- Email verification is intentionally mocked by returning the verification token in the registration response.
- The server stores one latest vault per account.
- Authenticated request nonces must strictly increase for each account.
- Correctly signed requests consume their nonce even when the operation later returns an application error. Invalid signatures do not consume nonces.
- The JSON store supports one server process. Its lock does not coordinate multiple processes.
- The solution is an assessment implementation, not a production password manager.

## Private data and Git

`data/vault.json`, `.venv`, Python caches and ZIP files are ignored by Git. Do not commit real email addresses, vault data or master passwords.
