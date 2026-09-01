# API Contract

The local base URL is `http://127.0.0.1:3000`.

All POST requests require:

```text
Content-Type: application/json
```

The maximum encoded HTTP request body is 256 KiB. Exactly one non-negative `Content-Length` header is required.

Successful and unsuccessful responses use JSON. Errors have this shape:

```json
{
  "error": {
    "code": "MACHINE_READABLE_CODE",
    "message": "human-readable message"
  }
}
```

## Health check

### `GET /health`

Response:

```json
{
  "status": "ok"
}
```

## Register

### `POST /v1/register`

Registration is unsigned because an account does not have a registered public key yet.

Request:

```json
{
  "email": "person@example.com",
  "publicKey": "<Base64 Ed25519 public key>"
}
```

The email must already be trimmed and lowercase. The decoded public key must contain exactly 32 bytes.

Response: `201 Created`

```json
{
  "status": "verification_required",
  "verificationToken": "<mock token>",
  "expiresAt": "2026-09-02T12:15:00+00:00"
}
```

Returning the token mocks delivery by email and does not prove control of a real mailbox.

## Verify email

### `POST /v1/verify-email`

Request:

```json
{
  "email": "person@example.com",
  "verificationToken": "<token from registration>"
}
```

Response: `200 OK`

```json
{
  "status": "verified"
}
```

Tokens expire after 15 minutes. The server stores only a SHA-256 token hash and clears it after successful verification.

## Authenticated envelope

Store and retrieve use this exact request shape:

```json
{
  "email": "person@example.com",
  "payload": "<Base64 UTF-8 JSON>",
  "nonce": 123,
  "signature": "<Base64 Ed25519 signature>"
}
```

The signature covers every other envelope field. The signed bytes are the UTF-8 encoding of this canonical JSON object:

```json
{"email":"person@example.com","nonce":123,"payload":"<exact Base64 payload text>"}
```

Canonicalisation rules:

- Keys are sorted.
- Separators are `,` and `:` with no extra spaces.
- Unicode is encoded directly as UTF-8.
- The exact Base64 payload text is signed.

The nonce must be a positive integer no greater than `2^63 - 1`, and it must be greater than the account's last consumed nonce.

After signature verification and replay checking, a correctly signed request consumes its nonce even if payload validation or the requested operation returns an application error. Requests with invalid signatures do not consume a nonce.

## Store an encrypted vault

### `POST /v1/store`

Decoded payload:

```json
{
  "type": "store",
  "vault": "<Base64 opaque encrypted vault>"
}
```

The decoded encrypted vault is limited to 128 KiB.

Response: `200 OK`

```json
{
  "status": "stored"
}
```

The server validates the Base64 representation but does not decrypt or interpret the vault.

## Retrieve an encrypted vault

### `POST /v1/retrieve`

Decoded payload:

```json
{
  "type": "retrieve"
}
```

Response: `200 OK`

```json
{
  "vault": "<Base64 opaque encrypted vault>"
}
```

The client decrypts the returned value locally.

## Main error codes

| HTTP status | Code | Meaning |
|---:|---|---|
| 400 | `INVALID_JSON` | Request body is not a JSON object. |
| 400 | `UNEXPECTED_FIELDS` | The object has missing or additional fields. |
| 400 | `INVALID_BASE64` | A Base64 field is malformed or non-canonical. |
| 400 | `INVALID_NONCE` | The nonce has the wrong type or range. |
| 400 | `INVALID_CONTENT_LENGTH` | The request length is malformed, repeated or negative. |
| 401 | `INVALID_SIGNATURE` | Ed25519 verification failed. |
| 401 | `INVALID_VERIFICATION_TOKEN` | Email verification token did not match. |
| 403 | `ACCOUNT_NOT_VERIFIED` | Store or retrieve was attempted before verification. |
| 404 | `ACCOUNT_NOT_FOUND` | No account exists for the canonical email. |
| 404 | `VAULT_NOT_FOUND` | The verified account has no stored vault. |
| 409 | `ACCOUNT_EXISTS` | The email is already registered. |
| 409 | `ACCOUNT_ALREADY_VERIFIED` | Verification was repeated. |
| 409 | `NONCE_REPLAYED` | The nonce is not greater than the stored nonce. |
| 410 | `VERIFICATION_EXPIRED` | The 15-minute verification period elapsed. |
| 411 | `LENGTH_REQUIRED` | No `Content-Length` header was supplied. |
| 413 | `REQUEST_TOO_LARGE` | The HTTP body or decoded field exceeds its limit. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type` is not JSON. |
