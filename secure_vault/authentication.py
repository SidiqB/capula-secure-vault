import base64
import hashlib
import hmac
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ApiError, bad_request
from .protocol import decode_base64

def validate_public_key(public_key_text): 
    # We validate the Base64 encoded Ed25519 public key. It must be exactly 32 bytes when decoded and must be a valid Ed25519 public key.
    public_key_bytes = decode_base64(
        public_key_text,
        "publicKey",
        max_bytes=32,
    )

    if len(public_key_bytes) != 32:
        raise bad_request(
            "INVALID_PUBLIC_KEY",
            "publicKey must contain exactly 32 bytes",
        )

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError:
        raise bad_request(
            "INVALID_PUBLIC_KEY",
            "publicKey must be a valid Ed25519 public key",
        )

    return public_key_text

def create_verification_token(): # Creating a sercure, random token for email verification.
    return secrets.token_urlsafe(24)

def hash_verification_token(token):
    token_bytes = token.encode("utf-8") # Convert text into bytes for the hashing function
    return hashlib.sha256(token_bytes).hexdigest() # Hash the token using SHA-256 and return the hexadecimal representation of the hash.

def verification_token_matches(expected_hash, token): # Check if the provided token mathches the expected hash.
    actual_hash = hash_verification_token(token)
    return hmac.compare_digest(expected_hash, actual_hash)

def signed_message(email, payload, nonce):
    # Makes a signed message to verify the request 
    message = {
        "email": email,
        "nonce": nonce,
        "payload": payload,
    }
    return json.dumps(
        message,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

def verify_request_signature(public_key_text, email, payload, nonce, signature_text):
    # Verifies the request signature using the provided public key, email, payload, nonce, and signature. 
    public_key_bytes = decode_base64(
        public_key_text,
        "publicKey",
        max_bytes=32,
    )
    signature_bytes = decode_base64(
        signature_text,
        "signature",
        max_bytes=64,
    )

    if len(signature_bytes) != 64: # Check if the signature is exactly 64 bytes long, as required for Ed25519 signatures.
        raise bad_request(
            "INVALID_SIGNATURE",
            "signature must contain exactly 64 bytes",
        )

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        public_key.verify(
            signature_bytes,
            signed_message(email, payload, nonce),
        )
    except InvalidSignature:  # If the signature verification fails, raise an ApiError indicating that the request signature is invalid.
        raise ApiError(401, "INVALID_SIGNATURE", "request signature is invalid")
