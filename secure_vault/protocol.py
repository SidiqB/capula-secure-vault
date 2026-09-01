import re # This is used for regular expression operations, which are useful for validating email formats.
import base64
import binascii
import json
from .errors import bad_request


EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MAX_NONCE = (2 ** 63) - 1
MAX_PAYLOAD_BYTES = 192 * 1024
MAX_VAULT_BYTES = 128 * 1024

def normalise_email(value):
    # This function takes an email address as input, checks if it's valid, and returns a normalised version of it (lowercase and stripped of whitespace).
    if not isinstance(value, str):
        raise bad_request("INVALID_EMAIL", "email must be text")

    normalised = value.strip().lower()

    if len(normalised) > 254 or EMAIL_PATTERN.fullmatch(normalised) is None:
        raise bad_request("INVALID_EMAIL", "email is not valid")

    return normalised

def require_canonical_email(value):
    # Make sure the email is in its canonical form (trimmed and lowercase). If not, raise an error.
    normalised = normalise_email(value)

    if value != normalised:
        raise bad_request(
            "EMAIL_NOT_CANONICAL",
            "email must be trimmed and lowercase",
        )

    return normalised

def require_exact_keys(value, expected, name):
    # This function checks if a given dictionary (value) has exactly the keys specified in the expected set. If not, it raises an error.
    if not isinstance(value, dict):
        raise bad_request("INVALID_REQUEST", f"{name} must be a JSON object")

    if set(value.keys()) != expected:
        fields = ", ".join(sorted(expected))
        raise bad_request(
            "UNEXPECTED_FIELDS",
            f"{name} must contain exactly: {fields}",
        )

def decode_base64(value, field, allow_empty=False, max_bytes=None):
    # We decode a Base64 encoded string and perform several checks to ensure it's valid. If any check fails, we raise an error.
    if not isinstance(value, str):
        raise bad_request("INVALID_BASE64", f"{field} must be Base64 text")

    if not allow_empty and value == "": 
        raise bad_request("INVALID_BASE64", f"{field} cannot be empty") # Reject empty strings if not allowed

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise bad_request("INVALID_BASE64", f"{field} must be valid Base64")

    canonical = base64.b64encode(decoded).decode("ascii")

    if canonical != value:
        raise bad_request("INVALID_BASE64", f"{field} must use canonical Base64")

    if max_bytes is not None and len(decoded) > max_bytes:
        raise bad_request("VALUE_TOO_LARGE", f"{field} is too large")

    return decoded

def require_non_empty_text(value, field, max_length=256):
    # Check if its not empty and does not exceed the max length
    if not isinstance(value, str) or value == "":
        raise bad_request("INVALID_FIELD", f"{field} must be non-empty text")

    if len(value) > max_length:
        raise bad_request("VALUE_TOO_LARGE", f"{field} is too large")

    return value

def validate_nonce(value):
    # Check if the nonce is a valid integer within the allowed range
    if isinstance(value, bool) or not isinstance(value, int):
        raise bad_request("INVALID_NONCE", "nonce must be an integer")

    if value < 1 or value > MAX_NONCE: # Raise an error if not
        raise bad_request("INVALID_NONCE", "nonce is outside the allowed range")

    return value

def decode_payload(value):
    # We decode the Base64 encoded payload and ensure that it is valid JSON
    raw_payload = decode_base64(value, "payload", max_bytes=MAX_PAYLOAD_BYTES)

    try:
        payload = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise bad_request("INVALID_PAYLOAD", "payload must contain valid UTF-8 JSON")

    if not isinstance(payload, dict):
        raise bad_request("INVALID_PAYLOAD", "payload must contain a JSON object")

    return payload

def validate_vault(value):
    # We decode the Base64 encoded vault and ensure that it does not exceed the maximum allowed size
    decode_base64(value, "vault", max_bytes=MAX_VAULT_BYTES)
    return value
