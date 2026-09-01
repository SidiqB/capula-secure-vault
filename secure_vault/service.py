from datetime import datetime, timedelta, timezone

from .authentication import (
    create_verification_token,
    hash_verification_token,
    validate_public_key,
    verification_token_matches,
    verify_request_signature,
)
from .errors import ApiError
from .protocol import (
    decode_payload,
    require_canonical_email,
    require_exact_keys,
    require_non_empty_text,
    validate_nonce,
    validate_vault,
)



VERIFICATION_TOKEN_LIFETIME = timedelta(minutes=15)

def utc_now():
    return datetime.now(timezone.utc)

# This class makes the blueprint for our main serivce object
class VaultService:
    def __init__(self, store):
        self.store = store  # Keep the store instance for later use
    
    def register(self, body): # Validating the registration request body and extracting the email and public key from it.
        require_exact_keys(
            body,
            {"email", "publicKey"},
            "registration request",
        )

        email = require_canonical_email(body["email"])
        public_key = validate_public_key(body["publicKey"])
        token = create_verification_token()
        now = utc_now()
        expires_at = now + VERIFICATION_TOKEN_LIFETIME

        def save_account(state):
            # Safely modify the state of the store to add a new account. If an account with the same email already exists, raise an error.
            accounts = state["accounts"]

            if email in accounts:
                raise ApiError(
                    409,
                    "ACCOUNT_EXISTS",
                    "an account already exists for this email",
                )
            
            accounts[email] = {  # Create a new account entry in the store with the provided email, public key, and other relevant information.
                "email": email,
                "publicKey": public_key,
                "verified": False,
                "verificationTokenHash": hash_verification_token(token),
                "verificationExpiresAt": expires_at.isoformat(),
                "lastNonce": 0,
                "vault": None,
                "createdAt": now.isoformat(),
                "updatedAt": now.isoformat(),
            }

        self.store.transact(save_account) # Persist the new account to the store

        return 201, { # Return a response indicating that the account was created successfully, along with the verification token and its expiration time.
            "status": "verification_required",
            "verificationToken": token,
            "expiresAt": expires_at.isoformat(),
        }

    def verify_email(self, body):
        require_exact_keys(
            body,
            {"email", "verificationToken"},
            "verification request",
        )
        email = require_canonical_email(body["email"])
        token = require_non_empty_text(
            body["verificationToken"],
            "verificationToken",
        )
        now = utc_now()

        def verify_account(state):
            account = state["accounts"].get(email)

            if account is None:
                raise ApiError(404, "ACCOUNT_NOT_FOUND", "account was not found")

            if account["verified"]:
                raise ApiError(409, "ACCOUNT_ALREADY_VERIFIED", "account is already verified")

            expires_at = datetime.fromisoformat(account["verificationExpiresAt"])

            if now > expires_at:
                raise ApiError(410, "VERIFICATION_EXPIRED", "verification token has expired")

            if not verification_token_matches(account["verificationTokenHash"], token):
                raise ApiError(401, "INVALID_VERIFICATION_TOKEN", "verification token is invalid")

            account["verified"] = True
            account["verificationTokenHash"] = None
            account["verificationExpiresAt"] = None
            account["updatedAt"] = now.isoformat()

        self.store.transact(verify_account)
        return 200, {"status": "verified"}

    def store_vault(self, body):
        email, payload_text, nonce = self._authenticate(body)

        def save_vault(account):
            payload = decode_payload(payload_text)
            require_exact_keys(payload, {"type", "vault"}, "store payload")

            if payload["type"] != "store":
                raise ApiError(400, "INVALID_OPERATION", "payload type must be store")

            account["vault"] = validate_vault(payload["vault"])
            return 200, {"status": "stored"}

        return self._consume_nonce(email, nonce, save_vault)

    def retrieve_vault(self, body):
        email, payload_text, nonce = self._authenticate(body)

        def retrieve(account):
            payload = decode_payload(payload_text)
            require_exact_keys(payload, {"type"}, "retrieve payload")

            if payload["type"] != "retrieve":
                raise ApiError(400, "INVALID_OPERATION", "payload type must be retrieve")

            if account["vault"] is None:
                raise ApiError(404, "VAULT_NOT_FOUND", "no vault has been stored")

            return 200, {"vault": account["vault"]}

        return self._consume_nonce(email, nonce, retrieve)

    def _authenticate(self, body):
        require_exact_keys(
            body,
            {"email", "payload", "nonce", "signature"},
            "authenticated request",
        )
        email = require_canonical_email(body["email"])
        payload_text = body["payload"]
        nonce = validate_nonce(body["nonce"])
        account = self.store.read_account(email)

        if account is None:
            raise ApiError(404, "ACCOUNT_NOT_FOUND", "account was not found")

        if not account["verified"]:
            raise ApiError(403, "ACCOUNT_NOT_VERIFIED", "account is not verified")

        verify_request_signature(
            account["publicKey"],
            email,
            payload_text,
            nonce,
            body["signature"],
        )
        return email, payload_text, nonce

    def _consume_nonce(self, email, nonce, operation):
        now = utc_now()

        def change_account(state):
            account = state["accounts"].get(email)

            if account is None:
                raise ApiError(404, "ACCOUNT_NOT_FOUND", "account was not found")

            if nonce <= account["lastNonce"]:
                raise ApiError(409, "NONCE_REPLAYED", "nonce has already been used")

            try:
                result = operation(account)
                error = None
            except ApiError as operation_error:
                result = None
                error = operation_error

            account["lastNonce"] = nonce
            account["updatedAt"] = now.isoformat()
            return result, error

        result, error = self.store.transact(change_account)

        if error is not None:
            raise error

        return result
