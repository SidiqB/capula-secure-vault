import base64
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..authentication import signed_message
from ..protocol import MAX_NONCE, normalise_email


class VaultApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class VaultApiClient:
    def __init__(self, base_url, email, private_key, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.email = normalise_email(email)
        self.private_key = private_key
        self.timeout = timeout
        self._last_nonce = min(time.time_ns(), MAX_NONCE - 1)

    def register(self, public_key):
        return self._post(
            "/v1/register",
            {
                "email": self.email,
                "publicKey": public_key,
            },
        )

    def verify_email(self, verification_token):
        return self._post(
            "/v1/verify-email",
            {
                "email": self.email,
                "verificationToken": verification_token,
            },
        )

    def store_vault(self, encrypted_vault):
        envelope = self.authenticated_envelope(
            {
                "type": "store",
                "vault": encrypted_vault,
            }
        )
        return self._post("/v1/store", envelope)

    def retrieve_vault(self):
        envelope = self.authenticated_envelope({"type": "retrieve"})
        return self._post("/v1/retrieve", envelope)["vault"]

    def authenticated_envelope(self, payload, nonce=None):
        payload_bytes = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload_text = base64.b64encode(payload_bytes).decode("ascii")

        if nonce is None:
            nonce = self._next_nonce()

        signature = self.private_key.sign(
            signed_message(self.email, payload_text, nonce)
        )
        return {
            "email": self.email,
            "payload": payload_text,
            "nonce": nonce,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def _next_nonce(self):
        current_time = min(time.time_ns(), MAX_NONCE)
        self._last_nonce = max(self._last_nonce + 1, current_time)

        if self._last_nonce > MAX_NONCE:
            raise RuntimeError("nonce limit has been reached")

        return self._last_nonce

    def _post(self, path, body):
        request = Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                return self._read_response(response.read())
        except HTTPError as error:
            self._raise_api_error(error.code, error.read())
        except URLError as error:
            raise ConnectionError(f"could not connect to vault service: {error.reason}")

    def _read_response(self, raw_body):
        try:
            response = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("vault service returned an invalid JSON response")

        if not isinstance(response, dict):
            raise RuntimeError("vault service returned an invalid response")

        return response

    def _raise_api_error(self, status, raw_body):
        try:
            response = self._read_response(raw_body)
            error = response["error"]
            code = error["code"]
            message = error["message"]
        except (KeyError, TypeError, RuntimeError):
            code = "HTTP_ERROR"
            message = f"vault service returned HTTP {status}"

        raise VaultApiError(status, code, message)
