import base64
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
import json
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path

from secure_vault.client.api import VaultApiClient, VaultApiError
from secure_vault.client.crypto import (
    decrypt_vault,
    derive_keys,
    encrypt_vault,
    public_key_text,
)
from secure_vault.client.demo import run_demo, run_recovery
from secure_vault.server import VaultRequestHandler, create_server
from secure_vault.service import VaultService
from secure_vault.storage import JsonStore


class QuietVaultRequestHandler(VaultRequestHandler):
    # Override to suppress logging during tests
    def log_message(self, format, *args):
        return


class IntegrationTests(unittest.TestCase):
    # Override setUp and tearDown to create a temporary server and storage for each test
    def setUp(self):
        # Create a temporary directory for the JSON store
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.storage_path = Path(self.temporary_directory.name) / "vault.json"
        store = JsonStore(self.storage_path).initialise()
        QuietVaultRequestHandler.service = VaultService(store)
        self.server = HTTPServer(("127.0.0.1", 0), QuietVaultRequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        host, port = self.server.server_address 
        self.base_url = f"http://{host}:{port}"
        self.email = "integration@example.com"
        self.private_key, self.encryption_key = derive_keys(
            "integration master password",
            self.email,
        )
        self.client = VaultApiClient(self.base_url, self.email, self.private_key)

    def tearDown(self):
        # Stop the server and clean up the temporary directory
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.temporary_directory.cleanup()

    def restart_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.server = create_server(
            "127.0.0.1",
            0,
            self.storage_path,
            QuietVaultRequestHandler,
        )
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def register_and_verify(self):
        # Register the account and verify the email
        registration = self.client.register(public_key_text(self.private_key))
        self.assertEqual(registration["status"], "verification_required")
        verification = self.client.verify_email(registration["verificationToken"])
        self.assertEqual(verification, {"status": "verified"})

    def test_complete_workflow_and_persistence(self):
        # Test the complete workflow of registering, verifying, storing, and retrieving the vault, and check persistence
        self.register_and_verify()
        original_vault = {
            "entries": [
                {
                    "name": "Bank",
                    "username": "vault-user",
                    "password": "private-password",
                }
            ]
        }
        encrypted_vault = encrypt_vault(original_vault, self.encryption_key)

        self.assertEqual(self.client.store_vault(encrypted_vault), {"status": "stored"})
        retrieved_vault = self.client.retrieve_vault()
        self.assertEqual(
            decrypt_vault(retrieved_vault, self.encryption_key),
            original_vault,
        )

        restarted_store = JsonStore(self.storage_path).initialise()
        stored_account = restarted_store.read_account(self.email)
        self.assertEqual(stored_account["vault"], encrypted_vault)
        self.assertNotIn("private-password", self.storage_path.read_text("utf-8"))

    def test_unverified_account_cannot_store(self):
        # Test that an unverified account cannot store a vault
        self.client.register(public_key_text(self.private_key))
        encrypted_vault = encrypt_vault({"entries": []}, self.encryption_key)

        with self.assertRaises(VaultApiError) as context: # Attempt to store the vault without verifying the account and expect an error
            self.client.store_vault(encrypted_vault)

        self.assertEqual(context.exception.status, 403)
        self.assertEqual(context.exception.code, "ACCOUNT_NOT_VERIFIED")

    def test_replayed_request_is_rejected(self):
        # Test that a replayed request is rejected by the server
        self.register_and_verify()
        encrypted_vault = encrypt_vault({"entries": []}, self.encryption_key)
        envelope = self.client.authenticated_envelope(
            {"type": "store", "vault": encrypted_vault}
        )
        self.client._post("/v1/store", envelope)

        with self.assertRaises(VaultApiError) as context:
            self.client._post("/v1/store", envelope)

        self.assertEqual(context.exception.status, 409)
        self.assertEqual(context.exception.code, "NONCE_REPLAYED")

    def test_altered_request_is_rejected(self):
        # Test that an altered request is rejected by the server
        self.register_and_verify() 
        encrypted_vault = encrypt_vault({"entries": []}, self.encryption_key)
        envelope = self.client.authenticated_envelope( # Create a valid envelope first
            {"type": "store", "vault": encrypted_vault}
        )
        altered_payload = json.dumps( # Alter the payload to simulate tampering
            {"type": "store", "vault": encrypt_vault({"changed": True}, self.encryption_key)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        envelope["payload"] = base64.b64encode(altered_payload).decode("ascii")

        with self.assertRaises(VaultApiError) as context: # Send the altered envelope and expect an error 
            self.client._post("/v1/store", envelope)

        self.assertEqual(context.exception.status, 401)
        self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

    def test_sample_client_completes_the_workflow(self):
        # Test that the sample client completes the workflow successfully
        result = run_demo(
            self.base_url,
            "demonstration@example.com",
            "demonstration master password",
        )

        self.assertTrue(result["registered"])
        self.assertTrue(result["verified"])
        self.assertTrue(result["stored"])
        self.assertTrue(result["retrieved"])
        self.assertTrue(result["matched"])

    def test_recovery_with_fresh_client_after_server_restart(self):
        self.register_and_verify()
        original_vault = {"entries": [{"name": "Recovered", "password": "kept-secret"}]}
        encrypted_vault = encrypt_vault(original_vault, self.encryption_key)
        self.client.store_vault(encrypted_vault)
        self.restart_server()

        result = run_recovery(
            self.base_url,
            self.email,
            "integration master password",
        )

        self.assertTrue(result["retrieved"])
        self.assertEqual(result["vault"], original_vault)

    def test_failed_authenticated_request_consumes_nonce(self):
        self.register_and_verify()
        envelope = self.client.authenticated_envelope({"type": "retrieve"})

        with self.assertRaises(VaultApiError) as first_error:
            self.client._post("/v1/retrieve", envelope)

        self.assertEqual(first_error.exception.code, "VAULT_NOT_FOUND")

        with self.assertRaises(VaultApiError) as replay_error:
            self.client._post("/v1/retrieve", envelope)

        self.assertEqual(replay_error.exception.code, "NONCE_REPLAYED")

    def test_unverified_account_cannot_retrieve(self):
        self.client.register(public_key_text(self.private_key))

        with self.assertRaises(VaultApiError) as context:
            self.client.retrieve_vault()

        self.assertEqual(context.exception.status, 403)
        self.assertEqual(context.exception.code, "ACCOUNT_NOT_VERIFIED")

    def test_wrong_and_reused_verification_tokens_are_rejected(self):
        registration = self.client.register(public_key_text(self.private_key))

        with self.assertRaises(VaultApiError) as wrong_token:
            self.client.verify_email("wrong-token")

        self.assertEqual(wrong_token.exception.code, "INVALID_VERIFICATION_TOKEN")
        self.client.verify_email(registration["verificationToken"])

        with self.assertRaises(VaultApiError) as reused_token:
            self.client.verify_email(registration["verificationToken"])

        self.assertEqual(reused_token.exception.code, "ACCOUNT_ALREADY_VERIFIED")

    def test_expired_verification_token_is_rejected(self):
        registration = self.client.register(public_key_text(self.private_key))

        def expire_token(state):
            account = state["accounts"][self.email]
            account["verificationExpiresAt"] = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat()

        QuietVaultRequestHandler.service.store.transact(expire_token)

        with self.assertRaises(VaultApiError) as context:
            self.client.verify_email(registration["verificationToken"])

        self.assertEqual(context.exception.status, 410)
        self.assertEqual(context.exception.code, "VERIFICATION_EXPIRED")

    def test_duplicate_registration_is_rejected(self):
        self.client.register(public_key_text(self.private_key))

        with self.assertRaises(VaultApiError) as context:
            self.client.register(public_key_text(self.private_key))

        self.assertEqual(context.exception.status, 409)
        self.assertEqual(context.exception.code, "ACCOUNT_EXISTS")

    def test_altered_nonce_is_rejected(self):
        self.register_and_verify()
        encrypted_vault = encrypt_vault({"entries": []}, self.encryption_key)
        envelope = self.client.authenticated_envelope(
            {"type": "store", "vault": encrypted_vault}
        )
        envelope["nonce"] += 1

        with self.assertRaises(VaultApiError) as context:
            self.client._post("/v1/store", envelope)

        self.assertEqual(context.exception.status, 401)
        self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

    def test_signature_from_another_private_key_is_rejected(self):
        self.register_and_verify()
        other_private_key, _ = derive_keys("different master password", self.email)
        other_client = VaultApiClient(self.base_url, self.email, other_private_key)
        encrypted_vault = encrypt_vault({"entries": []}, self.encryption_key)

        with self.assertRaises(VaultApiError) as context:
            other_client.store_vault(encrypted_vault)

        self.assertEqual(context.exception.status, 401)
        self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

    def send_headers_only_request(self, headers):
        host, port = self.server.server_address
        connection = HTTPConnection(host, port, timeout=5)
        connection.putrequest("POST", "/v1/register")

        for name, value in headers:
            connection.putheader(name, value)

        connection.endheaders()
        response = connection.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, body

    def test_negative_content_length_is_rejected(self):
        status, body = self.send_headers_only_request(
            [("Content-Type", "application/json"), ("Content-Length", "-1")]
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "INVALID_CONTENT_LENGTH")

    def test_missing_content_length_is_rejected(self):
        status, body = self.send_headers_only_request(
            [("Content-Type", "application/json")]
        )
        self.assertEqual(status, 411)
        self.assertEqual(body["error"]["code"], "LENGTH_REQUIRED")

    def test_oversized_content_length_is_rejected(self):
        status, body = self.send_headers_only_request(
            [("Content-Type", "application/json"), ("Content-Length", str(257 * 1024))]
        )
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "REQUEST_TOO_LARGE")

    def test_unsupported_content_type_is_rejected(self):
        status, body = self.send_headers_only_request(
            [("Content-Type", "text/plain"), ("Content-Length", "0")]
        )
        self.assertEqual(status, 415)
        self.assertEqual(body["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")


# Run the tests if this file is executed directly
if __name__ == "__main__":
    unittest.main()
