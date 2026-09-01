import base64
import unittest

from secure_vault.errors import ApiError
from secure_vault.protocol import (
    decode_base64,
    normalise_email,
    require_canonical_email,
    validate_nonce,
)


class ProtocolTests(unittest.TestCase):
    # Test the protocol functions for email normalisation, canonical email requirement, base64 decoding, and nonce validation
    def test_normalises_email(self): # Test that normalise_email function correctly normalises email addresses by stripping whitespace and converting to lowercase
        self.assertEqual(normalise_email("  Person@Example.COM "), "person@example.com")

    def test_requires_canonical_email(self):
        # Test that require_canonical_email function raises an ApiError when the email is not in canonical form
        with self.assertRaises(ApiError) as context:
            require_canonical_email("Person@Example.com")

        self.assertEqual(context.exception.code, "EMAIL_NOT_CANONICAL")

    def test_decodes_canonical_base64(self):
        # Test that decode_base64 function correctly decodes a valid base64-encoded string
        encoded = base64.b64encode(b"vault data").decode("ascii")
        self.assertEqual(decode_base64(encoded, "value"), b"vault data")

    def test_rejects_invalid_base64(self):
        # Test that decode_base64 function raises an ApiError when the input is not valid base64
        with self.assertRaises(ApiError) as context:
            decode_base64("not base64", "value")

        self.assertEqual(context.exception.code, "INVALID_BASE64")

    def test_validates_nonce(self):
        # Test that validate_nonce function correctly validates a valid nonce and raises an ApiError for invalid nonces
        self.assertEqual(validate_nonce(1), 1)

        for invalid_nonce in (True, 0, -1, 1.5, "1"):
            with self.subTest(invalid_nonce=invalid_nonce):
                with self.assertRaises(ApiError):
                    validate_nonce(invalid_nonce)


if __name__ == "__main__":
    unittest.main()
