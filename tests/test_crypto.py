import base64
import unittest

from secure_vault.client.crypto import (
    decrypt_vault,
    derive_keys,
    encrypt_vault,
    public_key_text,
)


class CryptoTests(unittest.TestCase):
    # Test that the key derivation function is repeatable and produces the same keys for the same inputs
    def test_key_derivation_is_repeatable(self):
        # Derive keys twice with the same password and email
        first_private_key, first_encryption_key = derive_keys(
            "a strong master password",
            "person@example.com",
        )
        second_private_key, second_encryption_key = derive_keys(
            "a strong master password",
            "person@example.com",
        )

        self.assertEqual( 
            public_key_text(first_private_key),
            public_key_text(second_private_key),
        )
        self.assertEqual(first_encryption_key, second_encryption_key)

    def test_encryption_round_trip(self):
        # Derive keys and encrypt a sample vault, then decrypt it and check that the original vault is recovered
        _, encryption_key = derive_keys("master password", "person@example.com")
        vault = {
            "entries": [
                {
                    "name": "Email",
                    "username": "person@example.com",
                    "password": "secret",
                }
            ]
        }
        encrypted_vault = encrypt_vault(vault, encryption_key)

        self.assertNotIn("secret", encrypted_vault)
        self.assertEqual(decrypt_vault(encrypted_vault, encryption_key), vault)

    def test_wrong_password_cannot_decrypt(self):
        # Derive keys for a correct and wrong password, encrypt a vault with the correct key, and assert that decrypting with the wrong key raises a ValueError
        _, correct_key = derive_keys("correct password", "person@example.com")
        _, wrong_key = derive_keys("wrong password", "person@example.com")
        encrypted_vault = encrypt_vault({"entries": []}, correct_key)

        with self.assertRaises(ValueError):
            decrypt_vault(encrypted_vault, wrong_key)

    def test_repeated_encryption_uses_different_nonces(self):
        _, encryption_key = derive_keys("master password", "person@example.com")
        vault = {"entries": []}
        first_encryption = encrypt_vault(vault, encryption_key)
        second_encryption = encrypt_vault(vault, encryption_key)

        self.assertNotEqual(first_encryption, second_encryption)
        self.assertEqual(decrypt_vault(first_encryption, encryption_key), vault)
        self.assertEqual(decrypt_vault(second_encryption, encryption_key), vault)

    def test_tampered_ciphertext_is_rejected(self):
        _, encryption_key = derive_keys("master password", "person@example.com")
        encrypted_vault = encrypt_vault({"entries": []}, encryption_key)
        tampered = bytearray(base64.b64decode(encrypted_vault))
        tampered[-1] ^= 1

        with self.assertRaises(ValueError):
            decrypt_vault(base64.b64encode(tampered).decode("ascii"), encryption_key)


if __name__ == "__main__":
    unittest.main()
