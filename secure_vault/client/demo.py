import argparse
import getpass
import json

from .api import VaultApiClient
from .crypto import decrypt_vault, derive_keys, encrypt_vault, public_key_text


def run_demo(base_url, email, master_password):
    private_key, encryption_key = derive_keys(master_password, email)
    client = VaultApiClient(base_url, email, private_key)
    registration = client.register(public_key_text(private_key))
    client.verify_email(registration["verificationToken"])

    original_vault = {
        "entries": [
            {
                "name": "Example account",
                "username": "demo-user",
                "password": "correct-horse-battery-staple",
            }
        ]
    }
    encrypted_vault = encrypt_vault(original_vault, encryption_key)
    client.store_vault(encrypted_vault)
    retrieved_vault = client.retrieve_vault()
    decrypted_vault = decrypt_vault(retrieved_vault, encryption_key)

    if decrypted_vault != original_vault:
        raise RuntimeError("retrieved vault does not match the original vault")

    return {
        "email": client.email,
        "registered": True,
        "verified": True,
        "stored": True,
        "retrieved": True,
        "matched": True,
    }


def run_recovery(base_url, email, master_password):
    private_key, encryption_key = derive_keys(master_password, email)
    client = VaultApiClient(base_url, email, private_key)
    encrypted_vault = client.retrieve_vault()
    vault = decrypt_vault(encrypted_vault, encryption_key)
    return {
        "email": client.email,
        "retrieved": True,
        "vault": vault,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("demo", "recover"), nargs="?", default="demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--email", required=True)
    arguments = parser.parse_args()
    master_password = getpass.getpass("Master password: ")

    if arguments.command == "demo":
        result = run_demo(arguments.base_url, arguments.email, master_password)
    else:
        result = run_recovery(arguments.base_url, arguments.email, master_password)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
