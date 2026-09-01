import base64
import binascii
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..protocol import normalise_email


VAULT_VERSION = 1
VAULT_AAD = b"capula-secure-vault-v1"


def derive_keys(master_password, email):
    if not isinstance(master_password, str) or master_password == "":
        raise ValueError("master password must be non-empty text")

    normalised_email = normalise_email(email)
    salt = hashlib.sha256(
        b"capula-secure-vault-key-derivation-v1:" + normalised_email.encode("utf-8")
    ).digest()
    key_derivation = Scrypt(
        salt=salt,
        length=64,
        n=2 ** 14,
        r=8,
        p=1,
    )
    material = key_derivation.derive(master_password.encode("utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(material[:32])
    encryption_key = material[32:]
    return private_key, encryption_key


def public_key_text(private_key):
    public_key_bytes = private_key.public_key().public_bytes_raw()
    return base64.b64encode(public_key_bytes).decode("ascii")


def encrypt_vault(vault, encryption_key):
    if not isinstance(vault, dict):
        raise ValueError("vault must be a dictionary")

    plaintext = json.dumps(
        vault,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, VAULT_AAD)
    encoded_vault = bytes([VAULT_VERSION]) + nonce + ciphertext
    return base64.b64encode(encoded_vault).decode("ascii")


def decrypt_vault(encrypted_vault, encryption_key):
    try:
        encoded_vault = base64.b64decode(encrypted_vault, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("encrypted vault must be valid Base64")

    if len(encoded_vault) < 30 or encoded_vault[0] != VAULT_VERSION:
        raise ValueError("encrypted vault has an invalid format")

    nonce = encoded_vault[1:13]
    ciphertext = encoded_vault[13:]

    try:
        plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, VAULT_AAD)
        vault = json.loads(plaintext.decode("utf-8"))
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("encrypted vault could not be decrypted")

    if not isinstance(vault, dict):
        raise ValueError("decrypted vault must contain a JSON object")

    return vault
