import json
from pathlib import Path
import tempfile
import unittest

from secure_vault.storage import JsonStore


class StorageTests(unittest.TestCase):
    def test_rejects_invalid_top_level_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            path.write_text(json.dumps({"version": 1, "accounts": []}), "utf-8")

            with self.assertRaises(ValueError):
                JsonStore(path).initialise()

    def test_rejects_invalid_nested_account(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "accounts": {
                            "person@example.com": {
                                "email": "person@example.com",
                                "verified": True,
                            }
                        },
                    }
                ),
                "utf-8",
            )

            with self.assertRaises(ValueError):
                JsonStore(path).initialise()

    def test_transaction_persists_atomically_readable_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            store = JsonStore(path).initialise()

            def change(state):
                state["version"] = 1

            store.transact(change)
            reloaded = JsonStore(path).initialise()
            self.assertIsNone(reloaded.read_account("missing@example.com"))


if __name__ == "__main__":
    unittest.main()
