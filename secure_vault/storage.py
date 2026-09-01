import copy
import json
import os
from pathlib import Path
import tempfile
import threading


ACCOUNT_FIELDS = {
    "email",
    "publicKey",
    "verified",
    "verificationTokenHash",
    "verificationExpiresAt",
    "lastNonce",
    "vault",
    "createdAt",
    "updatedAt",
}


class JsonStore:
    def __init__(self, file_path):
        self.file_path = Path(file_path).resolve() # Stores the absolute path of the file where the data will be stored
        self._lock = threading.RLock() # Stops multiple threads from accessing the data at the same time
        self._state = {
            "version": 1,
            "accounts": {},
        }
    
    def initialise(self):
        # Prepares the strorage when the server starts 
        self.file_path.parent.mkdir(parents=True, exist_ok=True) # Creates the folder containing the database file

        try:
            with self.file_path.open("r", encoding="utf-8") as file: # Open the exisiting database file
                stored_state = json.load(file)
        except FileNotFoundError:
            return self

        self._validate_state(stored_state) # Checking that the data in the file is valid
        self._state = stored_state
        return self
    
    def _validate_state(self, state):
        # This checks that the stored JSON file has the structure our program expects. 
        if not isinstance(state, dict):
            raise ValueError("storage file must contain a JSON object")

        if state.get("version") != 1: 
            raise ValueError("storage file has an unsupported version")

        if not isinstance(state.get("accounts"), dict):
            raise ValueError("storage file must contain an accounts object")

        for email, account in state["accounts"].items():
            self._validate_account(email, account)

    def _validate_account(self, email, account):
        if not isinstance(email, str) or not isinstance(account, dict):
            raise ValueError("storage file contains an invalid account")

        if set(account.keys()) != ACCOUNT_FIELDS or account["email"] != email:
            raise ValueError("storage file contains an invalid account structure")

        if not isinstance(account["publicKey"], str) or account["publicKey"] == "":
            raise ValueError("storage file contains an invalid public key")

        if not isinstance(account["verified"], bool):
            raise ValueError("storage file contains an invalid verification state")

        if isinstance(account["lastNonce"], bool) or not isinstance(account["lastNonce"], int):
            raise ValueError("storage file contains an invalid nonce")

        if account["lastNonce"] < 0:
            raise ValueError("storage file contains an invalid nonce")

        if account["vault"] is not None and not isinstance(account["vault"], str):
            raise ValueError("storage file contains an invalid vault")

        if not isinstance(account["createdAt"], str) or not isinstance(account["updatedAt"], str):
            raise ValueError("storage file contains invalid timestamps")

        if account["verified"]:
            if account["verificationTokenHash"] is not None:
                raise ValueError("verified account contains a verification token")
            if account["verificationExpiresAt"] is not None:
                raise ValueError("verified account contains a verification expiry")
        else:
            if not isinstance(account["verificationTokenHash"], str):
                raise ValueError("unverified account has no verification token")
            if not isinstance(account["verificationExpiresAt"], str):
                raise ValueError("unverified account has no verification expiry")
    
    def read_account(self, email):
        # Method retrieves an account from the email given
        with self._lock:
            account = self._state["accounts"].get(email)

            if account is None:
                return None

            return copy.deepcopy(account) # Returns a copy of the account data to prevent external modifications to the internal state.
    
    def transact(self, change): 
        # Let us safely change the infomation that we have stored
        with self._lock:
            next_state = copy.deepcopy(self._state)
            result = change(next_state)

            self._persist(next_state)
            self._state = next_state

            return result
    
    def _persist(self, state):
        # Put the current state in a temp file and then rename it to the actual file, this is to prevent data loss if the server crashes while writing
        descriptor, temporary_path = tempfile.mkstemp(
            dir=self.file_path.parent,
            prefix=f".{self.file_path.name}.",
            suffix=".tmp",
        )

        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                json.dump(state, file, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.file_path)

        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

            raise
