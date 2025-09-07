# keymanager.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict

class KeyManager:
    """
    Simple key manager for simulation. Stores keys in-memory.
    """

    def __init__(self):
        self.keys: Dict[str, bytes] = {}
        self.active_key_id: str = self._create_and_register_key()

    def _create_and_register_key(self) -> str:
        key = AESGCM.generate_key(bit_length=256)
        kid = f"key-{len(self.keys)+1}"
        self.keys[kid] = key
        return kid

    def get_key(self, key_id: str) -> bytes:
        return self.keys[key_id]

    def get_active_key(self):
        return self.active_key_id, self.keys[self.active_key_id]

    def rotate_key(self):
        new_kid = self._create_and_register_key()
        self.active_key_id = new_kid
        return new_kid

    @staticmethod
    def nonce_bytes():
        return os.urandom(12)

    @staticmethod
    def b64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def b64_decode(data_str: str) -> bytes:
        import base64
        return base64.b64decode(data_str.encode('utf-8'))
