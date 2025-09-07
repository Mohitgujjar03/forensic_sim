# collector.py
import time
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional, Dict
from protocol import canonical_json, compute_sha256, make_forensic_metadata
from keymanager import KeyManager

class Collector:
    """
    Collector module: takes events, adds metadata, computes hash,
    encrypts payload and hands to storage.
    """

    def __init__(self, storage, key_manager: KeyManager, collector_id: str = "collector-01", enable_hash_chain: bool = False):
        self.storage = storage
        self.km = key_manager
        self.collector_id = collector_id
        self.enable_hash_chain = enable_hash_chain
        self.sequence = 0
        self.last_hash = None

    def collect_and_store(self, event: Dict) -> int:
        """
        Process a single event and store it. Returns the storage row id.
        """
        self.sequence += 1
        collector_ts = time.time()

        # compute canonical JSON of the event (payload)
        event_json = canonical_json(event)
        event_hash = compute_sha256(event_json)

        prev_hash = self.last_hash if self.enable_hash_chain else None

        # metadata
        metadata = make_forensic_metadata(event, self.collector_id, sequence_no=self.sequence, prev_hash=prev_hash)
        metadata["collector_ts"] = collector_ts

        # encrypt the event JSON using AES-GCM
        key_id, key = self.km.get_active_key()
        aesgcm = AESGCM(key)
        nonce = self.km.nonce_bytes()  # 12 bytes
        aad = self.collector_id.encode('utf-8')  # AAD binds to collector_id
        ciphertext = aesgcm.encrypt(nonce=nonce, data=event_json, associated_data=aad)

        # build storage-ready record
        record = {
            "device_id": event.get("device_id"),
            "device_type": event.get("device_type"),
            "event_type": event.get("event_type"),
            "event_hash": event_hash,
            "collector_ts": collector_ts,
            "sequence_no": self.sequence,
            "prev_hash": prev_hash,
            "encrypted_blob": ciphertext,   # binary bytes
            "nonce": nonce,
            "key_id": key_id,
            "metadata": metadata
        }

        # store and update last_hash
        row_id = self.storage.store_evidence(record)
        self.last_hash = event_hash
        return row_id
