# protocol.py
import json
import hashlib
from typing import Dict, Optional

def canonical_json(obj: Dict) -> bytes:
    """
    Return canonical JSON bytes (stable ordering) for hashing.
    """
    return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')

def compute_sha256(data_bytes: bytes) -> str:
    """
    Compute SHA-256 hex digest for given bytes.
    """
    return hashlib.sha256(data_bytes).hexdigest()

def make_forensic_metadata(event: Dict, collector_id: str,
                           sequence_no: Optional[int] = None,
                           prev_hash: Optional[str] = None) -> Dict:
    """
    Build the chain-of-custody metadata and basic record info (without encryption).
    """
    cond = {
        "device_id": event.get("device_id"),
        "device_type": event.get("device_type"),
        "event_type": event.get("event_type"),
        "event_ts": event.get("event_ts"),
        "collector_id": collector_id,
        "collector_ts": None,  # collector will fill
        "sequence_no": sequence_no,
        "prev_hash": prev_hash
    }
    return cond
