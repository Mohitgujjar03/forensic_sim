# storage.py
import sqlite3
import base64
from typing import Dict, Optional, List
from keymanager import KeyManager
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "forensic.db"

class Storage:
    def __init__(self, db_path: str = DB_FILE, key_manager: Optional[KeyManager] = None):
        self.db_path = db_path
        self.km = key_manager
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                device_type TEXT,
                event_type TEXT,
                event_hash TEXT,
                collector_ts REAL,
                sequence_no INTEGER,
                prev_hash TEXT,
                encrypted_blob TEXT,
                nonce TEXT,
                key_id TEXT,
                collector_id TEXT,          -- NEW: store collector_id for AAD
                verified INTEGER DEFAULT 0,
                tampered INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def store_evidence(self, record: Dict) -> int:
        # encode bytes as base64 strings for storage
        enc_b64 = base64.b64encode(record["encrypted_blob"]).decode('utf-8')
        nonce_b64 = base64.b64encode(record["nonce"]).decode('utf-8')
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO evidence (
                device_id, device_type, event_type, event_hash,
                collector_ts, sequence_no, prev_hash, encrypted_blob, nonce, key_id, collector_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["device_id"], record["device_type"], record["event_type"], record["event_hash"],
            record["collector_ts"], record["sequence_no"], record["prev_hash"],
            enc_b64, nonce_b64, record["key_id"], record["metadata"]["collector_id"]
        ))
        rid = cur.lastrowid
        conn.commit()
        conn.close()
        return rid

    def list_all(self) -> List[Dict]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, device_id, device_type, event_type, event_hash, collector_ts, sequence_no, prev_hash, key_id, collector_id, verified, tampered FROM evidence")
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            res.append({
                "id": r[0], "device_id": r[1], "device_type": r[2],
                "event_type": r[3], "event_hash": r[4], "collector_ts": r[5],
                "sequence_no": r[6], "prev_hash": r[7], "key_id": r[8],
                "collector_id": r[9], "verified": r[10], "tampered": r[11]
            })
        return res

    def get_raw(self, record_id: int) -> Optional[Dict]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, device_id, device_type, event_type, event_hash, collector_ts, sequence_no, prev_hash, encrypted_blob, nonce, key_id, collector_id, verified, tampered FROM evidence WHERE id=?",(record_id,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return None
        return {
            "id": r[0], "device_id": r[1], "device_type": r[2], "event_type": r[3],
            "event_hash": r[4], "collector_ts": r[5], "sequence_no": r[6], "prev_hash": r[7],
            "encrypted_blob": r[8], "nonce": r[9], "key_id": r[10], "collector_id": r[11],
            "verified": r[12], "tampered": r[13]
        }

    def tamper_record(self, record_id: int, mode: str = "flip_encrypted"):
        """
        Simulate tampering: mode can be 'flip_encrypted' (change encrypted blob),
        or 'alter_hash' (change stored hash).
        """
        raw = self.get_raw(record_id)
        if not raw:
            return False
        conn = self._get_conn()
        cur = conn.cursor()
        if mode == "flip_encrypted":
            # decode, flip a byte, reencode
            b = bytearray(base64.b64decode(raw["encrypted_blob"].encode('utf-8')))
            if len(b) > 0:
                b[0] = (b[0] + 1) % 256
            new_enc = base64.b64encode(bytes(b)).decode('utf-8')
            cur.execute("UPDATE evidence SET encrypted_blob=?, verified=0, tampered=1 WHERE id=?", (new_enc, record_id))
        elif mode == "alter_hash":
            # change stored hash to random text
            cur.execute("UPDATE evidence SET event_hash='tampered-hash', verified=0, tampered=1 WHERE id=?", (record_id,))
        else:
            conn.close()
            return False
        conn.commit()
        conn.close()
        return True

    def verify_record(self, record_id: int, key_manager: KeyManager) -> Dict:
        """
        Try to decrypt and validate the payload hash. Returns verification result.
        """
        raw = self.get_raw(record_id)
        if not raw:
            return {"id": record_id, "ok": False, "reason": "not_found"}

        try:
            enc = base64.b64decode(raw["encrypted_blob"].encode('utf-8'))
            nonce = base64.b64decode(raw["nonce"].encode('utf-8'))
            key = key_manager.get_key(raw["key_id"])
            aesgcm = AESGCM(key)
            # Use stored collector_id as AAD
            aad = raw["collector_id"].encode('utf-8') if raw["collector_id"] else None
            plaintext = aesgcm.decrypt(nonce, enc, aad)
        except Exception as e:
            # decryption failed -> tampering or wrong key
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute("UPDATE evidence SET verified=0, tampered=1 WHERE id=?", (record_id,))
            conn.commit()
            conn.close()
            return {"id": record_id, "ok": False, "reason": "decryption_failed", "error": str(e)}

        # compute hash of plaintext and compare
        from protocol import compute_sha256
        computed_hash = compute_sha256(plaintext)
        ok = computed_hash == raw["event_hash"]
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE evidence SET verified=?, tampered=? WHERE id=?", (1 if ok else 0, 0 if ok else 1, record_id))
        conn.commit()
        conn.close()
        return {"id": record_id, "ok": ok, "computed_hash": computed_hash, "stored_hash": raw["event_hash"]}

    def verify_all(self, key_manager: KeyManager) -> Dict:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM evidence")
        rows = cur.fetchall()
        conn.close()
        total = 0
        ok_count = 0
        bad_count = 0
        details = []
        for r in rows:
            total += 1
            res = self.verify_record(r[0], key_manager)
            if res.get("ok"):
                ok_count += 1
            else:
                bad_count += 1
            details.append(res)
        return {"total": total, "ok": ok_count, "bad": bad_count, "details": details}
