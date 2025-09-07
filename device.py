# device.py
import time
import random
import json
from typing import Dict

class IoTDevice:
    """
    A lightweight simulated IoT device.
    """

    def __init__(self, device_id: str, device_type: str, seed: int = None):
        self.device_id = device_id
        self.device_type = device_type
        self.rng = random.Random(seed)

    def generate_event(self) -> Dict:
        """
        Produce one event dictionary.
        """
        # Example event types and payloads; extend as needed
        event_types = {
            "cctv": ["motion_detected", "access_attempt", "frame_snapshot"],
            "traffic": ["vehicle_count", "speed_sample", "congestion_alert"],
            "pollution": ["pm2_5_reading", "co_reading", "sensor_error"]
        }

        types = event_types.get(self.device_type, ["status"])
        ev_type = self.rng.choice(types)

        # Generate synthetic payload
        payload = {}
        if self.device_type == "cctv":
            payload = {
                "camera_id": self.device_id,
                "confidence": round(self.rng.uniform(0.5, 0.99), 3),
                "frame_hash": f"frame_{self.rng.randint(0,99999)}"
            }
        elif self.device_type == "traffic":
            payload = {
                "lane": self.rng.randint(1, 4),
                "vehicle_count": self.rng.randint(0, 50),
                "avg_speed_kmh": round(self.rng.uniform(10, 120), 2)
            }
        elif self.device_type == "pollution":
            payload = {
                "pm2_5": round(self.rng.uniform(0, 300), 2),
                "co": round(self.rng.uniform(0, 50), 2)
            }
        else:
            payload = {"status": "ok"}

        event = {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "event_type": ev_type,
            "event_payload": payload,
            "event_ts": time.time()
        }
        return event
