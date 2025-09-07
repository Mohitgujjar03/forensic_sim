# evaluator.py
import time
import tracemalloc
import pandas as pd
import matplotlib.pyplot as plt
from device import IoTDevice
from collector import Collector
from storage import Storage
from keymanager import KeyManager
import random
import os

class Evaluator:
    def __init__(self, devices_count=10, events_per_device=5, enable_hash_chain=False, db_file="forensic.db"):
        self.devices_count = devices_count
        self.events_per_device = events_per_device
        self.enable_hash_chain = enable_hash_chain
        self.db_file = db_file

    def run_scenario(self):
        # Setup
        if os.path.exists(self.db_file):
            os.remove(self.db_file)  # start fresh
        km = KeyManager()
        storage = Storage(db_path=self.db_file, key_manager=km)
        collector = Collector(storage, km, collector_id="collector-01", enable_hash_chain=self.enable_hash_chain)

        # create devices
        devices = []
        for i in range(self.devices_count):
            dtype = random.choice(["cctv", "traffic", "pollution"])
            devices.append(IoTDevice(device_id=f"dev-{i+1:03d}", device_type=dtype, seed=i))

        # evaluation records
        timeline = []

        tracemalloc.start()
        start_time = time.perf_counter()

        # generate events
        event_counter = 0
        for d in devices:
            for _ in range(self.events_per_device):
                event = d.generate_event()
                t0 = time.perf_counter()
                row_id = collector.collect_and_store(event)
                t1 = time.perf_counter()
                event_counter += 1
                timeline.append({
                    "row_id": row_id,
                    "device_id": d.device_id,
                    "device_type": d.device_type,
                    "time_taken_s": t1 - t0,
                    "timestamp": time.time()
                })

        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        total_time = end_time - start_time
        avg_time_per_event = sum([x["time_taken_s"] for x in timeline]) / len(timeline)

        results = {
            "devices": self.devices_count,
            "events_per_device": self.events_per_device,
            "total_events": event_counter,
            "total_time_s": total_time,
            "avg_time_per_event_s": avg_time_per_event,
            "memory_current_bytes": current,
            "memory_peak_bytes": peak,
            "timeline": pd.DataFrame(timeline)
        }
        return {"results": results, "storage": storage, "key_manager": km}

    def simulate_tamper_and_verify(self, storage: Storage, key_manager: KeyManager, percent_to_tamper: float = 0.05):
        """
        Tamper with a percentage of records, then run verification.
        """
        all_rows = storage.list_all()
        total = len(all_rows)
        to_tamper_count = max(1, int(total * percent_to_tamper))
        chosen = random.sample(all_rows, to_tamper_count)
        tampered_ids = []
        for r in chosen:
            storage.tamper_record(r["id"], mode=random.choice(["flip_encrypted", "alter_hash"]))
            tampered_ids.append(r["id"])

        verify_report = storage.verify_all(key_manager)
        return {"tampered_ids": tampered_ids, "verify_report": verify_report}

    def plot_timeline(self, df, out_png="timeline.png"):
        """
        Simple plot of time taken per event
        """
        plt.figure(figsize=(10,4))
        plt.plot(df["row_id"], df["time_taken_s"], marker='o')
        plt.xlabel("row_id")
        plt.ylabel("time_taken_s")
        plt.title("Time taken per event (collect+store)")
        plt.tight_layout()
        plt.savefig(out_png)
        plt.close()

    def save_results_csv(self, df, path="timeline.csv"):
        df.to_csv(path, index=False)
