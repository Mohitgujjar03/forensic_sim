# IoT Forensic Evidence Collection Simulation

## Project Overview

This project simulates a **forensic evidence collection protocol** for IoT-enabled smart city environments using a **Python-based framework** (no real hardware required).
It demonstrates secure log collection, hashing, encryption, tamper detection, and evidence verification while measuring performance.

The system is modular and includes:

* **Simulated IoT Devices** → Generate logs/events.
* **Collector Module** → Acquires data, adds timestamps, hashes, and chain-of-custody metadata.
* **Forensic Storage (SQLite)** → Stores encrypted evidence with integrity protection.
* **Verification Engine** → Detects tampering (hash mismatches, decryption failures).
* **Evaluator** → Runs performance tests and generates results/visualisations.

---

## Project Structure

```
forensic_sim/
│
├── device.py        # IoT device simulator
├── collector.py     # Collects logs, adds metadata
├── protocol.py      # Hashing, canonical JSON, metadata
├── storage.py       # SQLite storage + AES-GCM encryption
├── keymanager.py    # Key management (AES keys per collector)
├── evaluator.py     # Runs scenarios, collects stats, tamper simulation
├── main.py          # CLI runner (demo/tamper modes)
│
├── forensic.db      # Generated database (auto-created at runtime)
├── timeline.csv     # Timeline of collected events
├── timeline.png     # Event collection graph
├── verify_summary.csv # Verification results (for appendix)
├── verify_summary.txt # Text version of verification results
├── audit_log.txt    # Append-only forensic audit log
├── tamper_detection.png # Bar chart (OK vs Tampered)
│
└── README.md        # Project documentation
```

---

## Installation

### 1. Clone or copy project files

```bash
git clone <repo_url>
cd forensic_sim
```

### 2. Create virtual environment (Windows PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

> If `requirements.txt` doesn’t exist yet, install manually:

```powershell
pip install cryptography pandas matplotlib tabulate psutil
```

---

## Usage

Run simulations using the command line.

### 1. Demo Run (no tampering)

```powershell
python main.py --devices 20 --events 10 --run demo
```

Generates:

* `timeline.csv` (events dataset)
* `timeline.png` (performance plot)

### 2. Tamper Run (with verification)

```powershell
python main.py --devices 20 --events 10 --run tamper --summary
```

Generates:

* Console output with summary table
* `verify_summary.csv` / `verify_summary.txt`
* `audit_log.txt` (run history with timestamp)
* `tamper_detection.png` (bar chart OK vs Failed)

---

## Example Output

### Console (verification summary)

```
+-----------+--------+-------------------+
| Record ID | Status | Reason            |
+-----------+--------+-------------------+
| 1         | OK     |                   |
| 10        | FAIL   | decryption_failed |
| 19        | FAIL   | hash_mismatch     |
...
Summary:
  Total records: 200
  Verified OK  : 180
  Failed       : 20
```

### Audit Log

```
[2025-08-27 14:32:11] Run with 200 events → OK:180, Failed:20
```
---

## Future Enhancements

* Support for multiple forensic storage backends (MongoDB, Cloud).
* Integration with blockchain for immutable audit trails.
* Real IoT hardware integration (Raspberry Pi, ESP32).



