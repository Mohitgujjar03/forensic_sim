# main.py
import argparse
from evaluator import Evaluator
import json
import shutil

def print_summary_table(report):
    """Prints a neat summary table of verification results"""
    rows = []
    for r in report["details"]:
        rid = r["id"]
        status = "OK" if r.get("ok") else "FAIL"
        reason = r.get("reason", "")
        if not r.get("ok") and "computed_hash" in r:
            reason = "hash_mismatch"
        rows.append([rid, status, reason])

    # Try tabulate if installed
    try:
        from tabulate import tabulate
        print(tabulate(rows, headers=["Record ID", "Status", "Reason"], tablefmt="grid"))
    except ImportError:
        # Fallback simple table
        print("{:<10} {:<8} {:<20}".format("Record ID", "Status", "Reason"))
        print("-" * 40)
        for row in rows:
            print("{:<10} {:<8} {:<20}".format(*row))

    print("\nSummary:")
    print(f"  Total records: {report['total']}")
    print(f"  Verified OK  : {report['ok']}")
    print(f"  Failed       : {report['bad']}")

def export_verify_summary(report, csv_path="verify_summary.csv", txt_path="verify_summary.txt"):
    import csv
    # Export to CSV
    with open(csv_path, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Record ID", "Status", "Reason"])
        for r in report["details"]:
            rid = r["id"]
            status = "OK" if r.get("ok") else "FAIL"
            reason = r.get("reason", "")
            writer.writerow([rid, status, reason])
    # Export to TXT
    with open(txt_path, "w") as f:
        f.write("{:<10} {:<8} {:<20}\n".format("Record ID", "Status", "Reason"))
        f.write("-" * 40 + "\n")
        for r in report["details"]:
            rid = r["id"]
            status = "OK" if r.get("ok") else "FAIL"
            reason = r.get("reason", "")
            f.write("{:<10} {:<8} {:<20}\n".format(rid, status, reason))

def append_audit_log(report, log_path="audit_log.txt"):
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a") as f:
        f.write(f"--- Verification Run @ {now} ---\n")
        f.write(f"Total: {report['total']}, OK: {report['ok']}, Failed: {report['bad']}\n")
        for r in report["details"]:
            rid = r["id"]
            status = "OK" if r.get("ok") else "FAIL"
            reason = r.get("reason", "")
            f.write(f"{rid}: {status} ({reason})\n")
        f.write("\n")

def plot_tamper_bar(report, out_png="tamper_detection.png"):
    import matplotlib.pyplot as plt
    ok = report["ok"]
    bad = report["bad"]
    plt.figure(figsize=(5,4))
    plt.bar(["OK", "Tampered"], [ok, bad], color=["green", "red"])
    plt.ylabel("Count")
    plt.title("Tamper Detection Results")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Forensic simulation runner")
    parser.add_argument("--devices", type=int, default=10, help="Number of simulated devices")
    parser.add_argument("--events", type=int, default=5, help="Events per device")
    parser.add_argument("--hashchain", action="store_true", help="Enable hash chaining")
    parser.add_argument("--run", choices=["demo", "tamper"], default="demo", help="Action")
    parser.add_argument("--summary", action="store_true", help="Show verification results in a summary table")
    args = parser.parse_args()

    ev = Evaluator(devices_count=args.devices, events_per_device=args.events, enable_hash_chain=args.hashchain)
    out = ev.run_scenario()
    res = out["results"]
    print("Scenario finished.")
    print(json.dumps({
        "devices": res["devices"],
        "events_per_device": res["events_per_device"],
        "total_events": res["total_events"],
        "total_time_s": res["total_time_s"],
        "avg_time_per_event_s": res["avg_time_per_event_s"],
        "memory_peak_bytes": res["memory_peak_bytes"]
    }, indent=2))

    # save timeline and plot
    timeline_df = res["timeline"]
    ev.save_results_csv(timeline_df, path="timeline.csv")
    ev.plot_timeline(timeline_df, out_png="timeline.png")
    print("Saved timeline.csv and timeline.png")

    if args.run == "tamper":
        print("Simulating tamper and verifying...")
        tamper_report = ev.simulate_tamper_and_verify(out["storage"], out["key_manager"], percent_to_tamper=0.1)
        print("Tampered IDs:", tamper_report["tampered_ids"])

        verify_report = tamper_report["verify_report"]
        # Print summary table
        if args.summary:
            print_summary_table(verify_report)
        else:
            print("Verify summary:", verify_report)

        # Export summary table
        export_verify_summary(verify_report)
        print("Saved verify_summary.csv and verify_summary.txt")

        # Append to audit log
        append_audit_log(verify_report)
        print("Appended results to audit_log.txt")

        # Plot tamper detection bar chart
        plot_tamper_bar(verify_report)
        print("Saved tamper_detection.png")

if __name__ == "__main__":
    main()
