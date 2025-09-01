import os
import sqlite3
import requests

DB_FILE = "threat_intel.db"
API_KEY = "YOUR_API_KEY_HERE"   # Not used in Option 1 (fetch skipped)
ENABLE_FETCH = False            # Option 1: keep this False to skip API fetch

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            ip_address TEXT PRIMARY KEY,
            abuse_confidence INTEGER,
            country_code TEXT
        )
    """)
    conn.commit()
    conn.close()

def fetch_threat_feed(limit=50):
    print("\nFetching latest threat intelligence...")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"limit": limit}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return 0

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    added = 0
    for rec in data.get("data", []):
        try:
            cur.execute(
                "INSERT OR IGNORE INTO iocs (ip_address, abuse_confidence, country_code) VALUES (?, ?, ?)",
                (rec.get("ipAddress"), rec.get("abuseConfidenceScore"), rec.get("countryCode")),
            )
            if cur.rowcount > 0:
                added += 1
        except Exception:
            # skip bad rows safely
            pass
    conn.commit()
    conn.close()
    print(f"Database updated. Added {added} new IPs.")
    return added

def ensure_demo_data():
    """Seed at least one IOC so alert is guaranteed even if fetch is skipped/DB empty."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM iocs")
    count = cur.fetchone()[0]
    if count == 0:
        cur.execute(
            "INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code) VALUES (?, ?, ?)",
            ("45.143.200.100", 100, "ZZ"),
        )
        conn.commit()
        print("Seeded demo IOC: 45.143.200.100 (Confidence 100)")
    conn.close()

def check_logs(log_file):
    print(f"\nScanning log file: {log_file}...")
    if not os.path.exists(log_file):
        print(f"Log file '{log_file}' not found. Creating a demo log.")
        with open(log_file, "w") as f:
            f.write("45.143.200.100\n")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    found = False

    with open(log_file, "r") as f:
        for line in f:
            ip = line.strip()
            if not ip:
                continue
            cur.execute("SELECT ip_address, abuse_confidence FROM iocs WHERE ip_address = ?", (ip,))
            row = cur.fetchone()
            if row:
                print(f"  [!] ALERT: Malicious IP found: {row[0]} (Confidence: {row[1]}%)")
                found = True

    if not found:
        print("  No alerts found.")
    conn.close()

if __name__ == "__main__":
    print("⚡ Script started ⚡")
    setup_database()

    if ENABLE_FETCH:
        fetch_threat_feed()
    else:
        print("Skipping fetch (API limit or offline mode).")
        ensure_demo_data()

    # Ensure a demo log exists with the demo IOC so you see an alert
    if not os.path.exists("access.log"):
        with open("access.log", "w") as f:
            f.write("8.8.8.8\n")
            f.write("192.168.1.1\n")
            f.write("45.143.200.100\n")

    check_logs("access.log")

