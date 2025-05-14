#
# Ian Relecker
#
import time

import requests
import sqlite3
import json
import hashlib
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_data():
    response = requests.get(KEV_URL)
    response.raise_for_status()
    return response.json()


def create_database(db_name="kev_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS kev_entries (
                        cve_id TEXT PRIMARY KEY,
                        vendor TEXT,
                        product TEXT,
                        vulnerability_name TEXT,
                        description TEXT,
                        due_date TEXT)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS update_log (
                        timestamp TEXT,
                        changes TEXT)''')
    conn.commit()
    conn.close()


def hash_kev_entry(entry):
    entry_data = json.dumps({
        'cve_id': entry['cveID'],
        'vendor': entry['vendorProject'],
        'product': entry['product'],
        'vulnerability_name': entry['vulnerabilityName'],
        'description': entry['shortDescription'],
        'due_date': entry['dueDate']
    }, sort_keys=True)
    return hashlib.sha256(entry_data.encode()).hexdigest()


def compare_and_update_db(new_data, db_name="kev_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("SELECT cve_id FROM kev_entries")
    existing_entries = {row[0] for row in cursor.fetchall()}  # A set of existing cve_id values

    changes = {"added": [], "updated": [], "removed": []}

    for entry in new_data:
        entry_hash = hash_kev_entry(entry)
        cve_id = entry['cveID']
        if cve_id not in existing_entries:
            changes["added"].append(entry)
        else:
            cursor.execute("SELECT * FROM kev_entries WHERE cve_id=?", (cve_id,))
            existing_entry = cursor.fetchone()
            if hash_kev_entry({
                'cveID': existing_entry[0],
                'vendorProject': existing_entry[1],
                'product': existing_entry[2],
                'vulnerabilityName': existing_entry[3],
                'shortDescription': existing_entry[4],
                'dueDate': existing_entry[5]
            }) != entry_hash:
                changes["updated"].append(entry)

    new_cve_ids = {entry['cveID'] for entry in new_data}
    removed_ids = existing_entries - new_cve_ids
    changes["removed"] = list(removed_ids)

    if changes["added"] or changes["updated"] or changes["removed"]:
        cursor.execute("INSERT INTO update_log (timestamp, changes) VALUES (?, ?)",
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), json.dumps(changes)))

    for entry in changes["added"] + changes["updated"]:
        cursor.execute('''INSERT OR REPLACE INTO kev_entries (cve_id, vendor, product, vulnerability_name, description, due_date)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (entry['cveID'], entry['vendorProject'], entry['product'], entry['vulnerabilityName'],
                        entry['shortDescription'], entry['dueDate']))

    for removed_id in changes["removed"]:
        cursor.execute("DELETE FROM kev_entries WHERE cve_id=?", (removed_id,))

    conn.commit()
    conn.close()


def main():
    print("starting poll.")
    kev_data = fetch_kev_data()
    new_data = kev_data.get('vulnerabilities', [])

    create_database()

    compare_and_update_db(new_data)
    print("poll finished, sleeping 30 min.")
    time.sleep(1800)

if __name__ == "__main__":
    main()