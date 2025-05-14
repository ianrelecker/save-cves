import sqlite3
import time
from datetime import datetime, timedelta
import os

import nvdlib

import soccav4
import soccav5

# Load API key from environment variable or use a default placeholder
API_KEY = os.environ.get("NVD_API_KEY", "your-nvd-api-key-here")

conn = sqlite3.connect('processed_cves.db')
cursor = conn.cursor()


# Function to check if a CVE has already been processed
def is_cve_processed(cve_id):
    cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
    return cursor.fetchone() is not None


# Function to mark a CVE as processed
def mark_cve_as_processed(cve_id, description, url, pub, data, cata):
    cursor.execute("""
            INSERT INTO processed_cves (cve_id, description, url, pub, data, cata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cve_id, description, url, pub, data, cata))
    conn.commit()


# Polling function to fetch and process new vulnerabilities
begin_poll_time = datetime.utcnow() - timedelta(days=1)


def poll_nvd():
    global begin_poll_time
    try:
        cves = nvdlib.searchCVE(pubStartDate=begin_poll_time, pubEndDate=datetime.utcnow(), key=API_KEY,)
        print(str(cves))
    except Exception as e:
        #begin_poll_time = datetime.utcnow() - timedelta(days=1)
        print("api error" + str(e))
        #time.sleep(300)
        return False
    # Process only unprocessed CVEs
    for cve in cves:
        if not is_cve_processed(cve.id):
            print("Found: " + cve.id)
            desc = cve.descriptions[0].value
            page_list = []
            try:
                print(cve.references)
                for page in cve.references:
                    print(page.url)
                    page_list.append(page.url)
                print(page_list)
            except:
                print("fail url in nvd")

            pub = cve.published
            cata = ""
            try:
                cata = str(cve.cve)
            except:
                print("")
            cvssdata = str(cve.metrics)
            mark_cve_as_processed(cve.id, desc, str(page_list), pub, cvssdata, cata)
            soccav5.chat(cve.id, desc, str(page_list), pub, cvssdata, cata)

# Poll continuously
try:
    while True:
        print("Starting Search")
        poll_nvd()
        time.sleep(60)
except KeyboardInterrupt:
    print("Search stopped.")
finally:
    conn.close()  # Close the database connection
