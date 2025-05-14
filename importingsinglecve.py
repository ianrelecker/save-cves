import sqlite3
import time
from datetime import datetime, timedelta

import nvdlib

import soccav5


POLL_INTERVAL = 60  # 15 min

API_KEY = "2b6c0638-2eec-4887-8ca0-50aa0415b44e"

conn = sqlite3.connect('processed_cves.db')
cursor = conn.cursor()

def fromkevdb():
    conn = sqlite3.connect('kev_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM kev_entries")
    return cursor.fetchall()

# Function to check if a CVE has already been processed
def is_cve_processed(cve_id):
    cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
    return cursor.fetchone() is not None


# Function to mark a CVE as processed
def mark_cve_as_processed(cve_id, description, url, pub, data, cata, kev):
    print(cve_id)
    cursor.execute("""
            INSERT INTO processed_cves (cve_id, description, url, pub, data, cata, kev)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, description, url, pub, data, cata, kev))
    conn.commit()




def poll_nvd(cve):
    global begin_poll_time

    try:
        cves = nvdlib.searchCVE(cveId=cve, key=API_KEY)
        print(str(cves))
    except Exception as e:
        print("sleeping for 15 min bc of api error" + str(e) + str(datetime.utcnow() + timedelta(minutes=1)))
        #time.sleep(60)
        return False
        #cves = nvdlib.searchCVE(pubStartDate=begin_poll_time, pubEndDate=datetime.utcnow(), key=API_KEY)

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
            kev = ""
            mark_cve_as_processed(cve.id, desc, str(page_list), pub, cvssdata, cata, kev)
            soccav5.chat(cve.id, desc, str(page_list), pub, cvssdata, cata)



try:
    while True:
        print("Starting Search")
        poll_nvd("CVE-2024-11026")
        time.sleep(6)
except KeyboardInterrupt:
    print("Search stopped.")
finally:
    conn.close()  # Close the database connection
