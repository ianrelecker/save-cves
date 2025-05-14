import sqlite3
import time
from datetime import datetime, timedelta

import nvdlib

#import addKEVwarntoPosts
#import kevimport
import soccav4

POLL_INTERVAL = 86400  # 24 hours

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


# Polling function to fetch and process new vulnerabilities
#begin_poll_time = datetime.utcnow() - timedelta(days=1)


def poll_nvd():
    global begin_poll_time
    kevs = fromkevdb()
    #print(kevs)
    for kev in kevs:
        #print(kev[0].strip("'"))
        try:
            cves = nvdlib.searchCVE(cveId=kev[0].strip("'"), key=API_KEY)
        except Exception as e:
            print("sleeping for 15 min bc of api error" + str(e) + str(datetime.utcnow() + timedelta(minutes=1)))
            time.sleep(60)
            return False
        #cves = nvdlib.searchCVE(pubStartDate=begin_poll_time, pubEndDate=datetime.utcnow(), key=API_KEY)

        # Process only unprocessed CVEs
        for cve in cves:
            if not is_cve_processed(cve.id):
                print("Found: " + cve.id)
                desc = cve.descriptions[0].value
                try:
                    url = cve.references[0].url
                except:
                    url = "fail"
                    print("fail url in nvd")
                pub = cve.published
                cata = ""
                try:
                    cata = str(cve.cve)
                except:
                    print("no cwe")
                cvssdata = str(cve.metrics)
                #print("b")
                mark_cve_as_processed(cve.id, desc, url, pub, cvssdata, cata, True)
                #print("c")
                soccav4.chat(cve.id)
                #print('d')

    # Update the last poll time
    #begin_poll_time = datetime.utcnow()


# Poll continuously
try:
    while True:
        print("Starting Search")
        poll_nvd()
        #kevimport.main()
        #addKEVwarntoPosts.main()
        print("updated kev data for: " + str(datetime.utcnow() - timedelta(hours=8)))
        time.sleep(POLL_INTERVAL)
except KeyboardInterrupt:
    print("Search stopped.")
finally:
    conn.close()  # Close the database connection
