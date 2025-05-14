import sqlite3
import time
from datetime import datetime, timedelta
import nvdlib
import urllib3.exceptions
import soccav4

POLL_INTERVAL = 60

API_KEY = "2b6c0638-2eec-4887-8ca0-50aa0415b44e"

conn = sqlite3.connect('processed_cves.db')
cursor = conn.cursor()

def is_cve_processed(cve_id):
    cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
    return cursor.fetchone() is not None

def mark_cve_as_processed(cve_id, description, url, pub, data, cata):
    cursor.execute("""
            INSERT INTO processed_cves (cve_id, description, url, pub, data, cata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cve_id, description, url, pub, data, cata))
    conn.commit()


def poll_nvd(begin, end):
    print("polling")
    try:
        cves = nvdlib.searchCVE(pubStartDate=end, pubEndDate=begin, key=API_KEY)
    except urllib3.exceptions.ReadTimeoutError:
        print("sleeping for 2 min bc of api error")
        time.sleep(120)
        return False
    print("begin: "+ str(begin))
    print("end: "+ str(end))
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
            print(pub)
            cata = ""
            try:
                cata = str(cve.cve)
                print("cwe good")
            except:
                print("no cwe")
            cvssdata = str(cve.metrics)
            mark_cve_as_processed(cve.id, desc, url, pub, cvssdata, cata)
            soccav4.chat(cve.id)



# Poll continuously
try:
    while True:
        print("reading new date")
        with open("files/dateholder.txt", "r") as file:
            content = file.read()
        date_obj = datetime.strptime(content, "%Y-%m-%d %H:%M:%S.%f")
        begin_poll_time = date_obj
        end_poll_time = begin_poll_time - timedelta(days=1)
        print("indexing: " + str(begin_poll_time) + str(end_poll_time))
        poll_nvd(begin_poll_time, end_poll_time)
        print("sleeping 60 sec")
        time.sleep(POLL_INTERVAL)
        print("writing new date")
        with open("files/dateholder.txt", 'w') as file:
            file.write(str(end_poll_time))


except KeyboardInterrupt:
    print("Search stopped.")
finally:
    conn.close()  # Close the database connection
