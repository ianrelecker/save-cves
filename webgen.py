import json
import sqlite3
import time
import os
from datetime import datetime, timedelta
from openai import OpenAI

import requests

# Load OpenAI API key from environment variable
if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY environment variable is required")
    exit(1)

client = OpenAI()

# WordPress site and credentials
site_url = "https://socca.tech"
api_url = f"{site_url}/wp-json/wp/v2/posts"
categories_url = f"{site_url}/wp-json/wp/v2/categories"

# Load WordPress credentials from environment variables
username = os.environ.get("WORDPRESS_USERNAME", "ianrelecker")
password = os.environ.get("WORDPRESS_PASSWORD")
if not password:
    print("ERROR: WORDPRESS_PASSWORD environment variable is required")
    exit(1)

# Authentication setup for basic auth
auth = (username, password)

def get_pub_date(cve_id):
    conn = sqlite3.connect('processed_cves.db')
    cursor = conn.cursor()
    cursor.execute("SELECT pub FROM processed_cves WHERE cve_id = ?", (cve_id,))
    date_cleaning = cursor.fetchone()[0]
    pub_date = datetime.strptime(date_cleaning.replace("'", ""), "%Y-%m-%dT%H:%M:%S.%f")
    pub_date = pub_date - timedelta(hours=8)
    return pub_date

def get_cvss(cve_id):
    conn = sqlite3.connect('processed_cves.db')
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM processed_cves WHERE cve_id = ?", (cve_id,))

    cvss_cleaning = cursor.fetchone()[0]
    cvss_cleaning = cvss_cleaning.replace("'", '"')
    cvss_cleaning = json.loads(cvss_cleaning)
    cvss_cleaning = cvss_cleaning['cvssMetricV31'][0]['cvssData']['baseScore']
    return cvss_cleaning

def get_prod(report):
    prod_prompt = "You are doing two things, please respond with both items, please separate the two answers with a colon ':'. Here is the first item: 'You are identifying products in security reports, you are only to respond with the product and the vendor mentioned in the report. For example if the report is about a vulnerability in the Dell Configuration Manager, your response should be 'Dell Configuration Manager'. Here is another example, if the issue is in the linux kernel only respond with 'Linux Kernel'. Please only respond with the product name.' and 'You are assessing the risk imposed by the vulnerability, if the vulnerability is in a widely used piece of software and is able to get a high level of access, it should be classified as critical. If the vulnerability is in a less widely used bit of software or doesn't allow for many privileges to be gained, score it low. The 4 options that you have are (Low, Medium, High, Critical). Please only respond with the option of what risk you believe the vulnerability is.'"
    content = "This is the report: " + str(report)
    helper = client.chat.completions.create(
        model="gpt-4o-mini-2024-07-18",
        messages=[
            {"role": "system",
             "content": prod_prompt
             },
            {
                "role": "user",
                "content": content
            }
        ]
    )
    gpt_report = helper.choices[0].message.content
    return gpt_report

def is_cve_processed(cve_id):
    conn = sqlite3.connect('posts.db')
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM posts WHERE id = ?", (cve_id,))
    return cursor.fetchone() is not None


# Function to mark a CVE as processed
def mark_cve_as_processed(cve_id, report):
    conn = sqlite3.connect('posts.db')
    cursor = conn.cursor()
    cursor.execute("""
            INSERT INTO posts (id, report)
            VALUES (?, ?)
        """, (cve_id, report ))
    conn.commit()

def selectcve(cve_id):
    conn = sqlite3.connect('cve_reports.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM processed WHERE cve_id = ?", (cve_id,))
    cve = cursor.fetchall()

    conn = sqlite3.connect('processed_cves.db')
    cursor = conn.cursor()
    cursor.execute("SELECT cata FROM processed_cves WHERE cve_id = ?", (cve_id,))
    if cursor.fetchone() != "":
        id_list = []
        try:
            da = cursor.fetchall()
            # Convert the string into a list of dictionaries using ast.literal_eval
            input_data = da[0][0].replace("'", '"')

            # Convert the string into a Python object (list of dictionaries) using json.loads
            data = json.loads(input_data)

            # Extract the CWE values ('value' field) from each dictionary
            cwe_values = [entry['value'] for entry in data]

            for cwe in cwe_values:
                id_list.append(get_or_create_category(cwe, auth))
            print("cata sucess" + str(id_list))
        except:
            print("")
    else:
        print("cata/cwe fail")
    # processing single cve

    single = cve[0]
    id = single[0]
    content = single[1]
    return content, id_list

#def createpost(cve_id, content):


def get_or_create_category(name, auth):
    # Check if category already exists
    response = requests.get(categories_url, params={"search": name}, auth=auth)
    if response.status_code == 200:
        categories = response.json()
        if categories:
            return categories[0]['id']  # Return existing category ID if found

    # If the category does not exist, create it
    response = requests.post(categories_url, json={"name": name}, auth=auth)
    if response.status_code == 201:  # 201 Created
        return response.json()['id']  # Return new category ID
    else:
        print("Failed to create category:", response.status_code, response.json())
        return None


# Post details
def newcvepost(cve_id):
    if is_cve_processed(cve_id) == False:
        content, catagories = selectcve(cve_id)
        score = " Base Score: "
        try:
            score = score + str(get_cvss(cve_id))
        except:
            score = ""
        post_data = {
            "title": str(cve_id) + ": (" + get_prod(content) +")",
            "slug": str(cve_id),
            "content": content,
            "status": "publish",  # Options: 'publish', 'draft', 'pending', etc.
            "catagories": catagories,
            "date": get_pub_date(cve_id).isoformat()
        }
        mark_cve_as_processed(cve_id, "5")
        create_post(api_url, post_data, auth)

# Function to create a post
def create_post(api_url, post_data, auth):

    try:
        response = requests.post(api_url, json=post_data, auth=auth)

        # Check for successful response
        if response.status_code == 201:  # 201 Created
            print("Post created successfully.")
            print("Post ID:", response.json()["id"])
            print("Post URL:", response.json()["link"])
        else:
            print("Failed to create post:", response.status_code)
            print(response.json())  # Print error details

    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)


def main():
    # Poll continuously
    try:
        while True:
            conn = sqlite3.connect('cve_reports.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processed")
            cves = cursor.fetchall()
            for cve in cves:
                newcvepost(cve[0])
            print("trying again at: " + str(datetime.utcnow() + timedelta(seconds=60)))
            time.sleep(60)
    except KeyboardInterrupt:
        print("Search stopped.")
    finally:
        conn.close()  # Close the database connection

# Run the function to create the post
#create_post(api_url, post_data, auth)
#newcvepost("CVE-2024-50589")
main()