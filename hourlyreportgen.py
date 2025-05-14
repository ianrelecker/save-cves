import sqlite3
import datetime
import time
from datetime import timedelta
from http.client import responses
from logging import exception

import openai
import requests
import tiktoken
from openai import OpenAI
from requests.auth import HTTPBasicAuth

# Configuration
DATABASE_PATH = 'your_database.db'  # Replace with your database file path
TABLE_NAME = 'your_table'  # Replace with your table name
TIMESTAMP_COLUMN = 'created_at'  # Replace with the column name for timestamps
OPENAI_API_KEY = 'your-openai-api-key'  # Replace with your OpenAI API key
MODEL = 'gpt-4'  # Replace with the desired OpenAI model
client = OpenAI()

# WordPress Configuration
site_url = "https://socca.tech"
api_url = f"{site_url}/wp-json/wp/v2/posts"
categories_url = f"{site_url}/wp-json/wp/v2/categories"
username = "ianrelecker"
password = "nRTX y8ZZ vEXp B2W7 7z0t S84g"

# Authentication setup for basic auth
auth = (username, password)

# Initialize OpenAI API
openai.api_key = OPENAI_API_KEY


def fetch_recent_posts():

    if datetime.datetime.now().hour == 5:
        two_hours_ago = (datetime.datetime.now() + datetime.timedelta(hours=8) - datetime.timedelta(hours=15)).isoformat()
    if datetime.datetime.now().hour == 13:
        two_hours_ago = (datetime.datetime.now() + datetime.timedelta(hours=8) - datetime.timedelta(hours=11)).isoformat()

    print(two_hours_ago)
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('processed_cves.db')
        cursor = conn.cursor()

        # Calculate the timestamp for 2 hours ago


        # Query for posts created in the last 2 hours
        query = f"""
        SELECT * FROM processed_cves
        WHERE pub >= ?;
        """
        cursor.execute(query, (two_hours_ago,))
        print(two_hours_ago)
        # Fetch all matching records
        records = cursor.fetchall()

        # Get column names for reference
        #column_names = [desc[0] for desc in cursor.description]
        conn.close()

        print(str(records))

        conn = sqlite3.connect('cve_reports.db')
        cursor = conn.cursor()
        list_o_reports = []
        for cves in records:
            cursor.execute("SELECT report FROM processed WHERE cve_id = ?", (cves[0],))
            print(cves[0])
            hold = cursor.fetchall()
            list_o_reports.append(str(hold[0][0]).strip("'"))

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return [], []

    return list_o_reports, two_hours_ago

def send_to_chatgpt(records):
    # checking token length
    encoding = tiktoken.encoding_for_model("o1-mini")

    helper_prompt = "You are a cybersecurity expert specializing in vulnerability management and secure systems development. Your task is to create a comprehensive, actionable, and professional report analyzing the included vulnerability data from the past 12 hours. The primary audience for this report includes: SOC Analysts and Vulnerability Management Teams: Provide technical depth and actionable insights to support remediation efforts. Content Prioritization While the report should cover all vulnerabilities from the included data, prioritize and detail the most critical ones based on: Breadth of impact: Vulnerabilities affecting widely adopted software, critical infrastructure, or systems processing sensitive data (e.g., PII, financial, or healthcare information). Exploitability: Vulnerabilities with known exploits, proof-of-concept attacks, or those particularly easy to exploit. Severity: CVSS scores and other risk metrics, contextualized for large enterprise environments. Include a separate appendix for less critical vulnerabilities from the reports that could still be relevant for organizations using the affected products. Structure and Requirements Executive Summary (Highlight the top 3–5 critical vulnerabilities, their potential organizational impact, and a summary of remediation strategies.) Critical Vulnerabilities Analysis (Detailed Sections for Each): Vulnerability Overview: CVE, description, affected software versions, and vendors. Impact Analysis: Real-world implications, including risk to sensitive data or critical operations. Exploitability: Assessment of how easy the vulnerability is to exploit, known attack methods, and any observed activity in the wild. Mitigation and Recommendations: Clear guidance for remediation, such as applying patches, implementing compensating controls, or monitoring for exploits. Supplementary Vulnerabilities Section: Include all other CVEs from the reports, categorized by affected product/vendor. Provide summaries and recommendations where relevant but keep these concise for quick reference Risk categorization: High, Medium, Low. Style and Presentation Professional and Polished: Ensure the report is well-structured and visually appealing, with clear headings, tables, and diagrams where needed. Readable Yet Technical: Balance technical details with accessibility, making it useful for both high-level strategy and hands-on implementation. Action-Oriented: Emphasize strategic actions and pure analysis. Key Principles to Follow Risk-Based Prioritization: Guide on what to address first. Comprehensive Coverage: No vulnerability should be omitted. Provide a full picture, even for lower-priority items. Alignment with Best Practices: Reinforce frameworks or other relevant standards. Deliverable Expectations Take as much time and space as necessary to create a robust, detailed, and actionable report. Your work will directly influence decision-making at the highest levels, so ensure the quality reflects that responsibility. Please include the links to all of the vulnerabilities, the format is 'https://socca.tech/cve_id' with 'cve_id' being the ID of the CVE, example 'CVE-2024-1111' would be 'https://socca.tech/cve-2024-1111'. Make the report as human as possible as it will be the content for a news report. Your report is considered to be a Final Draft with no changes needing to be made. Start off the report with the executive summary and end with the conclusion, no need to introduce yourself."

    helper_info = "Here are all of the reports" + str(records)
    print("Helper info:" + str(helper_info))
    target_token_limit = 127000
    count = 0
    while len(encoding.encode(helper_info)) > target_token_limit:
        # Trim a small portion from the end (e.g., 50 characters) and re-check the length
        helper_info = helper_info[:-1000]
        count = count + 1
        print("trimming prompt: " + str(count))
    print("gpt start")
    helper = client.chat.completions.create(
        model="o1-mini-2024-09-12",
        messages=[
            {"role": "assistant",
             "content": helper_prompt
             },
            {
                "role": "user",
                "content": helper_info
            }
        ]
    )
    gpt_report = helper.choices[0].message.content
    print(gpt_report)
    return gpt_report


def send_to_wordpress(post_title, post_content):
    """Send a post to WordPress."""
    try:
        # Create the payload
        cat = [1367]
        payload = {
            'title': post_title,
            'content': post_content,
            'status': 'publish',  # You can set 'draft' if you want to review before publishing
            'categories': cat,
        }

        # Send the post to WordPress
        response = requests.post(
            api_url,
            json=payload,
            auth=auth
        )

        if response.status_code == 201:
            print(f"Post published successfully: {response.json().get('link')}")
        else:
            print(f"Failed to publish post: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"Error sending post to WordPress: {e}")


def main():
    try:
        while True:
            if (datetime.datetime.now().minute == 55 and datetime.datetime.now().hour == 5) or (datetime.datetime.now().minute == 55 and datetime.datetime.now().hour == 13) :
                print("starting report gen")
                # Fetch records from the database
                list_of_posts, timeline = fetch_recent_posts()
                if not list_of_posts:
                    print("No recent records found.")

                # Send records to ChatGPT and post results to WordPress
                gpt = send_to_chatgpt(list_of_posts)

                if gpt:
                    # Convert to a datetime object
                    dt_object = datetime.datetime.now()
                    # Format into a readable string
                    readable_format = dt_object.strftime("%I:%M %p %B %d, %Y")
                    # Send the response to WordPress
                    post_title = "Security Report for " + str(readable_format)
                    print(post_title)
                    send_to_wordpress(post_title, gpt)
                    #print("done: sleeping until" + str(datetime.datetime.now() + timedelta(hours=1)))
                else:
                    print("gpt")
            print("nope")
            time.sleep(60)
    except KeyboardInterrupt:
        print("stopped")

if __name__ == "__main__":
    main()
