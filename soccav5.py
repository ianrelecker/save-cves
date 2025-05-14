import ast
import sqlite3

import requests
import tiktoken
from openai import OpenAI
from readability import Document

client = OpenAI()

from bs4 import BeautifulSoup

urldata = []

def urllogic(url_list):
    url_list = ast.literal_eval(url_list)
    content_list = []

    # Step 3: Parse each URL
    for url in url_list:
        try:
            print("url:" + url)
            # Make the web request with a timeout of 10 seconds
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors

            # Use readability-lxml to extract main content
            doc = Document(response.text)
            main_content_html = doc.summary()  # Extracts the main content as HTML
            main_content_text = BeautifulSoup(main_content_html, 'html.parser').get_text(strip=True)

            # Append the extracted content
            if main_content_text:
                content_list.append(str(main_content_text))
                print("ct: " + str(content_list))
            else:
                print("")
                #content_list.append("No main content found")
        except requests.exceptions.Timeout:
            print(f"Timeout occurred for URL {url}")
            #content_list.append("Error: Timeout")
        except Exception as e:
            print(f"Failed to process URL {url}: {e}")
            #content_list.append(f"Error: {e}")
    return content_list

#okay url parsing works, just need to mod chat request.

def selectcve(cve_id):
    conn = sqlite3.connect('processed_cves.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM processed_cves WHERE cve_id = ?", (cve_id,))
    return cursor.fetchall()

def chat(cve_id, desc, page_list, pub, cvssdata, cata):
    global urldata


    urls = "Here are some of the refrences covering this vulnerability, please use them." + str(urllogic(page_list))
    print("urls" + str(urls))




    cvss = "and the CVSS data: " + str(cvssdata)
    #cata = "and the cwe data: " + str(cata)
    context = "'Additional Context (not to be included in the report): You are supported by a system called SOCca, which integrates live data, open-source intelligence, and advanced language models to provide contextual and actionable insights on vulnerabilities. SOCca emphasizes continuous improvement to align with the evolving needs of the cybersecurity community. Take the necessary time and space to create a report that is thorough, actionable, and at least 700 words in length. Your focus is to empower readers to understand, detect, and mitigate the vulnerability effectively while adhering to ethical and legal standards.'"

    # checking token length
    encoding = tiktoken.encoding_for_model("gpt-4o-mini")

    helper_prompt = "'You are a cybersecurity expert and developer specializing in vulnerability assessment and secure development practices. Your task is to produce a professional-grade report designed for cybersecurity practitioners and IT teams. The report should follow industry standards, provide actionable insights, and emphasize clarity and accuracy. Structure the report with the following sections: Vulnerability Overview: Provide a detailed description of the vulnerability, including the affected system(s), software version(s), and any underlying causes. Explain the nature of the vulnerability (e.g., buffer overflow, privilege escalation, SQL injection) and its technical context. Risk and Severity Analysis: Assign a risk level using a standardized scoring system (e.g., CVSS) and explain the rationale behind the score. Discuss the potential business, operational, or security impacts of successful exploitation. Attack Surface and Exploitability: Describe the prerequisites for exploitation, such as required privileges, user interaction, or specific configurations. Highlight what an attacker could achieve (e.g., unauthorized access, data exfiltration, service disruption). Alignment with Security Frameworks: Map the vulnerability to the MITRE ATT&CK Framework, identifying relevant TTPs (tactics, techniques, and procedures). Discuss how this mapping can aid in threat detection, incident response, and defensive strategies. Detection and Validation: Provide practical steps for testing whether a system is vulnerable. Include sample code snippets, pentesting commands, or tool recommendations that adhere to ethical hacking practices and avoid causing harm to systems. Mention known scanning or monitoring tools (e.g., Nmap, Nessus, Metasploit) where relevant. Mitigation and Remediation Recommendations: Offer clear guidance on immediate mitigation steps, such as configuration changes, disabling vulnerable features, or applying temporary fixes. Provide long-term remediation advice, such as patch application, code changes, or adopting best practices. Suggest compensating controls to minimize risk if a full fix is unavailable. Secure Code Review (if applicable): If code is included, analyze it to identify specific vulnerabilities and provide secure coding recommendations. Include detailed examples of secure implementation, referencing common standards like OWASP or NIST. Further Resources: Share links to authoritative resources, advisories, or related CVEs for more in-depth information. Mention any relevant threat intelligence feeds, documentation, or community tools. Formatting and Style Guidelines: Write the report in plain text for ease of sharing and compatibility with cybersecurity workflows. Format sections clearly with headings, bullet points, and readable code blocks for technical content. Ensure the tone is professional, concise, and practical, with a focus on enabling readers to take informed action.'"

    helper_info = "Here is the new vulnerability information. Here is the id:" + str(cve_id) + ", the description: " + str(desc) + str(cvss) + str(urls) + context
    target_token_limit = 127000
    count = 0
    while len(encoding.encode(helper_info)) > target_token_limit:
        helper_info = helper_info[:-10000]
        count = count + 1
        print("trimming prompt: " + str(count))

    print("gpt start")
    helper = client.chat.completions.create(
        model="gpt-4o-mini-2024-07-18",
        messages=[
            {"role": "system",
             "content": helper_prompt
             },
            {
                "role": "user",
                "content": helper_info
            }
        ]
    )
    gpt_report = helper.choices[0].message.content

    gpt_report = gpt_report + "\n\nSocca Version 5.0"
    #print(gpt_report)
    savereport(cve_id, gpt_report)

def savereport(cve_id, report):
    conn = sqlite3.connect('cve_reports.db')
    cursor = conn.cursor()
    cursor.execute("""
                INSERT INTO processed (cve_id, report)
                VALUES (?, ?)
            """, (cve_id, report))
    conn.commit()
    print("saving report")

#chat("CVE-2024-11068")