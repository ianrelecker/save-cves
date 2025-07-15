import json
import logging
from typing import List, Optional, Dict, Any

import requests
import tiktoken
from openai import OpenAI
from readability import Document
from bs4 import BeautifulSoup

from azure_db import get_database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize OpenAI client
client = OpenAI()

# Initialize database connection
db = get_database()


def extract_web_content(url_list: List[str]) -> List[str]:
    """Extract content from a list of URLs"""
    content_list = []

    for url in url_list:
        try:
            logger.info(f"Extracting content from URL: {url}")
            
            # Make the web request with a timeout of 10 seconds
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors

            # Use readability to extract main content
            doc = Document(response.text)
            main_content_html = doc.summary()  # Extracts the main content as HTML
            main_content_text = BeautifulSoup(main_content_html, 'html.parser').get_text(strip=True)

            # Append the extracted content
            if main_content_text:
                content_list.append(str(main_content_text))
                logger.debug(f"Extracted {len(main_content_text)} characters from {url}")
            else:
                logger.warning(f"No main content found for URL: {url}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout occurred for URL {url}")
        except Exception as e:
            logger.error(f"Failed to process URL {url}: {e}")
            
    return content_list


def analyze_cve(cve_id: str, description: str, reference_urls: List[str]) -> bool:
    """Analyze a CVE using AI and store the report"""
    try:
        logger.info(f"Starting AI analysis for CVE {cve_id}")
        
        # Extract content from reference URLs
        web_content = extract_web_content(reference_urls)
        urls_content = "Here are some of the references covering this vulnerability: " + str(web_content)
        
        # Get CVE data from database for additional context
        cve_query = "SELECT * FROM cve_entries WHERE cve_id = ?"
        cve_data = db.db.execute_query(cve_query, (cve_id,))
        
        if not cve_data:
            logger.error(f"CVE {cve_id} not found in database")
            return False
        
        cve_info = cve_data[0]
        
        # Build CVSS information
        cvss_info = ""
        if cve_info.get('cvss_score'):
            cvss_info = f"CVSS Score: {cve_info['cvss_score']}, Severity: {cve_info['cvss_severity']}"
            if cve_info.get('cvss_vector'):
                cvss_info += f", Vector: {cve_info['cvss_vector']}"
        
        # Build analysis context
        context = (
            "Additional Context (not to be included in the report): You are supported by a system called SOCca, "
            "which integrates live data, open-source intelligence, and advanced language models to provide "
            "contextual and actionable insights on vulnerabilities. SOCca emphasizes continuous improvement "
            "to align with the evolving needs of the cybersecurity community. Take the necessary time and space "
            "to create a report that is thorough, actionable, and at least 700 words in length. Your focus is "
            "to empower readers to understand, detect, and mitigate the vulnerability effectively while adhering "
            "to ethical and legal standards."
        )
        
        # Generate the analysis report
        report_content = generate_vulnerability_report(cve_id, description, cvss_info, urls_content, context)
        
        if report_content:
            # Save the report to database
            success = db.insert_cve_report(cve_id, report_content)
            if success:
                logger.info(f"Successfully saved analysis report for CVE {cve_id}")
                return True
            else:
                logger.error(f"Failed to save report for CVE {cve_id}")
                return False
        else:
            logger.error(f"Failed to generate report for CVE {cve_id}")
            return False
            
    except Exception as e:
        logger.error(f"Error analyzing CVE {cve_id}: {e}")
        return False


def generate_vulnerability_report(cve_id: str, description: str, cvss_info: str, 
                                 urls_content: str, context: str) -> Optional[str]:
    """Generate a comprehensive vulnerability report using OpenAI"""
    try:
        # Define the system prompt for generating comprehensive vulnerability reports
        system_prompt = (
            "You are a cybersecurity expert and developer specializing in vulnerability assessment and secure "
            "development practices. Your task is to produce a professional-grade report designed for cybersecurity "
            "practitioners and IT teams. The report should follow industry standards, provide actionable insights, "
            "and emphasize clarity and accuracy. Structure the report with the following sections:\n\n"
            
            "1. Vulnerability Overview: Provide a detailed description of the vulnerability, including the affected "
            "system(s), software version(s), and any underlying causes. Explain the nature of the vulnerability "
            "(e.g., buffer overflow, privilege escalation, SQL injection) and its technical context.\n\n"
            
            "2. Risk and Severity Analysis: Assign a risk level using a standardized scoring system (e.g., CVSS) "
            "and explain the rationale behind the score. Discuss the potential business, operational, or security "
            "impacts of successful exploitation.\n\n"
            
            "3. Attack Surface and Exploitability: Describe the prerequisites for exploitation, such as required "
            "privileges, user interaction, or specific configurations. Highlight what an attacker could achieve "
            "(e.g., unauthorized access, data exfiltration, service disruption).\n\n"
            
            "4. Alignment with Security Frameworks: Map the vulnerability to the MITRE ATT&CK Framework, identifying "
            "relevant TTPs (tactics, techniques, and procedures). Discuss how this mapping can aid in threat detection, "
            "incident response, and defensive strategies.\n\n"
            
            "5. Detection and Validation: Provide practical steps for testing whether a system is vulnerable. Include "
            "sample code snippets, pentesting commands, or tool recommendations that adhere to ethical hacking practices "
            "and avoid causing harm to systems. Mention known scanning or monitoring tools (e.g., Nmap, Nessus, Metasploit) "
            "where relevant.\n\n"
            
            "6. Mitigation and Remediation Recommendations: Offer clear guidance on immediate mitigation steps, such as "
            "configuration changes, disabling vulnerable features, or applying temporary fixes. Provide long-term "
            "remediation advice, such as patch application, code changes, or adopting best practices. Suggest compensating "
            "controls to minimize risk if a full fix is unavailable.\n\n"
            
            "7. Secure Code Review (if applicable): If code is included, analyze it to identify specific vulnerabilities "
            "and provide secure coding recommendations. Include detailed examples of secure implementation, referencing "
            "common standards like OWASP or NIST.\n\n"
            
            "8. Further Resources: Share links to authoritative resources, advisories, or related CVEs for more in-depth "
            "information. Mention any relevant threat intelligence feeds, documentation, or community tools.\n\n"
            
            "Formatting and Style Guidelines: Write the report in plain text for ease of sharing and compatibility with "
            "cybersecurity workflows. Format sections clearly with headings, bullet points, and readable code blocks for "
            "technical content. Ensure the tone is professional, concise, and practical, with a focus on enabling readers "
            "to take informed action."
        )
        
        # Build the user prompt with vulnerability information
        user_prompt = (
            f"Here is the vulnerability information for analysis:\n\n"
            f"CVE ID: {cve_id}\n"
            f"Description: {description}\n"
            f"{cvss_info}\n"
            f"{urls_content}\n\n"
            f"{context}"
        )
        
        # Check token length and trim if necessary
        encoding = tiktoken.encoding_for_model("gpt-4o-mini")
        target_token_limit = 127000
        trim_count = 0
        
        while len(encoding.encode(user_prompt)) > target_token_limit:
            user_prompt = user_prompt[:-10000]
            trim_count += 1
            logger.warning(f"Trimming prompt for CVE {cve_id}, iteration {trim_count}")
        
        logger.info(f"Generating AI report for CVE {cve_id}")
        
        # Generate the report using OpenAI
        response = client.chat.completions.create(
            model="gpt-4o-mini-2024-07-18",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        
        report_content = response.choices[0].message.content
        report_content += "\n\nSOCca Version 5.0"
        
        logger.info(f"Successfully generated report for CVE {cve_id}")
        return report_content
        
    except Exception as e:
        logger.error(f"Failed to generate vulnerability report for CVE {cve_id}: {e}")
        return None


# Legacy function for backward compatibility
def chat(cve_id: str, desc: str, page_list: str, pub: str, cvssdata: str, cata: str):
    """Legacy function - redirects to new analyze_cve function"""
    try:
        import ast
        url_list = ast.literal_eval(page_list)
        return analyze_cve(cve_id, desc, url_list)
    except Exception as e:
        logger.error(f"Error in legacy chat function for CVE {cve_id}: {e}")
        return False


def get_cve_report(cve_id: str) -> Optional[str]:
    """Get the report content for a CVE"""
    report = db.get_cve_report(cve_id)
    return report['report_content'] if report else None


def get_unprocessed_cves(limit: int = 100) -> List[Dict]:
    """Get CVEs that need AI analysis"""
    return db.get_unprocessed_cves(limit)