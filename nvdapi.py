import requests
import time
import datetime
import os

# Base URL for the NVD API
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Load API key from environment variable or use None if not available
API_KEY = os.environ.get("NVD_API_KEY")
# Configure rate limits (NVD allows up to 5 requests per second)
RATE_LIMIT = 6  # requests per second

# Headers for the request
HEADERS = {
    "Content-Type": "application/json",
}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

def fetch_cves(start_date, end_date):
    """
    Fetch CVEs from the NVD API within the given date range.

    :param start_date: Start date (YYYY-MM-DD)
    :param end_date: End date (YYYY-MM-DD)
    :return: List of CVEs
    """
    params = {
        "pubStartDate": f"{start_date}T00:00:00.000Z",
        "pubEndDate": f"{end_date}T23:59:59.999Z",
    }

    try:
        response = requests.get(NVD_API_BASE_URL, headers=HEADERS, params=params)

        # Handle rate-limiting
        time.sleep(1 / RATE_LIMIT)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def main():
    """Main function to fetch CVEs."""
    # Example: Fetch CVEs from the past 7 days
    end_date = datetime.datetime.utcnow()
    start_date = end_date - datetime.timedelta(days=1)

    start_date_str = start_date.strftime("%Y-%m-%d")
    end_date_str = end_date.strftime("%Y-%m-%d")

    print(f"Fetching CVEs from {start_date_str} to {end_date_str}...")
    cves = fetch_cves(start_date_str, end_date_str)

    if cves:
        print(f"Retrieved {len(cves.get('vulnerabilities', []))} CVEs.")
    else:
        print("No CVEs retrieved.")
    return cves

if __name__ == "__main__":
    main()
