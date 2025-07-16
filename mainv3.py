import time
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

import nvdlib

from azure_db import get_database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load API key from environment variable
API_KEY = os.environ.get("NVD_API_KEY")
if not API_KEY:
    logger.error("NVD_API_KEY environment variable is required")
    exit(1)

# Initialize database connection
db = get_database()


def parse_cvss_metrics(metrics) -> Dict[str, Any]:
    """Parse CVSS metrics from nvdlib CVE object"""
    cvss_data = {
        'score': None,
        'vector': None,
        'severity': None
    }
    
    if not metrics:
        return cvss_data
    
    # Try to extract CVSS v3.x first, then v2
    for metric in metrics:
        if hasattr(metric, 'cvssMetricV31') and metric.cvssMetricV31:
            cvss = metric.cvssMetricV31[0].cvssData
            cvss_data['score'] = cvss.baseScore
            cvss_data['vector'] = cvss.vectorString
            cvss_data['severity'] = cvss.baseSeverity
            break
        elif hasattr(metric, 'cvssMetricV30') and metric.cvssMetricV30:
            cvss = metric.cvssMetricV30[0].cvssData
            cvss_data['score'] = cvss.baseScore
            cvss_data['vector'] = cvss.vectorString
            cvss_data['severity'] = cvss.baseSeverity
            break
        elif hasattr(metric, 'cvssMetricV2') and metric.cvssMetricV2:
            cvss = metric.cvssMetricV2[0].cvssData
            cvss_data['score'] = cvss.baseScore
            cvss_data['vector'] = cvss.vectorString
            cvss_data['severity'] = 'UNKNOWN'  # v2 doesn't have severity
            break
    
    return cvss_data


def parse_cwe_categories(cve_data) -> List[str]:
    """Extract CWE categories from CVE data"""
    cwe_list = []
    
    try:
        if hasattr(cve_data, 'weaknesses') and cve_data.weaknesses:
            for weakness in cve_data.weaknesses:
                if hasattr(weakness, 'description'):
                    for desc in weakness.description:
                        if desc.value.startswith('CWE-'):
                            cwe_list.append(desc.value)
    except Exception as e:
        logger.warning(f"Failed to parse CWE categories: {e}")
    
    return cwe_list


def mark_cve_as_processed(cve_id: str, cve_obj) -> bool:
    """Process and store a CVE entry in Azure SQL"""
    try:
        # Extract description
        description = ""
        if cve_obj.descriptions:
            description = cve_obj.descriptions[0].value
        
        # Extract reference URLs
        reference_urls = []
        if cve_obj.references:
            reference_urls = [ref.url for ref in cve_obj.references]
        
        # Parse CVSS metrics
        cvss_data = parse_cvss_metrics(cve_obj.metrics)
        
        # Parse CWE categories
        cwe_categories = parse_cwe_categories(cve_obj.cve)
        
        # Prepare CVE data for database
        cve_data = {
            'cve_id': cve_id,
            'description': description,
            'publication_date': cve_obj.published,
            'modified_date': cve_obj.lastModified,
            'cvss_score': cvss_data['score'],
            'cvss_vector': cvss_data['vector'],
            'cvss_severity': cvss_data['severity'],
            'cwe_categories': cwe_categories,
            'reference_urls': reference_urls,
            'is_kev': False  # Will be updated by KEV import process
        }
        
        # Insert into database
        success = db.insert_cve_entry(cve_data)
        
        if success:
            logger.info(f"Successfully processed CVE {cve_id}")
        else:
            logger.error(f"Failed to process CVE {cve_id}")
        
        return success
        
    except Exception as e:
        logger.error(f"Error processing CVE {cve_id}: {e}")
        return False


def get_last_sync_time() -> datetime:
    """Get the last NVD synchronization time from database"""
    last_sync = db.get_config_value('last_nvd_sync')
    if last_sync:
        return datetime.fromisoformat(last_sync)
    else:
        # Default to 1 day ago if no previous sync
        return datetime.utcnow() - timedelta(days=1)


def update_last_sync_time():
    """Update the last NVD synchronization time in database"""
    current_time = datetime.utcnow().isoformat()
    db.set_config_value('last_nvd_sync', current_time, 'Last successful NVD API synchronization')


def poll_nvd() -> bool:
    """Poll NVD API for new vulnerabilities and process them"""
    try:
        # Get the time range for polling
        start_time = get_last_sync_time()
        end_time = datetime.utcnow()
        
        logger.info(f"Polling NVD from {start_time} to {end_time}")
        
        # Search for CVEs in the time range
        cves = nvdlib.searchCVE(
            pubStartDate=start_time, 
            pubEndDate=end_time, 
            key=API_KEY
        )
        
        logger.info(f"Found {len(cves)} CVEs from NVD API")
        
        processed_count = 0
        
        # Process only unprocessed CVEs
        for cve in cves:
            if not db.is_cve_processed(cve.id):
                logger.info(f"Processing new CVE: {cve.id}")
                
                # Process and store the CVE
                success = mark_cve_as_processed(cve.id, cve)
                
                if success:
                    processed_count += 1
                    logger.info(f"Successfully processed and stored CVE {cve.id}")
                else:
                    logger.error(f"Failed to process CVE {cve.id}")
            else:
                logger.debug(f"CVE {cve.id} already processed, skipping")
        
        logger.info(f"Processed {processed_count} new CVEs")
        
        # Update last sync time on successful completion
        update_last_sync_time()
        
        return True
        
    except Exception as e:
        logger.error(f"NVD API polling failed: {e}")
        return False


def main():
    """Main application loop"""
    logger.info("Starting CVE Processing Application")
    logger.info("Press Ctrl+C to stop")
    
    try:
        while True:
            logger.info("Starting NVD polling cycle")
            
            success = poll_nvd()
            
            if success:
                logger.info("NVD polling completed successfully")
            else:
                logger.error("NVD polling failed, will retry in next cycle")
            
            # Wait before next poll (configurable via database)
            sleep_duration = int(db.get_config_value('polling_interval_seconds') or '300')  # Default 5 minutes
            logger.info(f"Sleeping for {sleep_duration} seconds")
            time.sleep(sleep_duration)
            
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise
    finally:
        logger.info("CVE Processing Application shutting down")


if __name__ == "__main__":
    main()
