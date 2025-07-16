#!/usr/bin/env python3
"""
Local test script for database operations
Tests CVE processing and database insertion functionality
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from azure_db import get_database, CVEDatabase
from mainv3 import parse_cvss_metrics, parse_cwe_categories, mark_cve_as_processed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_mock_cve_object(cve_id: str = "CVE-2024-TEST") -> Mock:
    """Create a mock CVE object for testing"""
    mock_cve = Mock()
    mock_cve.id = cve_id
    mock_cve.published = datetime.utcnow() - timedelta(days=1)
    mock_cve.lastModified = datetime.utcnow()
    
    # Mock descriptions
    mock_desc = Mock()
    mock_desc.value = "This is a test CVE vulnerability description for testing purposes."
    mock_cve.descriptions = [mock_desc]
    
    # Mock references
    mock_ref1 = Mock()
    mock_ref1.url = "https://example.com/vuln1"
    mock_ref2 = Mock()
    mock_ref2.url = "https://example.com/vuln2"
    mock_cve.references = [mock_ref1, mock_ref2]
    
    # Mock CVSS metrics
    mock_cvss_data = Mock()
    mock_cvss_data.baseScore = 7.5
    mock_cvss_data.vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    mock_cvss_data.baseSeverity = "HIGH"
    
    mock_cvss_metric = Mock()
    mock_cvss_metric.cvssData = mock_cvss_data
    
    mock_metric = Mock()
    mock_metric.cvssMetricV31 = [mock_cvss_metric]
    mock_metric.cvssMetricV30 = None
    mock_metric.cvssMetricV2 = None
    
    mock_cve.metrics = [mock_metric]
    
    # Mock CWE data
    mock_weakness_desc = Mock()
    mock_weakness_desc.value = "CWE-79"
    
    mock_weakness = Mock()
    mock_weakness.description = [mock_weakness_desc]
    
    mock_cve_data = Mock()
    mock_cve_data.weaknesses = [mock_weakness]
    
    mock_cve.cve = mock_cve_data
    
    return mock_cve

def test_database_connection():
    """Test basic database connection"""
    print("\n=== Testing Database Connection ===")
    
    try:
        db = get_database()
        logger.info("✓ Database connection successful")
        
        # Test basic query
        result = db.db.execute_query("SELECT GETUTCDATE() as current_time")
        logger.info(f"✓ Database query successful: {result[0]['current_time']}")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Database connection failed: {e}")
        return False

def test_cvss_parsing():
    """Test CVSS metrics parsing"""
    print("\n=== Testing CVSS Parsing ===")
    
    try:
        mock_cve = create_mock_cve_object()
        cvss_data = parse_cvss_metrics(mock_cve.metrics)
        
        expected_data = {
            'score': 7.5,
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'severity': 'HIGH'
        }
        
        assert cvss_data == expected_data, f"Expected {expected_data}, got {cvss_data}"
        logger.info("✓ CVSS parsing successful")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ CVSS parsing failed: {e}")
        return False

def test_cwe_parsing():
    """Test CWE categories parsing"""
    print("\n=== Testing CWE Parsing ===")
    
    try:
        mock_cve = create_mock_cve_object()
        cwe_categories = parse_cwe_categories(mock_cve.cve)
        
        expected_categories = ['CWE-79']
        
        assert cwe_categories == expected_categories, f"Expected {expected_categories}, got {cwe_categories}"
        logger.info("✓ CWE parsing successful")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ CWE parsing failed: {e}")
        return False

def test_cve_processing():
    """Test complete CVE processing and database insertion"""
    print("\n=== Testing CVE Processing ===")
    
    try:
        db = get_database()
        test_cve_id = f"CVE-2024-TEST-{int(datetime.utcnow().timestamp())}"
        
        # Create mock CVE object
        mock_cve = create_mock_cve_object(test_cve_id)
        
        # Check if CVE is already processed (should be False)
        is_processed_before = db.is_cve_processed(test_cve_id)
        assert not is_processed_before, f"CVE {test_cve_id} should not be processed yet"
        logger.info(f"✓ CVE {test_cve_id} confirmed as not processed")
        
        # Process the CVE
        success = mark_cve_as_processed(test_cve_id, mock_cve)
        assert success, f"Failed to process CVE {test_cve_id}"
        logger.info(f"✓ CVE {test_cve_id} processed successfully")
        
        # Check if CVE is now processed (should be True)
        is_processed_after = db.is_cve_processed(test_cve_id)
        assert is_processed_after, f"CVE {test_cve_id} should be processed now"
        logger.info(f"✓ CVE {test_cve_id} confirmed as processed")
        
        # Verify data was inserted correctly
        cve_data = db.db.execute_query(
            "SELECT * FROM cve_entries WHERE cve_id = ?", 
            (test_cve_id,)
        )
        
        assert len(cve_data) == 1, f"Expected 1 CVE record, got {len(cve_data)}"
        
        cve_record = cve_data[0]
        assert cve_record['cve_id'] == test_cve_id
        assert cve_record['cvss_score'] == 7.5
        assert cve_record['cvss_severity'] == 'HIGH'
        assert 'This is a test CVE vulnerability' in cve_record['description']
        
        # Parse JSON fields
        cwe_categories = json.loads(cve_record['cwe_categories'])
        reference_urls = json.loads(cve_record['reference_urls'])
        
        assert cwe_categories == ['CWE-79']
        assert len(reference_urls) == 2
        assert 'https://example.com/vuln1' in reference_urls
        
        logger.info("✓ CVE data verification successful")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ CVE processing failed: {e}")
        return False

def test_data_retrieval():
    """Test data retrieval functions"""
    print("\n=== Testing Data Retrieval ===")
    
    try:
        db = get_database()
        
        # Test recent CVEs retrieval
        recent_cves = db.get_recent_cves(days=7)
        logger.info(f"✓ Found {len(recent_cves)} recent CVEs")
        
        # Test config operations
        test_key = "test_config_key"
        test_value = "test_config_value"
        
        db.set_config_value(test_key, test_value, "Test configuration")
        retrieved_value = db.get_config_value(test_key)
        
        assert retrieved_value == test_value, f"Expected {test_value}, got {retrieved_value}"
        logger.info("✓ Config operations successful")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Data retrieval failed: {e}")
        return False

def test_error_handling():
    """Test error handling scenarios"""
    print("\n=== Testing Error Handling ===")
    
    try:
        db = get_database()
        
        # Test with invalid CVE data
        invalid_cve_data = {
            'cve_id': None,  # Invalid - should cause error
            'description': 'Test description',
            'publication_date': datetime.utcnow(),
            'modified_date': datetime.utcnow()
        }
        
        success = db.insert_cve_entry(invalid_cve_data)
        assert not success, "Expected insertion to fail with invalid data"
        logger.info("✓ Error handling for invalid data successful")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Error handling test failed: {e}")
        return False

def run_all_tests():
    """Run all database tests"""
    print("=== DATABASE OPERATIONS TEST SUITE ===")
    
    tests = [
        ("Database Connection", test_database_connection),
        ("CVSS Parsing", test_cvss_parsing),
        ("CWE Parsing", test_cwe_parsing),
        ("CVE Processing", test_cve_processing),
        ("Data Retrieval", test_data_retrieval),
        ("Error Handling", test_error_handling)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                logger.info(f"✓ {test_name} - PASSED")
            else:
                failed += 1
                logger.error(f"✗ {test_name} - FAILED")
        except Exception as e:
            failed += 1
            logger.error(f"✗ {test_name} - FAILED: {e}")
    
    print(f"\n=== TEST RESULTS ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")
    
    if failed == 0:
        print("🎉 All tests passed!")
        return True
    else:
        print("❌ Some tests failed. Please check the logs above.")
        return False

if __name__ == "__main__":
    # Check if we have required environment variables
    missing_vars = []
    
    # Check NVD API key
    if not os.environ.get("NVD_API_KEY"):
        missing_vars.append("NVD_API_KEY")
    
    # Check Azure SQL connection parameters
    if not os.environ.get("AZURE_SQL_CONNECTION_STRING"):
        # Check for individual components
        server = os.environ.get("AZURE_SQL_SERVER")
        database = os.environ.get("AZURE_SQL_DATABASE")
        
        if not all([server, database]):
            missing_vars.append("AZURE_SQL_SERVER and AZURE_SQL_DATABASE (minimum for managed identity)")
        else:
            # Check authentication method
            use_managed_identity = os.environ.get("USE_MANAGED_IDENTITY", "false").lower() == "true"
            username = os.environ.get("AZURE_SQL_USERNAME")
            password = os.environ.get("AZURE_SQL_PASSWORD")
            
            if not use_managed_identity and not (username and password):
                print("ℹ️  Authentication method not specified. Will attempt managed identity authentication.")
                print("   To use username/password auth, set AZURE_SQL_USERNAME and AZURE_SQL_PASSWORD")
                print("   To explicitly use managed identity, set USE_MANAGED_IDENTITY=true")
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these environment variables and try again.")
        sys.exit(1)
    
    success = run_all_tests()
    sys.exit(0 if success else 1)