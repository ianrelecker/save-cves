"""
Azure SQL Database Connection Module
Provides unified database access for the CVE processing application
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

try:
    import pyodbc
except ImportError:
    raise ImportError(
        "pyodbc is required for Azure SQL Server connectivity. "
        "Install it with: pip install pyodbc"
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AzureSQLConnection:
    """Azure SQL Database connection and operations manager"""
    
    def __init__(self):
        self.connection_string = self._build_connection_string()
        self._test_connection()
    
    def _build_connection_string(self) -> str:
        """Build Azure SQL connection string from environment variables"""
        
        # Option 1: Use full connection string
        conn_str = os.environ.get("AZURE_SQL_CONNECTION_STRING")
        if conn_str:
            return conn_str
        
        # Option 2: Build from individual components
        server = os.environ.get("AZURE_SQL_SERVER")
        database = os.environ.get("AZURE_SQL_DATABASE")
        
        if not all([server, database]):
            raise ValueError(
                "Azure SQL connection parameters not found. Please set either:\n"
                "1. AZURE_SQL_CONNECTION_STRING (full connection string), or\n"
                "2. AZURE_SQL_SERVER and AZURE_SQL_DATABASE (for managed identity), or\n"
                "3. AZURE_SQL_SERVER, AZURE_SQL_DATABASE, AZURE_SQL_USERNAME, AZURE_SQL_PASSWORD"
            )
        
        # Check if we should use managed identity
        use_managed_identity = os.environ.get("USE_MANAGED_IDENTITY", "false").lower() == "true"
        username = os.environ.get("AZURE_SQL_USERNAME")
        password = os.environ.get("AZURE_SQL_PASSWORD")
        
        if use_managed_identity or (not username and not password):
            # Use managed identity authentication
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE={database};"
                f"Authentication=ActiveDirectoryMsi;"
                f"Encrypt=yes;"
                f"TrustServerCertificate=no;"
                f"Connection Timeout=30;"
            )
            logger.info("Using managed identity authentication for Azure SQL")
        else:
            # Use username/password authentication
            if not all([username, password]):
                raise ValueError(
                    "For username/password authentication, both AZURE_SQL_USERNAME and AZURE_SQL_PASSWORD must be set"
                )
            
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE={database};"
                f"UID={username};"
                f"PWD={password};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=no;"
                f"Connection Timeout=30;"
            )
            logger.info("Using username/password authentication for Azure SQL")
        
        return conn_str
    
    def _test_connection(self):
        """Test the database connection"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
            logger.info("Azure SQL database connection successful")
        except Exception as e:
            logger.error(f"Failed to connect to Azure SQL database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with automatic cleanup"""
        conn = None
        try:
            conn = pyodbc.connect(self.connection_string)
            conn.autocommit = False
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database operation failed: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[Dict]:
        """Execute a SELECT query and return results as list of dictionaries"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Get column names
            columns = [column[0] for column in cursor.description]
            
            # Fetch all rows and convert to dictionaries
            rows = cursor.fetchall()
            results = [dict(zip(columns, row)) for row in rows]
            
            return results
    
    def execute_non_query(self, query: str, params: Optional[Tuple] = None) -> int:
        """Execute INSERT, UPDATE, DELETE query and return rows affected"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            rows_affected = cursor.rowcount
            conn.commit()
            
            return rows_affected
    
    def execute_many(self, query: str, params_list: List[Tuple]) -> int:
        """Execute the same query with multiple parameter sets"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            rows_affected = cursor.rowcount
            conn.commit()
            return rows_affected


class CVEDatabase:
    """High-level CVE database operations"""
    
    def __init__(self):
        self.db = AzureSQLConnection()
    
    # ==========================================
    # CVE Entries Operations
    # ==========================================
    
    def is_cve_processed(self, cve_id: str) -> bool:
        """Check if a CVE has already been processed"""
        query = "SELECT 1 FROM cve_entries WHERE cve_id = ?"
        results = self.db.execute_query(query, (cve_id,))
        return len(results) > 0
    
    def insert_cve_entry(self, cve_data: Dict[str, Any]) -> bool:
        """Insert a new CVE entry"""
        query = """
        INSERT INTO cve_entries (
            cve_id, description, publication_date, modified_date,
            cvss_score, cvss_vector, cvss_severity, cwe_categories,
            reference_urls, is_kev
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            cve_data.get('cve_id'),
            cve_data.get('description'),
            cve_data.get('publication_date'),
            cve_data.get('modified_date'),
            cve_data.get('cvss_score'),
            cve_data.get('cvss_vector'),
            cve_data.get('cvss_severity'),
            json.dumps(cve_data.get('cwe_categories', [])),
            json.dumps(cve_data.get('reference_urls', [])),
            cve_data.get('is_kev', False)
        )
        
        try:
            self.db.execute_non_query(query, params)
            self._log_operation(cve_data.get('cve_id'), 'INSERT', 'SUCCESS')
            return True
        except Exception as e:
            self._log_operation(cve_data.get('cve_id'), 'INSERT', 'FAILED', str(e))
            logger.error(f"Failed to insert CVE {cve_data.get('cve_id')}: {e}")
            return False
    
    def get_unprocessed_cves(self, limit: int = 100) -> List[Dict]:
        """Get CVEs that don't have reports yet"""
        query = """
        SELECT c.* FROM cve_entries c
        LEFT JOIN cve_reports r ON c.cve_id = r.cve_id
        WHERE r.cve_id IS NULL
        ORDER BY c.publication_date DESC
        OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY
        """
        return self.db.execute_query(query, (limit,))
    
    # ==========================================
    # CVE Reports Operations
    # ==========================================
    
    def insert_cve_report(self, cve_id: str, report_content: str, 
                         ai_analysis: Optional[str] = None,
                         severity_assessment: Optional[str] = None,
                         exploitation_likelihood: Optional[str] = None) -> bool:
        """Insert a CVE analysis report"""
        query = """
        INSERT INTO cve_reports (
            cve_id, report_content, ai_analysis, 
            severity_assessment, exploitation_likelihood
        ) VALUES (?, ?, ?, ?, ?)
        """
        
        params = (cve_id, report_content, ai_analysis, 
                 severity_assessment, exploitation_likelihood)
        
        try:
            self.db.execute_non_query(query, params)
            self._log_operation(cve_id, 'ANALYSIS', 'SUCCESS')
            return True
        except Exception as e:
            self._log_operation(cve_id, 'ANALYSIS', 'FAILED', str(e))
            logger.error(f"Failed to insert report for CVE {cve_id}: {e}")
            return False
    
    def get_cve_report(self, cve_id: str) -> Optional[Dict]:
        """Get the latest report for a CVE"""
        query = """
        SELECT * FROM cve_reports 
        WHERE cve_id = ? 
        ORDER BY created_at DESC
        """
        results = self.db.execute_query(query, (cve_id,))
        return results[0] if results else None
    
    # ==========================================
    # KEV Operations
    # ==========================================
    
    def insert_kev_entry(self, kev_data: Dict[str, Any]) -> bool:
        """Insert a KEV entry"""
        query = """
        INSERT INTO kev_entries (
            cve_id, vendor_name, product_name, vulnerability_name,
            kev_description, due_date, date_added
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            kev_data.get('cve_id'),
            kev_data.get('vendor_name'),
            kev_data.get('product_name'),
            kev_data.get('vulnerability_name'),
            kev_data.get('description'),
            kev_data.get('due_date'),
            kev_data.get('date_added')
        )
        
        try:
            self.db.execute_non_query(query, params)
            # Update CVE entry to mark as KEV
            self.db.execute_non_query(
                "UPDATE cve_entries SET is_kev = 1 WHERE cve_id = ?",
                (kev_data.get('cve_id'),)
            )
            return True
        except Exception as e:
            logger.error(f"Failed to insert KEV entry for {kev_data.get('cve_id')}: {e}")
            return False
    
    def get_kev_cves(self) -> List[Dict]:
        """Get all KEV CVEs with details"""
        query = "SELECT * FROM vw_kev_cves ORDER BY due_date ASC"
        return self.db.execute_query(query)
    
    # ==========================================
    # WordPress Posts Operations
    # ==========================================
    
    def insert_wordpress_post(self, cve_id: str, post_title: str,
                             wordpress_post_id: Optional[int] = None,
                             post_status: str = 'draft',
                             post_url: Optional[str] = None) -> bool:
        """Insert a WordPress post record"""
        query = """
        INSERT INTO wordpress_posts (
            cve_id, wordpress_post_id, post_title, post_status, post_url
        ) VALUES (?, ?, ?, ?, ?)
        """
        
        params = (cve_id, wordpress_post_id, post_title, post_status, post_url)
        
        try:
            self.db.execute_non_query(query, params)
            self._log_operation(cve_id, 'PUBLISH', 'SUCCESS')
            return True
        except Exception as e:
            self._log_operation(cve_id, 'PUBLISH', 'FAILED', str(e))
            logger.error(f"Failed to insert WordPress post for CVE {cve_id}: {e}")
            return False
    
    def is_post_published(self, cve_id: str) -> bool:
        """Check if a CVE has been published to WordPress"""
        query = "SELECT 1 FROM wordpress_posts WHERE cve_id = ?"
        results = self.db.execute_query(query, (cve_id,))
        return len(results) > 0
    
    # ==========================================
    # Utility Methods
    # ==========================================
    
    def get_recent_cves(self, days: int = 7) -> List[Dict]:
        """Get CVEs published in the last N days"""
        query = """
        SELECT * FROM cve_entries 
        WHERE publication_date >= DATEADD(day, ?, GETUTCDATE())
        ORDER BY publication_date DESC
        """
        return self.db.execute_query(query, (-days,))
    
    def get_config_value(self, key: str) -> Optional[str]:
        """Get a configuration value"""
        query = "SELECT config_value FROM system_config WHERE config_key = ?"
        results = self.db.execute_query(query, (key,))
        return results[0]['config_value'] if results else None
    
    def set_config_value(self, key: str, value: str, description: Optional[str] = None):
        """Set a configuration value"""
        # Try update first
        update_query = "UPDATE system_config SET config_value = ?, updated_at = GETUTCDATE() WHERE config_key = ?"
        rows_affected = self.db.execute_non_query(update_query, (value, key))
        
        # If no rows updated, insert new
        if rows_affected == 0:
            insert_query = "INSERT INTO system_config (config_key, config_value, description) VALUES (?, ?, ?)"
            self.db.execute_non_query(insert_query, (key, value, description))
    
    def _log_operation(self, cve_id: str, operation_type: str, status: str, 
                      error_message: Optional[str] = None):
        """Log an operation to the processing log"""
        query = """
        INSERT INTO processing_log (cve_id, operation_type, operation_status, error_message)
        VALUES (?, ?, ?, ?)
        """
        try:
            self.db.execute_non_query(query, (cve_id, operation_type, status, error_message))
        except Exception as e:
            # Don't fail the main operation if logging fails
            logger.warning(f"Failed to log operation: {e}")


# Global database instance
db = None

def get_database() -> CVEDatabase:
    """Get the global database instance"""
    global db
    if db is None:
        db = CVEDatabase()
    return db