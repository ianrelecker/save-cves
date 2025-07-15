#!/usr/bin/env python3
"""
Migration script to move data from SQLite databases to Azure SQL
"""

import os
import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from azure_db import get_database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SQLiteMigrator:
    """Migrates data from SQLite databases to Azure SQL"""
    
    def __init__(self):
        self.azure_db = get_database()
        self.migration_stats = {
            'cve_entries': 0,
            'cve_reports': 0,
            'kev_entries': 0,
            'wordpress_posts': 0,
            'errors': []
        }
    
    def check_sqlite_files(self) -> Dict[str, bool]:
        """Check which SQLite database files exist"""
        sqlite_files = {
            'processed_cves.db': os.path.exists('processed_cves.db'),
            'cve_reports.db': os.path.exists('cve_reports.db'),
            'posts.db': os.path.exists('posts.db'),
            'kev_data.db': os.path.exists('kev_data.db')
        }
        
        logger.info("SQLite database file status:")
        for db_file, exists in sqlite_files.items():
            logger.info(f"  {db_file}: {'Found' if exists else 'Not found'}")
        
        return sqlite_files
    
    def migrate_processed_cves(self) -> int:
        """Migrate data from processed_cves.db to Azure SQL cve_entries table"""
        if not os.path.exists('processed_cves.db'):
            logger.warning("processed_cves.db not found, skipping CVE entries migration")
            return 0
        
        logger.info("Starting migration of processed CVE entries...")
        
        conn = sqlite3.connect('processed_cves.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM processed_cves")
            rows = cursor.fetchall()
            
            # Get column names
            cursor.execute("PRAGMA table_info(processed_cves)")
            columns = [col[1] for col in cursor.fetchall()]
            
            migrated_count = 0
            
            for row in rows:
                try:
                    # Map SQLite row to dictionary
                    cve_data = dict(zip(columns, row))
                    
                    # Transform data for Azure SQL schema
                    azure_cve_data = self._transform_cve_data(cve_data)
                    
                    # Check if CVE already exists in Azure SQL
                    if not self.azure_db.is_cve_processed(azure_cve_data['cve_id']):
                        success = self.azure_db.insert_cve_entry(azure_cve_data)
                        if success:
                            migrated_count += 1
                        else:
                            self.migration_stats['errors'].append(f"Failed to migrate CVE {azure_cve_data['cve_id']}")
                    else:
                        logger.debug(f"CVE {azure_cve_data['cve_id']} already exists in Azure SQL")
                
                except Exception as e:
                    error_msg = f"Error migrating CVE row {row}: {e}"
                    logger.error(error_msg)
                    self.migration_stats['errors'].append(error_msg)
            
            self.migration_stats['cve_entries'] = migrated_count
            logger.info(f"Migrated {migrated_count} CVE entries to Azure SQL")
            
        except Exception as e:
            logger.error(f"Error accessing processed_cves.db: {e}")
            
        finally:
            conn.close()
        
        return migrated_count
    
    def migrate_cve_reports(self) -> int:
        """Migrate data from cve_reports.db to Azure SQL cve_reports table"""
        if not os.path.exists('cve_reports.db'):
            logger.warning("cve_reports.db not found, skipping CVE reports migration")
            return 0
        
        logger.info("Starting migration of CVE reports...")
        
        conn = sqlite3.connect('cve_reports.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM processed")
            rows = cursor.fetchall()
            
            migrated_count = 0
            
            for row in rows:
                try:
                    cve_id, report_content = row[0], row[1]
                    
                    # Check if report already exists
                    existing_report = self.azure_db.get_cve_report(cve_id)
                    if not existing_report:
                        success = self.azure_db.insert_cve_report(cve_id, report_content)
                        if success:
                            migrated_count += 1
                        else:
                            self.migration_stats['errors'].append(f"Failed to migrate report for CVE {cve_id}")
                    else:
                        logger.debug(f"Report for CVE {cve_id} already exists in Azure SQL")
                
                except Exception as e:
                    error_msg = f"Error migrating CVE report {row}: {e}"
                    logger.error(error_msg)
                    self.migration_stats['errors'].append(error_msg)
            
            self.migration_stats['cve_reports'] = migrated_count
            logger.info(f"Migrated {migrated_count} CVE reports to Azure SQL")
            
        except Exception as e:
            logger.error(f"Error accessing cve_reports.db: {e}")
            
        finally:
            conn.close()
        
        return migrated_count
    
    def migrate_kev_data(self) -> int:
        """Migrate data from kev_data.db to Azure SQL kev_entries table"""
        if not os.path.exists('kev_data.db'):
            logger.warning("kev_data.db not found, skipping KEV data migration")
            return 0
        
        logger.info("Starting migration of KEV data...")
        
        conn = sqlite3.connect('kev_data.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM kev_entries")
            rows = cursor.fetchall()
            
            # Get column names
            cursor.execute("PRAGMA table_info(kev_entries)")
            columns = [col[1] for col in cursor.fetchall()]
            
            migrated_count = 0
            
            for row in rows:
                try:
                    # Map SQLite row to dictionary
                    kev_data = dict(zip(columns, row))
                    
                    # Transform data for Azure SQL schema
                    azure_kev_data = self._transform_kev_data(kev_data)
                    
                    success = self.azure_db.insert_kev_entry(azure_kev_data)
                    if success:
                        migrated_count += 1
                    else:
                        self.migration_stats['errors'].append(f"Failed to migrate KEV entry for CVE {azure_kev_data['cve_id']}")
                
                except Exception as e:
                    error_msg = f"Error migrating KEV entry {row}: {e}"
                    logger.error(error_msg)
                    self.migration_stats['errors'].append(error_msg)
            
            self.migration_stats['kev_entries'] = migrated_count
            logger.info(f"Migrated {migrated_count} KEV entries to Azure SQL")
            
        except Exception as e:
            logger.error(f"Error accessing kev_data.db: {e}")
            
        finally:
            conn.close()
        
        return migrated_count
    
    def migrate_wordpress_posts(self) -> int:
        """Migrate data from posts.db to Azure SQL wordpress_posts table"""
        if not os.path.exists('posts.db'):
            logger.warning("posts.db not found, skipping WordPress posts migration")
            return 0
        
        logger.info("Starting migration of WordPress posts...")
        
        conn = sqlite3.connect('posts.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM posts")
            rows = cursor.fetchall()
            
            migrated_count = 0
            
            for row in rows:
                try:
                    cve_id, report_status = row[0], row[1]
                    
                    # Check if post record already exists
                    if not self.azure_db.is_post_published(cve_id):
                        # Create a basic post title from CVE ID
                        post_title = f"Vulnerability Report: {cve_id}"
                        
                        success = self.azure_db.insert_wordpress_post(
                            cve_id=cve_id,
                            post_title=post_title,
                            post_status='published' if report_status else 'draft'
                        )
                        
                        if success:
                            migrated_count += 1
                        else:
                            self.migration_stats['errors'].append(f"Failed to migrate WordPress post for CVE {cve_id}")
                    else:
                        logger.debug(f"WordPress post for CVE {cve_id} already exists in Azure SQL")
                
                except Exception as e:
                    error_msg = f"Error migrating WordPress post {row}: {e}"
                    logger.error(error_msg)
                    self.migration_stats['errors'].append(error_msg)
            
            self.migration_stats['wordpress_posts'] = migrated_count
            logger.info(f"Migrated {migrated_count} WordPress posts to Azure SQL")
            
        except Exception as e:
            logger.error(f"Error accessing posts.db: {e}")
            
        finally:
            conn.close()
        
        return migrated_count
    
    def _transform_cve_data(self, sqlite_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform SQLite CVE data to Azure SQL schema"""
        try:
            # Parse reference URLs from string representation
            reference_urls = []
            if sqlite_data.get('url'):
                try:
                    import ast
                    reference_urls = ast.literal_eval(sqlite_data['url'])
                except:
                    reference_urls = [sqlite_data['url']]  # Fallback to single URL
            
            # Parse CVSS data from string representation
            cvss_score = None
            cvss_vector = None
            cvss_severity = None
            
            if sqlite_data.get('data'):
                try:
                    # Try to extract CVSS data from the metrics string
                    data_str = str(sqlite_data['data'])
                    # This is a simplified parser - actual implementation would need to handle nvdlib metrics format
                    if 'baseScore' in data_str:
                        import re
                        score_match = re.search(r'baseScore[\'\":\\s]*([0-9.]+)', data_str)
                        if score_match:
                            cvss_score = float(score_match.group(1))
                except:
                    pass
            
            # Parse CWE categories from string representation
            cwe_categories = []
            if sqlite_data.get('cata'):
                try:
                    cata_str = str(sqlite_data['cata'])
                    import re
                    cwe_matches = re.findall(r'CWE-\d+', cata_str)
                    cwe_categories = cwe_matches
                except:
                    pass
            
            # Transform to Azure SQL schema
            return {
                'cve_id': sqlite_data['cve_id'],
                'description': sqlite_data.get('description', ''),
                'publication_date': self._parse_date(sqlite_data.get('pub')),
                'modified_date': None,  # Not available in legacy data
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'cvss_severity': cvss_severity,
                'cwe_categories': cwe_categories,
                'reference_urls': reference_urls,
                'is_kev': sqlite_data.get('kev', False)
            }
            
        except Exception as e:
            logger.error(f"Error transforming CVE data: {e}")
            raise
    
    def _transform_kev_data(self, sqlite_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform SQLite KEV data to Azure SQL schema"""
        return {
            'cve_id': sqlite_data['cve_id'],
            'vendor_name': sqlite_data.get('vendor', ''),
            'product_name': sqlite_data.get('product', ''),
            'vulnerability_name': sqlite_data.get('vulnerability_name', ''),
            'description': sqlite_data.get('description', ''),
            'due_date': self._parse_date(sqlite_data.get('due_date')),
            'date_added': datetime.utcnow().date()  # Default to current date if not available
        }
    
    def _parse_date(self, date_str: Any) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str:
            return None
        
        try:
            if isinstance(date_str, str):
                # Try common date formats
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']:
                    try:
                        return datetime.strptime(date_str, fmt)
                    except ValueError:
                        continue
            return None
        except:
            return None
    
    def run_migration(self) -> Dict[str, Any]:
        """Run the complete migration process"""
        logger.info("Starting SQLite to Azure SQL migration...")
        
        # Check available SQLite files
        sqlite_files = self.check_sqlite_files()
        
        if not any(sqlite_files.values()):
            logger.warning("No SQLite database files found. Migration aborted.")
            return self.migration_stats
        
        # Run migrations in order
        try:
            # Migrate CVE entries first (other tables reference these)
            self.migrate_processed_cves()
            
            # Migrate KEV data (updates CVE entries)
            self.migrate_kev_data()
            
            # Migrate CVE reports
            self.migrate_cve_reports()
            
            # Migrate WordPress posts
            self.migrate_wordpress_posts()
            
            logger.info("Migration completed successfully!")
            logger.info(f"Migration statistics: {self.migration_stats}")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            self.migration_stats['errors'].append(f"Migration failed: {e}")
        
        return self.migration_stats


def main():
    """Main migration script"""
    print("SQLite to Azure SQL Migration Tool")
    print("=" * 40)
    
    # Check environment variables
    required_env_vars = ['AZURE_SQL_CONNECTION_STRING']
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    
    if missing_vars and not all([
        os.environ.get('AZURE_SQL_SERVER'),
        os.environ.get('AZURE_SQL_DATABASE'),
        os.environ.get('AZURE_SQL_USERNAME'),
        os.environ.get('AZURE_SQL_PASSWORD')
    ]):
        print("ERROR: Azure SQL connection parameters not found.")
        print("Please set either:")
        print("1. AZURE_SQL_CONNECTION_STRING, or")
        print("2. AZURE_SQL_SERVER, AZURE_SQL_DATABASE, AZURE_SQL_USERNAME, AZURE_SQL_PASSWORD")
        return 1
    
    # Confirm migration
    response = input("This will migrate data from SQLite to Azure SQL. Continue? (y/N): ")
    if response.lower() != 'y':
        print("Migration cancelled.")
        return 0
    
    # Run migration
    migrator = SQLiteMigrator()
    stats = migrator.run_migration()
    
    # Display results
    print("\nMigration Results:")
    print(f"CVE Entries migrated: {stats['cve_entries']}")
    print(f"CVE Reports migrated: {stats['cve_reports']}")
    print(f"KEV Entries migrated: {stats['kev_entries']}")
    print(f"WordPress Posts migrated: {stats['wordpress_posts']}")
    
    if stats['errors']:
        print(f"\nErrors encountered: {len(stats['errors'])}")
        for error in stats['errors']:
            print(f"  - {error}")
    
    print("\nMigration completed.")
    return 0


if __name__ == "__main__":
    exit(main())