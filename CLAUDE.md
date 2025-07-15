# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **cybersecurity automation system** called "Kryptos" that processes CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD) and publishes automated reports. **This version has been modernized to use Azure SQL Database** instead of the legacy SQLite implementation.

## Core Architecture

### Script-Based Microservices Pattern
The system uses independent Python scripts that communicate through a unified Azure SQL database:

- **Data Ingestion**: `mainv3.py`, `nvdapi.py`, `kevimport.py`
- **Processing Engine**: `soccav5.py` (AI-powered CVE analysis)
- **Content Publishing**: `webgen.py` (WordPress automation)  
- **Reporting**: `hourlyreportgen.py`
- **Database Module**: `azure_db.py` (unified database access layer)

### Database Architecture
**Single Azure SQL Database** with properly normalized tables:
- `cve_entries` - CVE records with metadata and CVSS scores
- `cve_reports` - AI-generated vulnerability analysis reports
- `kev_entries` - CISA Known Exploited Vulnerabilities data
- `wordpress_posts` - WordPress publishing status tracking
- `processing_log` - Audit trail of all operations
- `system_config` - Application configuration storage

## Required Environment Variables

### Azure SQL Database Connection
**Option 1 - Connection String:**
```bash
export AZURE_SQL_CONNECTION_STRING="Server=tcp:yourserver.database.windows.net,1433;Database=yourdatabase;User ID=yourusername;Password=yourpassword;Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
```

**Option 2 - Individual Parameters:**
```bash
export AZURE_SQL_SERVER="yourserver.database.windows.net"
export AZURE_SQL_DATABASE="yourdatabase" 
export AZURE_SQL_USERNAME="yourusername"
export AZURE_SQL_PASSWORD="yourpassword"
```

### API Keys
```bash
export NVD_API_KEY="your-nvd-api-key-here"
export OPENAI_API_KEY="your-openai-api-key-here"
export GITHUB_TOKEN="your-github-token-here"
export HUGGINGFACE_TOKEN="your-huggingface-token-here"
```

### WordPress Integration
```bash
export WORDPRESS_USERNAME="your-wordpress-username"
export WORDPRESS_PASSWORD="your-wordpress-app-password"
```

## Installation and Setup

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Initialize Azure SQL Database
```bash
# Run the schema creation script in your Azure SQL database
# Execute: azure_sql_schema.sql
```

### Migrate Existing Data (if needed)
```bash
python migrate_to_azure.py
```

## Common Commands

### Running the Main Application
```bash
python mainv3.py
```

### Processing Specific CVE Data
```bash
python importingsinglecve.py      # Single CVE processing
python importingoldcve.py         # Historical CVE import
python importingkevdata.py        # CISA KEV data import
```

### Content Generation and Publishing
```bash
python soccav5.py                 # Run AI-powered CVE analysis
python webgen.py                  # Generate WordPress content  
python hourlyreportgen.py         # Generate automated reports
```

### Database Operations
```bash
python modifyingdb.py             # Database utilities
python addKEVwarntoPosts.py       # Add KEV warnings to posts
```

## Key Dependencies

All dependencies are managed in `requirements.txt`:
- `pyodbc>=4.0.35` - Azure SQL Server connectivity
- `nvdlib>=0.7.3` - NVD API integration
- `openai>=1.3.0` - AI analysis capabilities
- `requests>=2.31.0` - HTTP requests
- `beautifulsoup4>=4.12.0` - Web content extraction
- `readability>=0.3.1` - Content parsing
- `tiktoken>=0.5.0` - Token counting

## Database Access Patterns

### Using the Database Module
```python
from azure_db import get_database

# Get database instance
db = get_database()

# Check if CVE exists
if db.is_cve_processed('CVE-2024-12345'):
    print("CVE already processed")

# Insert CVE entry
cve_data = {
    'cve_id': 'CVE-2024-12345',
    'description': 'Vulnerability description',
    'cvss_score': 7.5,
    # ... other fields
}
db.insert_cve_entry(cve_data)

# Get recent CVEs
recent_cves = db.get_recent_cves(days=7)
```

### Raw SQL Queries
```python
# Execute SELECT query
results = db.db.execute_query("SELECT * FROM cve_entries WHERE cvss_score > ?", (8.0,))

# Execute INSERT/UPDATE
rows_affected = db.db.execute_non_query("UPDATE cve_entries SET is_kev = 1 WHERE cve_id = ?", ('CVE-2024-12345',))
```

## API Integration Points

- **NVD API**: Rate-limited CVE data fetching with `nvdlib`
- **OpenAI API**: AI-powered vulnerability analysis and categorization  
- **WordPress REST API**: Automated content publishing to socca.tech
- **CISA KEV API**: Known exploited vulnerabilities tracking

## Database Schema Highlights

### Normalized Design
- **Foreign key relationships** between tables
- **Proper data types** (DATETIME2, DECIMAL, NVARCHAR)
- **Indexes** for performance on common queries
- **Triggers** for automatic timestamp updates

### Built-in Views
- `vw_kev_cves` - KEV CVEs with full details
- `vw_recent_cve_reports` - Recent CVEs with reports

### Configuration Management
- System settings stored in `system_config` table
- Configurable polling intervals, API limits, etc.
- Persistent state tracking (last sync times)

## Development Notes

- **Unified database access** through `azure_db.py` module
- **Proper logging** throughout all modules
- **Error handling** with transaction rollback
- **Type hints** and documentation for all functions
- **Backward compatibility** maintained for legacy function calls
- **Migration tools** for transitioning from SQLite