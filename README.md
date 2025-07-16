# CVE Data Processor - Azure Functions

## Overview

Automated CVE (Common Vulnerabilities and Exposures) data processing system deployed as Azure Functions with timer-based execution. Processes CVE data from the National Vulnerability Database (NVD) and stores it in Azure SQL Database.

## Architecture

**Azure Functions Timer-Triggered Microservice**
- Executes every 5 minutes via timer trigger
- Polls NVD API for new CVE data
- Processes and stores CVE information in Azure SQL Database
- Comprehensive structured logging for monitoring

## Core Components

- `CVEProcessor/__init__.py`: Azure Function entry point with timer trigger
- `CVEProcessor/function.json`: Function binding configuration (5-minute schedule)
- `mainv3.py`: Core CVE processing logic and NVD API integration
- `azure_db.py`: Azure SQL database access layer
- `host.json`: Azure Functions runtime configuration
- `azure_sql_schema.sql`: Database schema definition

## Environment Setup

### Required Environment Variables

#### Azure SQL Database Connection
```bash
export AZURE_SQL_CONNECTION_STRING="Server=tcp:yourserver.database.windows.net,1433;Database=yourdatabase;User ID=yourusername;Password=yourpassword;Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
```

#### API Keys
```bash
export NVD_API_KEY="your-nvd-api-key-here"
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Install Azure Functions Core Tools
npm install -g azure-functions-core-tools@4 --unsafe-perm true

# Run locally
func start
```

### Azure Functions Deployment

1. **Create Azure Function App**
   - Runtime: Python 3.9+
   - Plan: Consumption or Premium
   - Storage Account required

2. **Configure Environment Variables**
   - Set all required environment variables in Function App settings
   - Ensure Azure SQL Database is accessible

3. **Deploy Function**
   ```bash
   # Using Azure Functions Core Tools
   func azure functionapp publish <function-app-name>
   
   # Or using Azure CLI
   az functionapp deployment source config-zip \
     --resource-group <resource-group> \
     --name <function-app-name> \
     --src <zip-file>
   ```

4. **Verify Deployment**
   - Check Function execution logs in Azure Portal
   - Monitor timer trigger execution (every 5 minutes)
   - Verify CVE data processing in Azure SQL Database

## Function Execution Flow

1. **Timer Trigger** - Executes every 5 minutes
2. **NVD API Polling** - Fetches new CVEs since last sync
3. **Data Processing** - Parses CVE data (CVSS scores, CWE categories, references)
4. **Database Storage** - Stores processed CVE data in Azure SQL
5. **Logging** - Structured JSON logging for monitoring and debugging

## Database Architecture

Azure SQL Database with normalized tables:
- `cve_entries` - CVE records with metadata, CVSS scores, and classifications
- `cve_reports` - AI-generated vulnerability analysis reports
- `kev_entries` - CISA Known Exploited Vulnerabilities data
- `wordpress_posts` - WordPress publishing status tracking
- `processing_log` - Audit trail of all operations
- `system_config` - Application configuration storage

## Monitoring and Logging

### Structured Logging Events
- `function_start` - Function execution begins
- `cvs_processing_start` - CVE processing starts
- `cvs_processing_success/failed` - Processing results
- `cvs_processing_exception` - Detailed error information
- `function_end` - Execution summary with metrics
- `performance_warning` - Long-running executions (>5min)
- `timer_past_due` - Schedule adherence monitoring

### Application Insights Integration
- Dependency tracking enabled
- Performance counters collection
- Custom telemetry for CVE processing metrics
- Health monitoring with automatic recovery

## Features

- **Automated CVE Processing** - Timer-driven execution every 5 minutes
- **NVD API Integration** - Official API with rate limiting and error handling
- **Azure SQL Database** - Scalable, managed database with proper schema
- **Comprehensive Logging** - Structured JSON logging for monitoring
- **Performance Monitoring** - Execution metrics and performance warnings
- **Error Handling** - Robust exception handling with detailed error tracking
- **Configuration Management** - Database-stored configuration with defaults
