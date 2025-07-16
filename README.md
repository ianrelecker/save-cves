# CVE Data Processor API

## Overview

REST API for CVE data processing and management, built for Azure App Service deployment with Azure SQL database integration.

## Core Components

- `app.py`: Flask REST API application
- `nvdapi.py`: NVD API integration module
- `azure_db.py`: Azure SQL database access layer
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
pip install -r requirements.txt
python app.py
```

### Azure App Service Deployment

1. Create Azure App Service (Python 3.9+)
2. Configure environment variables in App Service settings
3. Deploy code via Git or ZIP deployment
4. App will auto-start using startup.sh

## API Endpoints

### Health Check
- `GET /` - Service health status

### CVE Operations
- `GET /api/cves` - List recent CVEs
  - Query params: `limit`, `offset`, `days`
- `GET /api/cves/{cve_id}` - Get specific CVE
- `GET /api/cves/search?q={query}` - Search CVEs
- `POST /api/cves/sync` - Sync new CVEs from NVD
  - Body: `{"days": 7}`
- `GET /api/cves/stats` - Get CVE statistics

### Example Usage

```bash
# Get recent CVEs
curl https://your-app.azurewebsites.net/api/cves?limit=10

# Search for specific CVE
curl https://your-app.azurewebsites.net/api/cves/CVE-2024-1234

# Sync new CVEs
curl -X POST https://your-app.azurewebsites.net/api/cves/sync \
  -H "Content-Type: application/json" \
  -d '{"days": 7}'
```

## Database Architecture

Azure SQL Database with normalized tables:
- `cve_entries` - CVE records with metadata
- `processing_log` - Audit trail
- `system_config` - Application configuration

## Features

- REST API for CVE data access
- Automated CVE synchronization
- Search and filtering capabilities
- Azure App Service ready
- CORS enabled for web clients
