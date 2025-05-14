# Kryptos Web Application (Legacy Version)

> **IMPORTANT NOTE**: This is a very old version. A new version called **CVE-Processor** exists which replaces this codebase with significant improvements. The SQL database setup in this legacy version is suboptimal and not recommended for production use.

## Main Application

The main application file is `mainv3.py`, which is the latest version of the code. This file handles fetching and processing CVE entries from the NVD API.

## Environment Setup

After removing hardcoded API keys for security reasons, you need to set up the following environment variables:

### Required Environment Variables

- `NVD_API_KEY`: National Vulnerability Database API key
- `OPENAI_API_KEY`: OpenAI API key for AI features
- `GITHUB_TOKEN`: GitHub token for GitHub integration
- `HUGGINGFACE_TOKEN`: Hugging Face token for AI model access

### Setting Environment Variables

#### On Unix/Linux/macOS:

```bash
export NVD_API_KEY="your-nvd-api-key-here"
export OPENAI_API_KEY="your-openai-api-key-here"
export GITHUB_TOKEN="your-github-token-here"
export HUGGINGFACE_TOKEN="your-huggingface-token-here"
```

#### On Windows:

```cmd
setx NVD_API_KEY "your-nvd-api-key-here"
setx OPENAI_API_KEY "your-openai-api-key-here"
setx GITHUB_TOKEN "your-github-token-here"
setx HUGGINGFACE_TOKEN "your-huggingface-token-here"
```

## Files Organization

- `mainv3.py`: Main application file
- `soccav5.py`: Current SOCCA analysis version
- `nvdapi.py`: NVD API integration
- `backup/`: Contains older versions and test files
- `files/`: Contains configuration files and data

## Database Information

The database setup in this application has several limitations that have been addressed in the newer CVE-Processor version:

- Legacy database structure with suboptimal design
- Simple SQLite implementation with basic queries
- No complex relationships between tables
- Limited error handling for database operations

The newer CVE-Processor version uses a more robust database design with proper schema definitions, consistent table structures, appropriate indexing, and better transaction management.

## Database Files

This project uses several SQLite database files that are already initialized with appropriate schemas:

- `processed_cves.db`: Stores processed CVE entries
- `cve_reports.db`: Contains detailed CVE reports
- `posts.db`: Manages post data 
- `kev_data.db`: Stores CISA Known Exploited Vulnerabilities (KEV) data

If you need to reset these databases, simply delete the files and they will be recreated with empty schemas when the application runs.
