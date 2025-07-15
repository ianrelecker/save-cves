-- Azure SQL Database Schema for CVE Processing Application
-- Unified database replacing 4 separate SQLite databases

-- =====================================================
-- 1. CVE Entries Table (replaces processed_cves.db)
-- =====================================================
CREATE TABLE cve_entries (
    cve_id NVARCHAR(20) PRIMARY KEY,
    description NVARTEXT,
    publication_date DATETIME2,
    modified_date DATETIME2,
    cvss_score DECIMAL(3,1),
    cvss_vector NVARCHAR(100),
    cvss_severity NVARCHAR(20),
    cwe_categories NVARCHAR(MAX), -- JSON array of CWE IDs
    reference_urls NVARCHAR(MAX), -- JSON array of URLs
    is_kev BIT DEFAULT 0,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE()
);

-- =====================================================
-- 2. CVE Reports Table (replaces cve_reports.db)
-- =====================================================
CREATE TABLE cve_reports (
    report_id INT IDENTITY(1,1) PRIMARY KEY,
    cve_id NVARCHAR(20) NOT NULL,
    report_content NVARTEXT NOT NULL,
    ai_analysis NVARTEXT,
    severity_assessment NVARCHAR(20),
    exploitation_likelihood NVARCHAR(20),
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE(),
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE CASCADE
);

-- =====================================================
-- 3. KEV Data Table (replaces kev_data.db)
-- =====================================================
CREATE TABLE kev_entries (
    kev_id INT IDENTITY(1,1) PRIMARY KEY,
    cve_id NVARCHAR(20) NOT NULL,
    vendor_name NVARCHAR(100),
    product_name NVARCHAR(200),
    vulnerability_name NVARCHAR(500),
    kev_description NVARTEXT,
    due_date DATE,
    date_added DATE,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE CASCADE
);

-- =====================================================
-- 4. WordPress Posts Table (replaces posts.db)
-- =====================================================
CREATE TABLE wordpress_posts (
    post_id INT IDENTITY(1,1) PRIMARY KEY,
    cve_id NVARCHAR(20) NOT NULL,
    wordpress_post_id INT,
    post_title NVARCHAR(300),
    post_status NVARCHAR(20) DEFAULT 'draft', -- draft, published, scheduled
    post_url NVARCHAR(500),
    published_at DATETIME2,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE(),
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE CASCADE
);

-- =====================================================
-- 5. Processing Log Table (new - for audit trail)
-- =====================================================
CREATE TABLE processing_log (
    log_id INT IDENTITY(1,1) PRIMARY KEY,
    cve_id NVARCHAR(20),
    operation_type NVARCHAR(50), -- INSERT, UPDATE, ANALYSIS, PUBLISH
    operation_status NVARCHAR(20), -- SUCCESS, FAILED, PARTIAL
    error_message NVARTEXT,
    processing_time_ms INT,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE SET NULL
);

-- =====================================================
-- 6. System Configuration Table (new)
-- =====================================================
CREATE TABLE system_config (
    config_id INT IDENTITY(1,1) PRIMARY KEY,
    config_key NVARCHAR(100) UNIQUE NOT NULL,
    config_value NVARTEXT,
    description NVARCHAR(500),
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE()
);

-- =====================================================
-- INDEXES for Performance
-- =====================================================

-- CVE Entries indexes
CREATE INDEX IX_cve_entries_publication_date ON cve_entries(publication_date);
CREATE INDEX IX_cve_entries_is_kev ON cve_entries(is_kev);
CREATE INDEX IX_cve_entries_cvss_score ON cve_entries(cvss_score);
CREATE INDEX IX_cve_entries_created_at ON cve_entries(created_at);

-- CVE Reports indexes
CREATE INDEX IX_cve_reports_cve_id ON cve_reports(cve_id);
CREATE INDEX IX_cve_reports_created_at ON cve_reports(created_at);

-- KEV Entries indexes
CREATE INDEX IX_kev_entries_cve_id ON kev_entries(cve_id);
CREATE INDEX IX_kev_entries_due_date ON kev_entries(due_date);
CREATE INDEX IX_kev_entries_date_added ON kev_entries(date_added);

-- WordPress Posts indexes
CREATE INDEX IX_wordpress_posts_cve_id ON wordpress_posts(cve_id);
CREATE INDEX IX_wordpress_posts_status ON wordpress_posts(post_status);
CREATE INDEX IX_wordpress_posts_published_at ON wordpress_posts(published_at);

-- Processing Log indexes
CREATE INDEX IX_processing_log_cve_id ON processing_log(cve_id);
CREATE INDEX IX_processing_log_created_at ON processing_log(created_at);
CREATE INDEX IX_processing_log_operation_type ON processing_log(operation_type);

-- =====================================================
-- TRIGGERS for updating timestamps
-- =====================================================

-- Update timestamp trigger for cve_entries
CREATE TRIGGER tr_cve_entries_updated_at
ON cve_entries
AFTER UPDATE
AS
BEGIN
    UPDATE cve_entries 
    SET updated_at = GETUTCDATE()
    FROM cve_entries c
    INNER JOIN inserted i ON c.cve_id = i.cve_id;
END;

-- Update timestamp trigger for cve_reports
CREATE TRIGGER tr_cve_reports_updated_at
ON cve_reports
AFTER UPDATE
AS
BEGIN
    UPDATE cve_reports 
    SET updated_at = GETUTCDATE()
    FROM cve_reports c
    INNER JOIN inserted i ON c.report_id = i.report_id;
END;

-- Update timestamp trigger for wordpress_posts
CREATE TRIGGER tr_wordpress_posts_updated_at
ON wordpress_posts
AFTER UPDATE
AS
BEGIN
    UPDATE wordpress_posts 
    SET updated_at = GETUTCDATE()
    FROM wordpress_posts w
    INNER JOIN inserted i ON w.post_id = i.post_id;
END;

-- =====================================================
-- VIEWS for common queries
-- =====================================================

-- View for KEV CVEs with full details
CREATE VIEW vw_kev_cves AS
SELECT 
    c.cve_id,
    c.description,
    c.publication_date,
    c.cvss_score,
    c.cvss_severity,
    k.vendor_name,
    k.product_name,
    k.vulnerability_name,
    k.due_date,
    k.date_added,
    w.post_status,
    w.published_at
FROM cve_entries c
INNER JOIN kev_entries k ON c.cve_id = k.cve_id
LEFT JOIN wordpress_posts w ON c.cve_id = w.cve_id;

-- View for recent CVEs with reports
CREATE VIEW vw_recent_cve_reports AS
SELECT 
    c.cve_id,
    c.description,
    c.publication_date,
    c.cvss_score,
    c.cvss_severity,
    r.report_content,
    r.ai_analysis,
    r.severity_assessment,
    r.created_at as report_created_at
FROM cve_entries c
INNER JOIN cve_reports r ON c.cve_id = r.cve_id
WHERE c.publication_date >= DATEADD(day, -30, GETUTCDATE());

-- =====================================================
-- INSERT INITIAL CONFIGURATION
-- =====================================================

INSERT INTO system_config (config_key, config_value, description) VALUES
('last_nvd_sync', NULL, 'Last successful NVD API synchronization timestamp'),
('last_kev_sync', NULL, 'Last successful CISA KEV synchronization timestamp'),
('api_rate_limit_nvd', '50', 'NVD API requests per hour limit'),
('wordpress_site_url', NULL, 'WordPress site URL for posting'),
('processing_batch_size', '100', 'Number of CVEs to process in each batch'),
('ai_analysis_enabled', '1', 'Enable AI-powered vulnerability analysis'),
('auto_publish_enabled', '0', 'Enable automatic WordPress publishing');