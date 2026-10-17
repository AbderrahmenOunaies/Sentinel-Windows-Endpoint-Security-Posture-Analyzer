# Sentinel — Database & Persistence Specification

Sentinel uses SQLite 3 for local audit trail persistence and scan history.

---

## 1. Storage Location & Privacy

- **Database Path**: `%LOCALAPPDATA%\Sentinel\sentinel.db` (resolved dynamically via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`).
- **Privacy & Security**:
  - The database is stored locally under the user's Windows profile directory.
  - Access is restricted by standard Windows NTFS file system permissions.
  - **No Secrets Stored**: The database never persists passwords, password hashes, encryption recovery keys, or access tokens.
  - **No Telemetry / Cloud Sync**: Sentinel operates 100% offline. No database content is uploaded to any remote server or cloud service.

---

## 2. SQLite Configuration

- **Journal Mode**: Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) for high concurrency and write safety.
- **Foreign Keys**: Enabled (`PRAGMA foreign_keys = ON;`) to ensure relational integrity and cascading deletes.
- **Prepared Statements**: All write and query operations strictly use parameterized queries (`sqlite3_prepare_v2`, `sqlite3_bind_*`) eliminating SQL injection risks.
- **Thread Safety**: Full-mutex multithreading (`SQLITE_OPEN_FULLMUTEX`).

---

## 3. Schema Versioning & Migrations

Schema versioning is managed via SQLite's `PRAGMA user_version`:

### Schema Version 1 (Current)

```sql
-- 1. Scan Records
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    profile_name TEXT NOT NULL,
    base_score INTEGER NOT NULL,
    final_score INTEGER NOT NULL,
    score_classification TEXT NOT NULL,
    passed_count INTEGER NOT NULL,
    failed_count INTEGER NOT NULL,
    unknown_count INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    completed_successfully INTEGER NOT NULL,
    status_message TEXT NOT NULL
);

-- 2. Security Findings
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    impact TEXT,
    recommendation TEXT NOT NULL,
    remediation_available INTEGER NOT NULL,
    remediation_id TEXT,
    detected_at INTEGER NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_rule_id ON findings(rule_id);
CREATE INDEX idx_findings_severity ON findings(severity);

-- 3. Audit Evidence
CREATE TABLE evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX idx_evidence_finding_id ON evidence(finding_id);

-- 4. Application Settings (Non-sensitive)
CREATE TABLE app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 5. Collector Diagnostics
CREATE TABLE collector_status_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    message TEXT,
    native_error_code INTEGER,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_collector_scan_id ON collector_status_records(scan_id);
```

---

## 4. Retention & Deletion Policy

- Operators can inspect historical scans through the **Scan History & Audit Logs** dialog in the desktop UI.
- Operators can permanently clear all historical scans, findings, and evidence with explicit confirmation via the **Clear History** action.
- Clearing history executes `DELETE FROM scans;`, triggering cascading deletion across all linked finding and evidence records without corrupting or deleting the database file.
