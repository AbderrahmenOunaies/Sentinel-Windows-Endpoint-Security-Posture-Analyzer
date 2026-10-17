# Changelog

All notable changes to Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-10-16

### Added
- **Core Domain & Security Model (Milestones 1–2)**:
  - Severity enum (`Critical`, `High`, `Medium`, `Low`, `Info`) with mathematical deduction weights.
  - Transparent 0–100 security scoring algorithm.
  - Profiles (`Standard`, `Developer`, `High Security`).
  - Structured `Finding` and key-value `Evidence` models.
- **System & Security Collectors (Milestones 3–4)**:
  - Native Windows collectors: System, Network (TCP/UDP socket tables), Services, Firewall (COM `INetFwPolicy2`), Defender (Registry), Accounts (`NetUserEnum`), Authentication policies (`NetUserModalsGet`), BitLocker encryption (IOCTLs), and Windows Update (CBS packages).
- **Rule Engine (Milestone 5)**:
  - 14 initial security rules covering Firewall, Defender, Authentication, Encryption, and Updates.
  - 3-state evaluation logic (`Pass`, `Fail`, `Unknown`) with zero false-positives on missing telemetry.
- **Scan Orchestration & Dashboard UI (Milestones 6–7)**:
  - Multithreaded non-blocking `ScanController` with progress reporting and cancellation.
  - Interactive cybersecurity dashboard with score breakdown dialog and category summaries.
  - Findings widget with real-time text search, severity filter, and category filter.
  - Audit inspection dialog with clipboard export and remediation action previews.
- **Persistence & Historical Auditing (Milestone 8)**:
  - SQLite persistence engine with WAL journal mode, foreign-key cascade integrity, and schema migrations (`PRAGMA user_version`).
  - Scan history inspection dialog (`ScanHistoryDialog`) for loading past audit results into the dashboard.
  - Standalone release package verified on Windows x64.
