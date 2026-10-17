# Sentinel — Testing & Quality Assurance

Sentinel employs an automated test suite executed via CTest and C++20 assertions, covering all domain components, collectors, scoring algorithms, and SQLite storage.

---

## 1. Test Suite Coverage

### Unit & Domain Tests
- **Milestone 1**: Platform privilege detection, hostname, and OS version resolution.
- **Milestone 2**: Severity enum conversions, mathematical score deduction penalties, profile configurations, and result error categories.
- **Milestone 3**: Native and synthetic system, network socket table enumeration, and Windows service status snapshots.
- **Milestone 4**: Native and synthetic Windows Firewall, Microsoft Defender, local accounts, password/lockout policies, BitLocker encryption IOCTLs, and Windows Update package telemetry.
- **Milestone 5**: Rule engine evaluation logic across Standard, Developer, and High-Security profiles; zero false-positive validation under partial collection failure.
- **Milestone 6**: Scan orchestration result construction, duration calculation, and collector health tracking.
- **Milestone 7**: Finding detail audit models, multi-source evidence provenance, remediation IDs, and timestamps.
- **Milestone 8**: SQLite database initialization, WAL mode verification, schema versioning via PRAGMA user_version, transactional scan/finding/evidence insertion, cascade deletion, and settings storage.

---

## 2. Running Automated Tests

From the project root:

```powershell
ctest --test-dir build --output-on-failure
```

Or execute the test binary directly:

```powershell
./build/sentinel_tests.exe
```
