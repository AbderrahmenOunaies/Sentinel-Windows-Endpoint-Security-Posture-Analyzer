# Sentinel — Security Model & Defensive Assessment Principles

Sentinel is designed as a defensive posture assessment application following strict least-privilege, read-only inspection, and zero false-positive design principles.

---

## 1. Core Defensive Principles

1. **Non-Destructive Read-Only Operation**:
   - Sentinel performs security scans purely through non-invasive Win32, COM, and Network APIs.
   - Scanning never modifies system state, firewall rules, service configurations, or registry entries.
2. **No Shell Invocations**:
   - Sentinel avoids `system()`, `popen()`, `cmd.exe`, or `powershell.exe` wrappers.
   - All collectors interface directly with native system APIs (e.g., `NetUserEnum`, `INetFwPolicy2`, `FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER`).
3. **Strict Three-State Evaluation Logic**:
   - Rules evaluate to `Pass`, `Fail`, or `Unknown`.
   - Incomplete or inaccessible telemetry evaluates strictly to `Unknown` and **never generates false-positive findings**.
4. **Transparent Scoring**:
   - Every score deduction is tied to an explicit finding severity: Critical (`-25`), High (`-10`), Medium (`-5`), Low (`-2`).
   - The deduction arithmetic is directly inspectable in the UI.

---

## 2. Privilege Model

- **Standard User**:
  - Fully capable of running baseline posture scans, viewing findings, inspecting audit evidence, and querying local scan history.
- **Administrator**:
  - Provides visibility into privileged system volume encryption posture (BitLocker IOCTLs) and system services.
- Sentinel detects elevation status on startup and displays it prominently in the top navigation bar. Sentinel never attempts silent or unsolicited elevation.

---

## 3. Remediation Architecture & Transparency

- Sentinel includes remediation IDs and actionable guidance for detected misconfigurations.
- The **Preview Remediation** action currently emits an operator-intent hook and logs the remediation ID; it does not render or apply a system change.
- Sentinel does **not** execute system modifications in this release. Any future remediation requires explicit operator confirmation, prerequisite validation, elevated privileges, and post-change verification.

---

## 4. Privacy & Data Integrity

- All scan results, findings, and evidence are persisted strictly in local storage under `%LOCALAPPDATA%\Sentinel\sentinel.db`.
- No sensitive user credentials, password hashes, or recovery keys are collected or persisted.
- Sentinel contains no network telemetry, analytics beacons, or remote cloud connections.
