# Sentinel

Windows Endpoint Security Posture Analyzer.

Sentinel analyzes a Windows workstation's security posture, identifies security weaknesses, provides evidence for every finding, assigns a severity level, and recommends remediation. The current release is assessment-only; it does not modify system security settings.

**Disclaimer**: Sentinel is a defensive security assessment tool. It is intended for systems that the user owns or is authorized to administer.

---

## Architecture & Technology Stack

- **Language standard**: C++20
- **GUI Framework**: Qt 6 (Widgets)
- **Build System**: CMake 3.22+ & Ninja
- **Platform**: Windows 10/11 x64 (Native Windows APIs, `advapi32`)

---

## Build Instructions

### Prerequisites & Compilation Dependencies
- **CMake**: 3.22+
- **C++20 Compiler**: MinGW-w64 (`g++` 13+) or MSVC (Visual Studio 2022 v143+)
- **Build Generator**: Ninja or MSBuild
- **Qt 6 Framework**: `Qt6::Core`, `Qt6::Gui`, `Qt6::Widgets`
- **SQLite 3**: Header (`sqlite3.h`) and development import library (`libsqlite3.a` / `sqlite3.lib`)
- **Windows SDK System Libraries** (Linked during compilation):
  - `advapi32.dll` (Windows Security & Registry APIs)
  - `iphlpapi.dll` (IP Helper API for socket tables)
  - `ws2_32.dll` (Winsock 2.0 network library)
  - `ole32.dll` & `oleaut32.dll` (COM runtime for `INetFwPolicy2`)
  - `netapi32.dll` (Network Management & User Accounts API)
  - `shell32.dll` (Shell API for `SHGetKnownFolderPath` app-data resolution)

### Building with CMake

```powershell
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Set `CMAKE_PREFIX_PATH` to the Qt/MinGW installation when Qt is not discoverable automatically, for example:

```powershell
cmake -S . -B build-final -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/msys64/mingw64
```

### Running Tests

```powershell
ctest --test-dir build --output-on-failure
```

The default CTest run includes deterministic unit tests and a separately named Windows integration test. Run only the deterministic suite with:

```powershell
ctest --test-dir build-final -R SentinelUnitTests --output-on-failure
```

Run the host-dependent collector checks explicitly with:

```powershell
ctest --test-dir build-final -R SentinelWindowsIntegrationTests --output-on-failure
```

### Running Sentinel

```powershell
./build/sentinel.exe
```

---

## Required Runtime DLLs (Standalone Deployment)

When distributing or running `sentinel.exe` outside of the development shell (e.g. MSYS2/MinGW or Qt environment), the following dynamic libraries must be placed in the executable directory:

### 1. Application Directory Root (`./`)

| Category | DLL Name | Description / Origin |
|---|---|---|
| **C++ Runtime** | `libstdc++-6.dll` | GNU C++ Standard Library runtime |
| **C++ Runtime** | `libgcc_s_seh-1.dll` | GCC Stack Unwind & SEH Exception runtime |
| **C++ Runtime** | `libwinpthread-1.dll` | POSIX Threads library for Win32 |
| **Database** | `libsqlite3-0.dll` | SQLite 3 embedded database engine |
| **Qt Framework** | `Qt6Core.dll` | Qt 6 Core runtime, event loop, and metadata engine |
| **Qt Framework** | `Qt6Gui.dll` | Qt 6 GUI abstraction, fonts, and rendering engine |
| **Qt Framework** | `Qt6Widgets.dll` | Qt 6 Desktop UI Widget components |
| **Qt Framework** | `Qt6Network.dll` | Qt 6 Network communication stack (optional / helper) |

### 2. Qt Platform & Plugin Subdirectories

Qt requires its platform and style plugins to reside in specific subdirectories alongside `sentinel.exe`:

- **`./platforms/`** (Required):
  - `qwindows.dll`: Windows Desktop platform integration plugin (mandatory for GUI rendering on Windows).
- **`./styles/`**:
  - `qmodernwindowsstyle.dll`: Windows native style plugin.
- **`./imageformats/`**:
  - `qico.dll`, `qjpeg.dll`, `qgif.dll`: Icon and image decode plugins.
- **`./tls/`**:
  - `qschannelbackend.dll`, `qcertonlybackend.dll`: Windows SChannel TLS backend.
- **`./networkinformation/`**:
  - `qnetworklistmanager.dll`, `qglib.dll`: Windows Network List Manager plugin.

> [!TIP]
> You can deploy these automatically to your target folder using Qt's deployment tool:
> ```powershell
> windeployqt --compiler-runtime --release ./release/sentinel.exe
> ```
> And copy `libsqlite3-0.dll` alongside `sentinel.exe`.

For the MSYS2/MinGW build used by this repository, use the checked-in deployment
script instead. It also stages ICU and the MinGW runtime DLLs that Qt loads
dynamically:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-windows.ps1 -BuildDirectory build-final -OutputDirectory release -MingwBin C:/msys64/mingw64/bin
```

Keep the staged DLLs beside `sentinel.exe`; do not launch it from a development
shell whose `PATH` can select incompatible MSYS2 libraries.

---

## Privilege Model

Sentinel operates under two modes:
1. **Standard Mode**: Read-only assessments where non-elevated APIs suffice.
2. **Administrator Mode**: Required for privileged security operations and remediation.
Sentinel detects elevation on startup and communicates its status clearly on the dashboard.

---

## Core Domain Model

- **Finding**: Evidence-backed vulnerability or misconfiguration detection record with assigned severity, impact analysis, and remediation ID.
- **Evidence**: Key-value context pairs tying detections directly to raw system states and audit sources.
- **Severity**: `Critical`, `High`, `Medium`, `Low`, and `Info`.
- **Transparent Security Score**: Starts from a baseline of 100 with clear deterministic deductions:
  - Critical: `-25`
  - High: `-10`
  - Medium: `-5`
  - Low: `-2`
  - Info: `-0`
  Clamped cleanly between `0` and `100` with full audit explanation.
- **Security Profiles**: `Standard`, `Developer`, `High Security`, and `Custom` profiles adjusting rule baselines without weakening core security checks.
- **CollectionResult<T>**: Explicit error categorization handling `Success`, `PermissionDenied`, `NotSupported`, `NotFound`, and `SystemError` without conflating errors with security states.

---

## System Collectors (Milestone 3)

The collection layer uses native Windows APIs to gather raw, trustworthy endpoint facts without making premature security judgments or classifications:

- **`SystemCollector`**: Gathers hardware and OS facts (`GetNativeSystemInfo`, `GlobalMemoryStatusEx`, `GetComputerNameW`, `GetSystemDirectoryW`).
- **`NetworkCollector`**: Enumerates IPv4 and IPv6 TCP/UDP socket tables with owning PIDs and resolved process names using Windows IP Helper (`GetExtendedTcpTable`, `GetExtendedUdpTable`, `QueryFullProcessImageNameW`). Distinguishes listening endpoints (`0.0.0.0`, `127.0.0.1`, `::`) and preserves connection states.
- **`ServiceCollector`**: Enumerates installed Windows services using Service Control Manager (`OpenSCManagerW`, `EnumServicesStatusExW`, `QueryServiceConfigW`) collecting service names, display names, execution states, startup types, binary paths, and running PIDs.
- **String Encoding**: Safe Windows UTF-16 to UTF-8 domain conversions.

---

## Security Collectors (Milestone 4)

Native Windows security facts collection without making premature security judgments:

- **`FirewallCollector`**: Queries Windows Firewall COM interface (`INetFwPolicy2`) across Domain, Private, and Public profiles, inspecting enabled states, default inbound/outbound actions (`Block` / `Allow`), and notification flags.
- **`DefenderCollector`**: Inspects Microsoft Defender security states and signature telemetry directly via native registry interfaces without spawning PowerShell or CLI wrappers.
- **`AccountCollector`**: Enumerates local accounts via `NetUserEnum` / `NetApiBufferFree` with user flags (`UF_ACCOUNTDISABLE`, `UF_PASSWD_NOTREQD`, `UF_DONT_EXPIRE_PASSWD`, `UF_LOCKOUT`).
- **`AuthenticationCollector`**: Retrieves system authentication and lockout policies via `NetUserModalsGet` (minimum password length, password age, history, lockout threshold and observation window).
- **`EncryptionCollector`**: Queries system storage encryption status (BitLocker) via native Win32 device IOCTLs (`FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER`) without calling `manage-bde` or exposing recovery keys.
- **`UpdateCollector`**: Gathers Windows Update posture facts via Component-Based Servicing (`CBS`) packages and Service Control Manager for `wuauserv` service state and pending reboot indicators.

---

## Rule Engine & Security Evaluation (Milestone 5)

Sentinel separates raw security facts collection from policy evaluation:

- **Strict Three-State Evaluation Logic**: Every rule condition yields `EvaluationState::True`, `EvaluationState::False`, or `EvaluationState::Unknown`. Incomplete or uncollected telemetry evaluates strictly to `RuleOutcome::Unknown` and **never generates false-positive findings**.
- **Evidence-Backed Findings**: `Finding` records are generated only upon definitive `RuleOutcome::Fail` evaluations and carry structured `Evidence` key-value pairs pointing back to collector sources.
- **Declarative Initial Ruleset (14 Rules)**:
  - `FW-001` .. `FW-003`: Windows Firewall Domain, Private, and Public profile enabled checks.
  - `FW-004`: Public network profile default inbound block posture.
  - `DEF-001` .. `DEF-004`: Microsoft Defender antivirus enabled, real-time protection, spyware protection, and behavior monitoring.
  - `AUTH-001` .. `AUTH-003`: Minimum password length baseline, complexity requirements, and account lockout threshold.
  - `ENC-001`: Operating system system volume encryption posture (BitLocker).
  - `UPD-001` .. `UPD-002`: Pending system reboot detection and Windows Update service health.
- **Profile-Aware Evaluation**: Profile configurations (`Standard`, `Developer`, `High Security`) customize rule parameters (e.g., minimum password lengths) without altering the underlying security facts or engine integrity.
- **Isolated Domain**: The Rule Engine operates entirely in-memory over `SecurityContext` structures with zero direct operating system or Win32 API calls.

---

## Scan Orchestration, Dashboard & Findings UI (Milestone 6)

Sentinel delivers a complete asynchronous, non-blocking scan orchestration and cybersecurity dashboard:

- **Asynchronous Orchestration (`ScanController`)**:
  - Executes the native Windows collectors on a dedicated worker thread (`QThread`) without freezing or blocking the GUI. Collector stages currently run sequentially so progress and partial telemetry remain deterministic.
  - Features thread-safe cancellation tokens, duplicate scan prevention, and stage-by-stage progress reporting.
  - Constructs `SecurityContext`, evaluates rules via `RuleEngine`, computes transparent scores via `SecurityScoreCalculator`, and produces authoritative `ScanResult`s.
- **Traceable Cybersecurity Dashboard (`DashboardWidget`)**:
  - **`ScoreWidget`**: Displays prominent numeric workstation security score (`/ 100`) and security posture badge (`EXCELLENT`, `GOOD`, `MODERATE RISK`, `HIGH RISK`).
  - **`ScoreBreakdownDialog`**: Provides deterministic score deduction accounting (Critical `-25`, High `-10`, Medium `-5`, Low `-2`).
  - **Evaluation Outcomes**: Real-time counters for Passed, Failed, Unknown, and Findings with scan timestamps and duration.
  - **`CategorySummaryWidget`**: Outcome breakdown across security domains (`Firewall`, `Endpoint Protection`, `Authentication`, `Encryption`, `Updates`).
  - **`CollectorStatusWidget`**: Telemetry collection health monitoring distinguishing `Complete`, `Permission Denied`, `Not Supported`, and system errors.
  - **`FindingsWidget`**: High-density findings table ordered by severity (`Critical` → `High` → `Medium` → `Low` → `Info`).
  - **`FindingDetailDialog`**: Double-click inspection dialog detailing rule ID, title, severity, category, description, security impact, audit evidence table, and actionable recommendations.
- **Pure Model-View Separation**: The Qt UI is strictly a view of the underlying domain model. The UI contains no Windows API calls, collector invocations, or security evaluation logic.

---

## Finding Details & Audit Inspection (Milestone 7)

Sentinel provides comprehensive investigation capabilities for every detected posture finding:

- **Audit Evidence View (`FindingDetailDialog`)**:
  - Displays rule identifier (`ruleId`), security category, severity badge, full title, and detailed vulnerability descriptions.
  - Formatted security impact explanation assessing attack surface implications.
  - Multi-column structured evidence table (`Source`, `Key`, `Observed Value`) linking detections to raw system telemetry.
  - Exact detection timestamp (`detectedAt`) preserving timeline provenance.
  - Actionable recommendation block with remediation ID and interactive **Preview Remediation** hook.
  - **Copy Evidence** functionality for instant export to clipboard for incident response or SOC ticketing.
- **Advanced Findings Filtering (`FindingsWidget`)**:
  - Free-text real-time filter across title, rule ID, and description.
  - Dynamic severity filter (`Critical`, `High`, `Medium`, `Low`, `Info`).
  - Dynamic category filter generated from active scan findings.
  - Remediation indicator column informing operators whether automated fixes are available.

---

## SQLite Persistence, Migrations & Audit History (Milestone 8)

Sentinel provides complete offline audit trail storage and historical inspection:

- **Storage Engine (`src/storage/`)**:
  - Thread-safe SQLite 3 database located at `%LOCALAPPDATA%\Sentinel\sentinel.db`.
  - Configured with Write-Ahead Logging (`WAL`) and foreign-key constraint enforcement (`PRAGMA foreign_keys = ON`).
  - Strict schema versioning using SQLite's `PRAGMA user_version` with transactional migrations.
  - Parameterized prepared statements across all queries for complete SQL injection protection.
- **Data Model & Audit Trail**:
  - **Scans**: Persists scan ID, start/end timestamps, elapsed duration, profile, overall score, score classification, outcome counts, and completion status.
  - **Findings & Evidence**: Normalizes findings and associated evidence key-values with cascading deletion.
  - **Collector Diagnostics**: Records collector health and native error codes for full auditability.
  - **Application Settings**: Stores non-sensitive user preferences (no secrets or credentials).
- **Historical Audit Inspection (`ScanHistoryDialog`)**:
  - Dedicated **Scan History** button on the main dashboard.
  - Audit table displaying historical scans with dates, profiles, scores, posture classifications, and finding counts.
  - **Inspect Historical Scan**: Re-populates the dashboard with previous findings and evidence without invoking live collectors.
  - **Clear History**: Safely purges historical records with explicit confirmation without deleting the database file.
- **Privacy & Security**:
  - 100% offline, zero telemetry, zero cloud synchronization.
  - No credentials, passwords, or BitLocker recovery keys are ever collected or stored.

---

## Project Documentation

Detailed technical documentation is available in the [`docs/`](docs/) directory:
- [Architecture & Data Pipeline](docs/architecture.md)
- [Database Schema & Migrations](docs/database.md)
- [Security Model & Defensive Principles](docs/security.md)
- [Threat Model](docs/threat-model.md)
- [Testing & Quality Assurance](docs/testing.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Release Readiness and Current Limitations

- Implemented and reviewed: native read-only collectors, three-state rule evaluation, evidence-backed findings, transparent scoring, Qt dashboard, and SQLite scan history.
- The remediation button currently records an operator-intent hook only. No firewall, service, account, Defender, encryption, or other system modification is executed.
- JSON and HTML report generation, continuous monitoring, baseline comparison, and configurable external rule-file loading are not implemented in this release.
- Automated tests include host-dependent Windows integration checks. A successful build does not prove that every collector behaves identically on every Windows edition or privilege level.
- The project is distributed under the MIT license in `LICENSE`.

