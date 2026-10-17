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

## 3. Milestone 8 Baseline Checkpoint

Baseline captured on 2026-10-17 from the project root:

- Toolchain: CMake/Ninja with MSYS2 MinGW-w64 and Qt 6; C++20 Release configuration.
- `cmake --build build-final --config Release`: passed with exit code 0.
- `ctest --test-dir build-final --output-on-failure`: failed with exit code 8 because the host-dependent network test requires at least one live TCP or UDP endpoint; the collector returned zero endpoints.
- The project directory has no `.git` metadata, so Git status and diff validation are unavailable.
- Existing generated build and deployment directories were preserved.

The Milestone 8 implementation separates deterministic unit checks from host-dependent integration checks. Subsequent results are recorded below as each phase is completed.

## 4. Milestone 8 Verification Record

Commands run with the matching MSYS2 runtime first on `PATH`:

```powershell
$env:MSYS2_MINGW64_BIN = "<path-to-msys2>\mingw64\bin"
$env:Path = "$env:MSYS2_MINGW64_BIN;C:\Windows\System32;C:\Windows"
cmake --build build-final --config Release
ctest --test-dir build-final --output-on-failure
```

Results:

- Release build: passed, exit code 0.
- `SentinelUnitTests`: passed.
- `SentinelWindowsIntegrationTests`: passed on the current Windows host.
- CTest: 2/2 tests passed, exit code 0.

Deployment verification:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-windows.ps1 `
  -BuildDirectory build-final `
  -OutputDirectory release-final-check `
  -MingwBin $env:MSYS2_MINGW64_BIN
```

The deployment command completed with exit code 0. PE import inspection confirmed the staged Qt, MinGW, SQLite, ICU, compression, text, image, and font runtime libraries were present. Windows system DLLs were not bundled. A GUI smoke test with a sanitized `PATH` remains a manual verification step.

## 5. Milestone 8 Phase Status

- Phase A: complete. Baseline and environment limitations recorded.
- Phase B: complete. Encryption query outcomes are injectable and insufficient evidence maps to `Unknown`.
- Phase C: complete. Scan activity remains active until `QThread::finished`; worker cleanup waits for confirmed termination.
- Phase D: complete. Deterministic unit tests and Windows integration tests are registered separately.
- Phase E: complete. Rule operators are evaluated, malformed rule definitions are rejected, and regression tests cover operator handling.
- Phase F: complete. SQLite close failures preserve the live handle and remain observable.
- Phase G: complete. Fresh configure/build, CTest, deployment generation, and PE dependency inspection passed.
- Phase H: complete for documentation. GUI smoke testing remains manual and was not run in this verification pass.

## 6. Manual Checks Remaining

- Launch `release-final-check\sentinel.exe` with a `PATH` containing only Windows system directories and the staged application directory.
- Start a scan, request cancellation during collection, and confirm the UI returns to an idle state without a crash.
- Close the application during an active scan and confirm shutdown waits for the worker thread before process exit.
- Request a second scan while one is active and confirm it is rejected without starting overlapping work.
