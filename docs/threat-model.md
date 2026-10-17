# Sentinel Threat Model

## 1. Scope and Objective
Sentinel is an endpoint security posture analyzer running locally on Windows workstations. This document identifies security assumptions, potential threats against Sentinel, and mitigation strategies.

## 2. Threat Analysis

### 2.1 Malicious Local Software
- **Threat**: Malicious software running concurrently could attempt to tamper with Sentinel's scan results, modify logs, or inject false telemetry.
- **Mitigation**: Sentinel relies on direct native Windows APIs, token validation, and reads immutable kernel data where available. In future milestones, database and report cryptographic integrity checks will be enforced.

### 2.2 Privilege Abuse & Unauthorized Remediation
- **Threat**: Unintended configuration modifications running under administrator privileges.
- **Mitigation**: 
  - Sentinel does not perform silent or background remediation.
  - All remediation actions require explicit interactive confirmation with preview diffs and verification.
  - Sentinel runs cleanly as standard user for read-only scans.

### 2.3 Command & Path Injection
- **Threat**: Shell code execution or file traversal via untrusted rule definitions or user inputs.
- **Mitigation**:
  - No shell invocation (`cmd.exe` / `powershell.exe`) is used for security collection where native Win32 APIs exist.
  - All rule conditions are declarative (JSON) and parsed without dynamic evaluation.
  - Strictly typed data models with bounds checking.

### 2.4 DLL Hijacking
- **Threat**: Loading of untrusted DLLs from current working directory.
- **Mitigation**: Native Windows search path hardening and explicit system directory linking.
