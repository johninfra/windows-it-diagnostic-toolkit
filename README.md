# Windows IT Diagnostic Toolkit

A PowerShell-based Windows diagnostic toolkit designed to automate common IT support and system administration checks.

## Features

- Windows OS information
- Computer manufacturer and model
- CPU information
- Memory usage
- Disk capacity and free space
- IPv4 network configuration
- Default gateway and DNS configuration
- Gateway connectivity testing
- Internet connectivity testing
- DNS resolution testing
- Microsoft Defender status
- Windows Firewall status
- Automatic services that are not running
- Recent critical and error events
- Automated HTML reporting
- Dedicated Windows Event Log analysis
- Detection of critical events, errors, warnings, service failures, application crashes, storage issues, and unexpected shutdowns

## Scripts

### `it-diagnostics.ps1`

Runs the full Windows diagnostic assessment and generates an HTML report.

### `system-info.ps1`

Provides a lightweight overview of:

- Computer name
- Current user
- Windows version
- IP configuration
- Disk space

### `network-check.ps1`

Performs basic Windows network diagnostics, including:

- Displays active network configuration
- Shows IPv4 information
- Tests internet connectivity
- Tests DNS resolution
- Reports PASS/FAIL results for connectivity checks

### `event-log-check.ps1`

Performs deeper Windows Event Log diagnostics, including:

- Scans System and Application logs
- Identifies critical events, errors, and warnings
- Detects unexpected shutdowns and reboots
- Detects application crashes
- Detects Windows service failures
- Detects disk and storage-related errors
- Detects hardware-related WHEA events
- Generates a dedicated HTML event log report

## Usage

Run the full diagnostic tool:

```powershell
.\it-diagnostics.ps1
```