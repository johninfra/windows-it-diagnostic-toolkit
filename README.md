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

## Scripts

### `it-diagnostic.ps1`

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

## Usage

Run the full diagnostic tool:

```powershell
.\it-diagnostic.ps1
```