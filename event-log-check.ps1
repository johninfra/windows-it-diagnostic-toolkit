<#
.SYNOPSIS
    Windows Event Log Diagnostic Scanner

.DESCRIPTION
    Scans recent Windows System and Application event logs for
    critical events, errors, warnings, hardware faults, storage issues,
    unexpected shutdowns, application crashes, and service failures.

    Generates an HTML report in the Reports folder.

.PARAMETER Hours
    Number of hours of event history to analyze.

.PARAMETER MaxEvents
    Maximum number of events to retrieve from each event log.

.EXAMPLE
    .\event-log-check.ps1

.EXAMPLE
    .\event-log-check.ps1 -Hours 48

.EXAMPLE
    .\event-log-check.ps1 -Hours 72 -MaxEvents 500
#>

param(
    [int]$Hours = 24,
    [int]$MaxEvents = 300
)

$ErrorActionPreference = "SilentlyContinue"

# --------------------------------------------------
# Header
# --------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "     Windows Event Log Diagnostic Scanner"     -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# --------------------------------------------------
# Create Reports Folder
# --------------------------------------------------

$reportFolder = Join-Path $PSScriptRoot "Reports"

if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $reportFolder "Event-Log-Report-$timestamp.html"

$startTime = (Get-Date).AddHours(-$Hours)

# --------------------------------------------------
# Administrator Check
# --------------------------------------------------

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

Write-Host "Administrator: $isAdmin"
Write-Host "Analyzing last $Hours hours..."
Write-Host ""

# --------------------------------------------------
# Collect Event Logs
# --------------------------------------------------

Write-Host "[+] Scanning System log..." -ForegroundColor Yellow

$systemEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        StartTime = $startTime
        Level     = 1, 2, 3
    } -MaxEvents $MaxEvents
)

Write-Host "[+] Scanning Application log..." -ForegroundColor Yellow

$applicationEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Application"
        StartTime = $startTime
        Level     = 1, 2, 3
    } -MaxEvents $MaxEvents
)

$allEvents = @($systemEvents + $applicationEvents)

# --------------------------------------------------
# Event Statistics
# --------------------------------------------------

$criticalEvents = @(
    $allEvents | Where-Object { $_.Level -eq 1 }
)

$errorEvents = @(
    $allEvents | Where-Object { $_.Level -eq 2 }
)

$warningEvents = @(
    $allEvents | Where-Object { $_.Level -eq 3 }
)

# --------------------------------------------------
# Detect High-Priority Diagnostic Events
# --------------------------------------------------

$importantEventIDs = @(
    7,      # Disk bad block
    11,     # Disk/controller error
    41,     # Kernel-Power unexpected reboot
    51,     # Disk paging error
    55,     # NTFS corruption
    129,    # Storage device reset
    153,    # Disk I/O retry
    1000,   # Application crash
    1001,   # BugCheck / Windows Error Reporting
    6008,   # Unexpected shutdown
    7000,   # Service failed to start
    7001,   # Service dependency failure
    7009,   # Service timeout
    7011,   # Service timeout
    7031,   # Service terminated unexpectedly
    7034    # Service crashed
)

$priorityEvents = @(
    $allEvents |
        Where-Object {
            $_.Id -in $importantEventIDs -or
            $_.ProviderName -eq "Microsoft-Windows-WHEA-Logger"
        } |
        Sort-Object TimeCreated -Descending
)

# --------------------------------------------------
# Categorize Important Events
# --------------------------------------------------

function Get-IssueCategory {

    param(
        [int]$EventID,
        [string]$Provider
    )

    if ($Provider -eq "Microsoft-Windows-WHEA-Logger") {
        return "Hardware"
    }

    switch ($EventID) {

        { $_ -in 7, 11, 51, 55, 129, 153 } {
            return "Disk / Storage"
        }

        41 {
            return "Unexpected Reboot"
        }

        6008 {
            return "Unexpected Shutdown"
        }

        1000 {
            return "Application Crash"
        }

        1001 {
            return "Crash / BugCheck"
        }

        { $_ -in 7000, 7001, 7009, 7011, 7031, 7034 } {
            return "Service Failure"
        }

        default {
            return "Other"
        }
    }
}

# --------------------------------------------------
# Console Summary
# --------------------------------------------------

Write-Host ""
Write-Host "========== Diagnostic Summary ==========" -ForegroundColor Cyan

Write-Host "Total Events : $($allEvents.Count)"
Write-Host "Critical     : $($criticalEvents.Count)" -ForegroundColor Red
Write-Host "Errors       : $($errorEvents.Count)" -ForegroundColor Red
Write-Host "Warnings     : $($warningEvents.Count)" -ForegroundColor Yellow
Write-Host "Priority     : $($priorityEvents.Count)" -ForegroundColor Magenta

if ($priorityEvents.Count -gt 0) {

    Write-Host ""
    Write-Host "High-Priority Events:" -ForegroundColor Red

foreach ($logEvent in ($priorityEvents | Select-Object -First 15)) {

    $category = Get-IssueCategory `
        -EventID $logEvent.Id `
        -Provider $logEvent.ProviderName

    Write-Host ""
    Write-Host "[$category] Event ID $($logEvent.Id)" -ForegroundColor Yellow
    Write-Host "Time:     $($logEvent.TimeCreated)"
    Write-Host "Provider: $($logEvent.ProviderName)"

    $message = $logEvent.Message

        if ($message -and $message.Length -gt 250) {
            $message = $message.Substring(0, 250) + "..."
        }

        Write-Host "Message:  $message"
    }
}

# --------------------------------------------------
# Prepare HTML Event Data
# --------------------------------------------------

$reportEvents = foreach ($logEvent in ($allEvents | Sort-Object TimeCreated -Descending)) {

    $category = Get-IssueCategory `
        -EventID $logEvent.Id `
        -Provider $logEvent.ProviderName

    $message = $logEvent.Message

    if (-not $message) {
        $message = "No event message available."
    }

[PSCustomObject]@{
    Time       = $logEvent.TimeCreated
    Log        = $logEvent.LogName
    Severity   = $logEvent.LevelDisplayName
    EventID    = $logEvent.Id
    Provider   = $logEvent.ProviderName
    Category   = $category
    Message    = $message
}
}

# --------------------------------------------------
# Generate HTML Report
# --------------------------------------------------

$eventTable = $reportEvents |
    ConvertTo-Html -Fragment `
    -Property Time, Log, Severity, EventID, Provider, Category, Message

$html = @"
<!DOCTYPE html>
<html>
<head>

<title>Windows Event Log Diagnostic Report</title>

<style>

body {
    font-family: Segoe UI, Arial, sans-serif;
    background-color: #111827;
    color: #e5e7eb;
    margin: 40px;
}

h1 {
    color: #38bdf8;
}

h2 {
    color: #7dd3fc;
}

.summary {
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
    flex-wrap: wrap;
}

.card {
    background-color: #1f2937;
    padding: 20px;
    border-radius: 8px;
    min-width: 150px;
}

.card-value {
    font-size: 28px;
    font-weight: bold;
}

table {
    width: 100%;
    border-collapse: collapse;
    background-color: #1f2937;
}

th {
    background-color: #0f172a;
    color: #38bdf8;
    padding: 10px;
    text-align: left;
}

td {
    padding: 8px;
    border-bottom: 1px solid #374151;
    vertical-align: top;
}

tr:hover {
    background-color: #374151;
}

.footer {
    margin-top: 30px;
    color: #9ca3af;
}

</style>

</head>

<body>

<h1>Windows Event Log Diagnostic Report</h1>

<p>
Computer: $env:COMPUTERNAME<br>
Generated: $(Get-Date)<br>
Analysis Window: Last $Hours hours<br>
Administrator: $isAdmin
</p>

<h2>Summary</h2>

<div class="summary">

<div class="card">
<div>Events</div>
<div class="card-value">$($allEvents.Count)</div>
</div>

<div class="card">
<div>Critical</div>
<div class="card-value">$($criticalEvents.Count)</div>
</div>

<div class="card">
<div>Errors</div>
<div class="card-value">$($errorEvents.Count)</div>
</div>

<div class="card">
<div>Warnings</div>
<div class="card-value">$($warningEvents.Count)</div>
</div>

<div class="card">
<div>Priority Issues</div>
<div class="card-value">$($priorityEvents.Count)</div>
</div>

</div>

<h2>Event Details</h2>

$eventTable

<div class="footer">
Generated by Windows IT Diagnostic Toolkit
</div>

</body>
</html>
"@

$html | Out-File $reportPath -Encoding UTF8

# --------------------------------------------------
# Completion
# --------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "Event log analysis complete." -ForegroundColor Green
Write-Host "Report: $reportPath" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""