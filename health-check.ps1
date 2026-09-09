<#
.SYNOPSIS
    Windows System Health Check

.DESCRIPTION
    Performs read-only health checks against Windows system resources,
    storage, security controls, services, hardware events, and OS integrity.

    Returns an overall status:
        HEALTHY
        WARNING
        CRITICAL

.PARAMETER DeepScan
    Runs additional CHKDSK, DISM, and SFC verification checks.

.EXAMPLE
    .\health-check.ps1

.EXAMPLE
    .\health-check.ps1 -DeepScan
#>

param(
    [switch]$DeepScan
)

$ErrorActionPreference = "SilentlyContinue"

# --------------------------------------------------
# Configuration
# --------------------------------------------------

$Results = @()

function Add-HealthResult {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Details
    )

    $script:Results += [PSCustomObject]@{
        Check   = $Check
        Status  = $Status
        Details = $Details
    }
}

# --------------------------------------------------
# Header
# --------------------------------------------------

Clear-Host

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "          Windows System Health Check"          -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

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

if ($isAdmin) {
    Add-HealthResult `
        -Check "Administrator Session" `
        -Status "PASS" `
        -Details "PowerShell is running as Administrator."
}
else {
    Add-HealthResult `
        -Check "Administrator Session" `
        -Status "WARNING" `
        -Details "Some health checks may be limited without Administrator privileges."
}

# --------------------------------------------------
# Operating System
# --------------------------------------------------

Write-Host "[+] Checking operating system..." -ForegroundColor Yellow

$os = Get-CimInstance Win32_OperatingSystem

$uptime = (Get-Date) - $os.LastBootUpTime

Add-HealthResult `
    -Check "Operating System" `
    -Status "PASS" `
    -Details "$($os.Caption) | Version $($os.Version) | Uptime: $([math]::Round($uptime.TotalDays, 1)) days"

# --------------------------------------------------
# CPU
# --------------------------------------------------

Write-Host "[+] Checking CPU..." -ForegroundColor Yellow

$cpu = Get-CimInstance Win32_Processor

$cpuLoad = [math]::Round(
    ($cpu | Measure-Object -Property LoadPercentage -Average).Average,
    0
)

if ($cpuLoad -ge 90) {
    Add-HealthResult `
        -Check "CPU Usage" `
        -Status "CRITICAL" `
        -Details "$cpuLoad% CPU utilization."
}
elseif ($cpuLoad -ge 75) {
    Add-HealthResult `
        -Check "CPU Usage" `
        -Status "WARNING" `
        -Details "$cpuLoad% CPU utilization."
}
else {
    Add-HealthResult `
        -Check "CPU Usage" `
        -Status "PASS" `
        -Details "$cpuLoad% CPU utilization."
}

# --------------------------------------------------
# Memory
# --------------------------------------------------

Write-Host "[+] Checking memory..." -ForegroundColor Yellow

$totalMemoryGB = [math]::Round(
    $os.TotalVisibleMemorySize / 1MB,
    2
)

$freeMemoryGB = [math]::Round(
    $os.FreePhysicalMemory / 1MB,
    2
)

$usedMemoryGB = $totalMemoryGB - $freeMemoryGB

$memoryPercent = [math]::Round(
    ($usedMemoryGB / $totalMemoryGB) * 100,
    1
)

if ($memoryPercent -ge 90) {
    Add-HealthResult `
        -Check "Memory" `
        -Status "CRITICAL" `
        -Details "$memoryPercent% used ($usedMemoryGB GB / $totalMemoryGB GB)."
}
elseif ($memoryPercent -ge 80) {
    Add-HealthResult `
        -Check "Memory" `
        -Status "WARNING" `
        -Details "$memoryPercent% used ($usedMemoryGB GB / $totalMemoryGB GB)."
}
else {
    Add-HealthResult `
        -Check "Memory" `
        -Status "PASS" `
        -Details "$memoryPercent% used ($usedMemoryGB GB / $totalMemoryGB GB)."
}

# --------------------------------------------------
# Disk Free Space
# --------------------------------------------------

Write-Host "[+] Checking disk capacity..." -ForegroundColor Yellow

$volumes = Get-Volume |
    Where-Object {
        $_.DriveLetter -and
        $_.Size -gt 0
    }

foreach ($volume in $volumes) {

    $freePercent = [math]::Round(
        ($volume.SizeRemaining / $volume.Size) * 100,
        1
    )

    $freeGB = [math]::Round(
        $volume.SizeRemaining / 1GB,
        1
    )

    if ($freePercent -lt 5) {
        $status = "CRITICAL"
    }
    elseif ($freePercent -lt 15) {
        $status = "WARNING"
    }
    else {
        $status = "PASS"
    }

    Add-HealthResult `
        -Check "Disk $($volume.DriveLetter): Free Space" `
        -Status $status `
        -Details "$freeGB GB free ($freePercent%)."
}

# --------------------------------------------------
# Physical Disk Health
# --------------------------------------------------

Write-Host "[+] Checking physical disk health..." -ForegroundColor Yellow

try {

    $physicalDisks = Get-PhysicalDisk

    foreach ($disk in $physicalDisks) {

        if (
            $disk.HealthStatus -eq "Healthy" -and
            $disk.OperationalStatus -contains "OK"
        ) {
            $status = "PASS"
        }
        elseif ($disk.HealthStatus -eq "Unhealthy") {
            $status = "CRITICAL"
        }
        else {
            $status = "WARNING"
        }

        Add-HealthResult `
            -Check "Physical Disk" `
            -Status $status `
            -Details "$($disk.FriendlyName) | Health: $($disk.HealthStatus) | Operational: $($disk.OperationalStatus -join ', ')"
    }

}
catch {

    Add-HealthResult `
        -Check "Physical Disk" `
        -Status "WARNING" `
        -Details "Physical disk health information unavailable."
}

# --------------------------------------------------
# Microsoft Defender
# --------------------------------------------------

Write-Host "[+] Checking Microsoft Defender..." -ForegroundColor Yellow

try {

    $defender = Get-MpComputerStatus

    if (
        $defender.AntivirusEnabled -and
        $defender.RealTimeProtectionEnabled
    ) {

        Add-HealthResult `
            -Check "Microsoft Defender" `
            -Status "PASS" `
            -Details "Antivirus and real-time protection are enabled."

    }
    else {

        Add-HealthResult `
            -Check "Microsoft Defender" `
            -Status "CRITICAL" `
            -Details "Microsoft Defender protection is not fully enabled."

    }

    if ($defender.AntivirusSignatureAge -gt 7) {

        Add-HealthResult `
            -Check "Defender Signatures" `
            -Status "WARNING" `
            -Details "Signatures are $($defender.AntivirusSignatureAge) days old."

    }
    else {

        Add-HealthResult `
            -Check "Defender Signatures" `
            -Status "PASS" `
            -Details "Signature age: $($defender.AntivirusSignatureAge) day(s)."

    }

}
catch {

    Add-HealthResult `
        -Check "Microsoft Defender" `
        -Status "WARNING" `
        -Details "Unable to query Microsoft Defender."
}

# --------------------------------------------------
# Windows Firewall
# --------------------------------------------------

Write-Host "[+] Checking Windows Firewall..." -ForegroundColor Yellow

try {

    $firewallProfiles = Get-NetFirewallProfile

    $disabledProfiles = @(
        $firewallProfiles |
        Where-Object {
            -not $_.Enabled
        }
    )

    if ($disabledProfiles.Count -eq 0) {

        Add-HealthResult `
            -Check "Windows Firewall" `
            -Status "PASS" `
            -Details "All firewall profiles are enabled."

    }
    else {

        Add-HealthResult `
            -Check "Windows Firewall" `
            -Status "WARNING" `
            -Details "Disabled profiles: $($disabledProfiles.Name -join ', ')"

    }

}
catch {

    Add-HealthResult `
        -Check "Windows Firewall" `
        -Status "WARNING" `
        -Details "Unable to query firewall status."
}

# --------------------------------------------------
# Automatic Services
# --------------------------------------------------

Write-Host "[+] Checking automatic services..." -ForegroundColor Yellow

$stoppedServices = @(
    Get-CimInstance Win32_Service |
    Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.State -ne "Running"
    }
)

if ($stoppedServices.Count -eq 0) {

    Add-HealthResult `
        -Check "Automatic Services" `
        -Status "PASS" `
        -Details "All automatic services are running."

}
elseif ($stoppedServices.Count -le 5) {

    Add-HealthResult `
        -Check "Automatic Services" `
        -Status "WARNING" `
        -Details "$($stoppedServices.Count) automatic service(s) are not running."

}
else {

    Add-HealthResult `
        -Check "Automatic Services" `
        -Status "WARNING" `
        -Details "$($stoppedServices.Count) automatic services are not running."
}

# --------------------------------------------------
# Critical Hardware / System Events
# --------------------------------------------------

Write-Host "[+] Checking critical Event Log entries..." -ForegroundColor Yellow

$startTime = (Get-Date).AddDays(-7)

$importantEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        StartTime = $startTime
    } -ErrorAction SilentlyContinue |
    Where-Object {

        (
            $_.ProviderName -eq "Microsoft-Windows-WHEA-Logger"
        ) -or

        (
            $_.ProviderName -match "Disk|Ntfs|StorAHCI|stornvme" -and
            $_.Level -le 2
        ) -or

        (
            $_.ProviderName -eq "Microsoft-Windows-Kernel-Power" -and
            $_.Id -eq 41
        ) -or

        (
            $_.Id -eq 55
        )
    }
)

if ($importantEvents.Count -eq 0) {

    Add-HealthResult `
        -Check "Critical System Events" `
        -Status "PASS" `
        -Details "No major hardware/storage events found in the last 7 days."

}
else {

    Add-HealthResult `
        -Check "Critical System Events" `
        -Status "WARNING" `
        -Details "$($importantEvents.Count) important system event(s) detected during the last 7 days."
}

# --------------------------------------------------
# Pending Restart
# --------------------------------------------------

Write-Host "[+] Checking reboot state..." -ForegroundColor Yellow

$pendingReboot = $false

$rebootKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
)

foreach ($key in $rebootKeys) {

    if (Test-Path $key) {
        $pendingReboot = $true
    }
}

if ($pendingReboot) {

    Add-HealthResult `
        -Check "Pending Restart" `
        -Status "WARNING" `
        -Details "Windows indicates that a restart is pending."

}
else {

    Add-HealthResult `
        -Check "Pending Restart" `
        -Status "PASS" `
        -Details "No pending restart detected."
}

# --------------------------------------------------
# Optional Deep Scan
# --------------------------------------------------

if ($DeepScan) {

    Write-Host ""
    Write-Host "[+] Running deep integrity checks..." -ForegroundColor Magenta
    Write-Host ""

    # CHKDSK

    Write-Host "[+] Running CHKDSK scan..." -ForegroundColor Yellow

    $chkdskOutput = chkdsk C: /scan | Out-String

    if ($chkdskOutput -match "found no problems") {

        Add-HealthResult `
            -Check "CHKDSK" `
            -Status "PASS" `
            -Details "Windows found no filesystem problems."

    }
    else {

        Add-HealthResult `
            -Check "CHKDSK" `
            -Status "WARNING" `
            -Details "CHKDSK did not return a clean result. Review manually."

    }

    # DISM

    Write-Host "[+] Checking Windows component store..." -ForegroundColor Yellow

    $dismOutput = DISM.exe /Online /Cleanup-Image /CheckHealth | Out-String

    if ($dismOutput -match "No component store corruption detected") {

        Add-HealthResult `
            -Check "DISM Component Store" `
            -Status "PASS" `
            -Details "No component store corruption detected."

    }
    elseif ($dismOutput -match "repairable") {

        Add-HealthResult `
            -Check "DISM Component Store" `
            -Status "WARNING" `
            -Details "Windows component store corruption is repairable."

    }
    else {

        Add-HealthResult `
            -Check "DISM Component Store" `
            -Status "WARNING" `
            -Details "Unable to determine component-store health automatically."

    }

    # SFC

    Write-Host "[+] Verifying Windows system files..." -ForegroundColor Yellow

    $sfcOutput = sfc /verifyonly | Out-String

    if (
        $sfcOutput -match
        "Windows Resource Protection did not find any integrity violations"
    ) {

        Add-HealthResult `
            -Check "System File Checker" `
            -Status "PASS" `
            -Details "No Windows system-file integrity violations detected."

    }
    elseif (
        $sfcOutput -match
        "Windows Resource Protection found integrity violations"
    ) {

        Add-HealthResult `
            -Check "System File Checker" `
            -Status "WARNING" `
            -Details "Windows system-file integrity violations were detected."

    }
    else {

        Add-HealthResult `
            -Check "System File Checker" `
            -Status "WARNING" `
            -Details "Unable to determine SFC result automatically."

    }
}

# --------------------------------------------------
# Overall Health
# --------------------------------------------------

$criticalCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "CRITICAL"
    }
).Count

$warningCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "WARNING"
    }
).Count

$passCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "PASS"
    }
).Count

if ($criticalCount -gt 0) {

    $overallHealth = "CRITICAL"
    $healthColor = "Red"

}
elseif ($warningCount -gt 0) {

    $overallHealth = "WARNING"
    $healthColor = "Yellow"

}
else {

    $overallHealth = "HEALTHY"
    $healthColor = "Green"

}

# --------------------------------------------------
# Results
# --------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "                 Health Results"               -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

foreach ($result in $Results) {

    switch ($result.Status) {

        "PASS" {
            Write-Host "[PASS]     " -ForegroundColor Green -NoNewline
        }

        "WARNING" {
            Write-Host "[WARNING]  " -ForegroundColor Yellow -NoNewline
        }

        "CRITICAL" {
            Write-Host "[CRITICAL] " -ForegroundColor Red -NoNewline
        }
    }

    Write-Host "$($result.Check): $($result.Details)"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor $healthColor
Write-Host " OVERALL SYSTEM HEALTH: $overallHealth" -ForegroundColor $healthColor
Write-Host "==============================================" -ForegroundColor $healthColor

Write-Host ""
Write-Host "Passed:   $passCount" -ForegroundColor Green
Write-Host "Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "Critical: $criticalCount" -ForegroundColor Red
Write-Host ""

# --------------------------------------------------
# Exit Code
# --------------------------------------------------

if ($criticalCount -gt 0) {
    exit 2
}
elseif ($warningCount -gt 0) {
    exit 1
}
else {
    exit 0
}