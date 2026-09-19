# ============================================
# Windows IT Diagnostic Tool
# ============================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Windows IT Diagnostic Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# --------------------------------------------
# Create Reports Folder
# --------------------------------------------

$reportFolder = "C:\DiagnosticReports"

if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $reportFolder "IT-Diagnostic-$timestamp.html"

# --------------------------------------------
# Administrative Status
# --------------------------------------------

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# --------------------------------------------
# Operating System
# --------------------------------------------

Write-Host "[+] Collecting operating system information..." -ForegroundColor Yellow

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem

$uptime = (Get-Date) - $os.LastBootUpTime

$systemSummary = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    CurrentUser  = $env:USERNAME
    Manufacturer = $computer.Manufacturer
    Model        = $computer.Model
    Windows      = $os.Caption
    Version      = $os.Version
    Architecture = $os.OSArchitecture
    LastBoot     = $os.LastBootUpTime
    UptimeDays   = [math]::Round($uptime.TotalDays, 2)
    AdminSession = $isAdmin
}

# --------------------------------------------
# CPU
# --------------------------------------------

Write-Host "[+] Checking CPU..." -ForegroundColor Yellow

$cpu = Get-CimInstance Win32_Processor |
    Select-Object Name,
        NumberOfCores,
        NumberOfLogicalProcessors,
        LoadPercentage

# --------------------------------------------
# Memory
# --------------------------------------------

Write-Host "[+] Checking memory..." -ForegroundColor Yellow

$totalMemoryGB = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)

$freeMemoryGB = [math]::Round(
    $os.FreePhysicalMemory / 1MB,
    2
)

$usedMemoryGB = [math]::Round(
    $totalMemoryGB - $freeMemoryGB,
    2
)

$memoryUsagePercent = if ($totalMemoryGB -gt 0) {
    [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 2)
}
else {
    0
}

$memory = [PSCustomObject]@{
    TotalGB      = $totalMemoryGB
    UsedGB       = $usedMemoryGB
    FreeGB       = $freeMemoryGB
    PercentUsed  = $memoryUsagePercent
}

# --------------------------------------------
# Disk Space
# --------------------------------------------

Write-Host "[+] Checking disk space..." -ForegroundColor Yellow

$disks = Get-Volume |
    Where-Object {
        $_.DriveLetter -and
        $_.Size -gt 0
    } |
    ForEach-Object {

        $freePercent = [math]::Round(
            ($_.SizeRemaining / $_.Size) * 100,
            2
        )

        [PSCustomObject]@{
            Drive       = "$($_.DriveLetter):"
            Label       = $_.FileSystemLabel
            FileSystem  = $_.FileSystem
            SizeGB      = [math]::Round($_.Size / 1GB, 2)
            FreeGB      = [math]::Round($_.SizeRemaining / 1GB, 2)
            FreePercent = $freePercent
        }
    }

# --------------------------------------------
# Network Configuration
# --------------------------------------------

Write-Host "[+] Collecting network configuration..." -ForegroundColor Yellow

$network = Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4Address
    } |
    ForEach-Object {

        [PSCustomObject]@{
            Interface = $_.InterfaceAlias

            IPv4 = (
                $_.IPv4Address.IPAddress -join ", "
            )

            Gateway = (
                $_.IPv4DefaultGateway.NextHop -join ", "
            )

            DNS = (
                $_.DNSServer.ServerAddresses -join ", "
            )
        }
    }

# --------------------------------------------
# Internet Connectivity
# --------------------------------------------

Write-Host "[+] Testing network connectivity..." -ForegroundColor Yellow

$gatewayTest = $false
$internetTest = $false
$dnsTest = $false

$defaultGateway = (
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
    Sort-Object RouteMetric |
    Select-Object -First 1
).NextHop

if ($defaultGateway) {
    $gatewayTest = Test-Connection `
        -ComputerName $defaultGateway `
        -Count 1 `
        -Quiet
}

$internetTest = Test-Connection `
    -ComputerName "1.1.1.1" `
    -Count 1 `
    -Quiet

try {
    Resolve-DnsName "microsoft.com" -ErrorAction Stop | Out-Null
    $dnsTest = $true
}
catch {
    $dnsTest = $false
}

$connectivity = [PSCustomObject]@{
    DefaultGateway      = $defaultGateway
    GatewayReachable    = $gatewayTest
    InternetReachable   = $internetTest
    DNSResolutionWorks  = $dnsTest
}

# --------------------------------------------
# Windows Defender
# --------------------------------------------

Write-Host "[+] Checking Microsoft Defender..." -ForegroundColor Yellow

try {

    $defenderStatus = Get-MpComputerStatus

    $defender = [PSCustomObject]@{
        AntivirusEnabled        = $defenderStatus.AntivirusEnabled
        RealTimeProtection      = $defenderStatus.RealTimeProtectionEnabled
        BehaviorMonitor         = $defenderStatus.BehaviorMonitorEnabled
        AntivirusSignatureAge   = $defenderStatus.AntivirusSignatureAge
        QuickScanAge            = $defenderStatus.QuickScanAge
        FullScanAge             = $defenderStatus.FullScanAge
    }

}
catch {

    $defender = [PSCustomObject]@{
        Status = "Microsoft Defender information unavailable."
    }

}

# --------------------------------------------
# Windows Firewall
# --------------------------------------------

Write-Host "[+] Checking Windows Firewall..." -ForegroundColor Yellow

try {

    $firewall = Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

}
catch {

    $firewall = [PSCustomObject]@{
        Status = "Firewall information unavailable."
    }

}

# --------------------------------------------
# Automatic Services That Are Not Running
# --------------------------------------------

Write-Host "[+] Checking Windows services..." -ForegroundColor Yellow

$stoppedServices = Get-CimInstance Win32_Service |
    Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.State -ne "Running"
    } |
    Select-Object Name,
        DisplayName,
        State,
        StartMode

# --------------------------------------------
# Recent Critical / Error Events
# --------------------------------------------

Write-Host "[+] Checking Windows Event Logs..." -ForegroundColor Yellow

try {

    $events = Get-WinEvent `
        -FilterHashtable @{
            LogName   = "System"
            Level     = 1,2
            StartTime = (Get-Date).AddHours(-24)
        } `
        -MaxEvents 20 |
        Select-Object TimeCreated,
            Id,
            ProviderName,
            LevelDisplayName,
            Message

}
catch {

    $events = [PSCustomObject]@{
        Status = "No events found or event log access unavailable."
    }

}

# --------------------------------------------
# HTML Styling
# --------------------------------------------

$style = @"

<style>

body {
    font-family: Segoe UI, Arial, sans-serif;
    background-color: #111827;
    color: #e5e7eb;
    margin: 40px;
}

h1 {
    color: #60a5fa;
}

h2 {
    color: #93c5fd;
    border-bottom: 1px solid #374151;
    padding-bottom: 8px;
    margin-top: 35px;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 20px;
}

th {
    background-color: #1f2937;
    color: #93c5fd;
    text-align: left;
    padding: 10px;
}

td {
    border-bottom: 1px solid #374151;
    padding: 9px;
}

tr:hover {
    background-color: #1f2937;
}

.summary {
    background-color: #1f2937;
    padding: 20px;
    border-radius: 8px;
}

.footer {
    margin-top: 40px;
    color: #9ca3af;
    font-size: 12px;
}

</style>

"@

# --------------------------------------------
# Build HTML Report
# --------------------------------------------

$html = @"

<!DOCTYPE html>

<html>

<head>

<title>Windows IT Diagnostic Report</title>

$style

</head>

<body>

<h1>Windows IT Diagnostic Report</h1>

<div class="summary">

<strong>Computer:</strong> $env:COMPUTERNAME

<br>

<strong>Generated:</strong> $(Get-Date)

<br>

<strong>Administrator Session:</strong> $isAdmin

</div>

<h2>System Summary</h2>

$($systemSummary | ConvertTo-Html -Fragment)

<h2>CPU</h2>

$($cpu | ConvertTo-Html -Fragment)

<h2>Memory</h2>

$($memory | ConvertTo-Html -Fragment)

<h2>Disk Space</h2>

$($disks | ConvertTo-Html -Fragment)

<h2>Network Configuration</h2>

$($network | ConvertTo-Html -Fragment)

<h2>Connectivity Tests</h2>

$($connectivity | ConvertTo-Html -Fragment)

<h2>Microsoft Defender</h2>

$($defender | ConvertTo-Html -Fragment)

<h2>Windows Firewall</h2>

$($firewall | ConvertTo-Html -Fragment)

<h2>Automatic Services Not Running</h2>

$($stoppedServices | ConvertTo-Html -Fragment)

<h2>Critical / Error Events - Last 24 Hours</h2>

$($events | ConvertTo-Html -Fragment)

<div class="footer">

Generated by Windows IT Diagnostic Tool

</div>

</body>

</html>

"@

# --------------------------------------------
# Save Report
# --------------------------------------------

$html | Out-File `
    -FilePath $reportPath `
    -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Diagnostic Complete" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

Write-Host "`nReport saved to:" -ForegroundColor Cyan
Write-Host $reportPath

# Automatically open report
Start-Process $reportPath
