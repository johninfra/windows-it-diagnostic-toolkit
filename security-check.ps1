# Windows IT Diagnostic Toolkit
# Security Check
# Performs common Windows endpoint security checks.

Write-Host "`n=== Windows Security Check ===" -ForegroundColor Cyan

# ---------------------------------------------------------
# Administrator Check
# ---------------------------------------------------------

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if ($isAdmin) {
    Write-Host "`n[PASS] PowerShell is running as Administrator." -ForegroundColor Green
}
else {
    Write-Host "`n[WARNING] PowerShell is not running as Administrator." -ForegroundColor Yellow
    Write-Host "Some security checks may return limited information." -ForegroundColor Yellow
}

# ---------------------------------------------------------
# Microsoft Defender Status
# ---------------------------------------------------------

Write-Host "`n--- Microsoft Defender ---" -ForegroundColor Cyan

try {

    $defender = Get-MpComputerStatus -ErrorAction Stop

    Write-Host "Antivirus Enabled: $($defender.AntivirusEnabled)"
    Write-Host "Antispyware Enabled: $($defender.AntispywareEnabled)"
    Write-Host "Real-Time Protection: $($defender.RealTimeProtectionEnabled)"
    Write-Host "Behavior Monitoring: $($defender.BehaviorMonitorEnabled)"

    if (
        $defender.AntivirusEnabled -and
        $defender.RealTimeProtectionEnabled
    ) {
        Write-Host "[PASS] Microsoft Defender protection is active." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] Microsoft Defender protection may not be fully enabled." -ForegroundColor Yellow
    }

}
catch {
    Write-Host "[ERROR] Unable to retrieve Microsoft Defender status." -ForegroundColor Red
}

# ---------------------------------------------------------
# Defender Signature Information
# ---------------------------------------------------------

Write-Host "`n--- Defender Signatures ---" -ForegroundColor Cyan

try {

    $defender = Get-MpComputerStatus -ErrorAction Stop

    Write-Host "Signature Version: $($defender.AntivirusSignatureVersion)"
    Write-Host "Last Signature Update: $($defender.AntivirusSignatureLastUpdated)"

}
catch {
    Write-Host "[ERROR] Unable to retrieve Defender signature information." -ForegroundColor Red
}

# ---------------------------------------------------------
# Windows Firewall
# ---------------------------------------------------------

Write-Host "`n--- Windows Firewall ---" -ForegroundColor Cyan

try {

    $firewallProfiles = Get-NetFirewallProfile

    foreach ($firewallProfile in $firewallProfiles) {

        $status = if ($firewallProfile.Enabled) {
            "ENABLED"
        }
        else {
            "DISABLED"
        }

        Write-Host "$($firewallProfile.Name): $status"

        if (-not $firewallProfile.Enabled) {
            Write-Host "[WARNING] $($firewallProfile.Name) firewall profile is disabled." -ForegroundColor Yellow
        }

    }

    if ($firewallProfiles.Enabled -notcontains $false) {
        Write-Host "[PASS] All Windows Firewall profiles are enabled." -ForegroundColor Green
    }

}
catch {
    Write-Host "[ERROR] Unable to retrieve Windows Firewall status." -ForegroundColor Red
}

# ---------------------------------------------------------
# Secure Boot
# ---------------------------------------------------------

Write-Host "`n--- Secure Boot ---" -ForegroundColor Cyan

try {

    $secureBoot = Confirm-SecureBootUEFI

    if ($secureBoot) {
        Write-Host "[PASS] Secure Boot is enabled." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] Secure Boot is disabled." -ForegroundColor Yellow
    }

}
catch {
    Write-Host "[INFO] Secure Boot status could not be determined." -ForegroundColor Yellow
}

# ---------------------------------------------------------
# BitLocker
# ---------------------------------------------------------

Write-Host "`n--- BitLocker ---" -ForegroundColor Cyan

try {

    $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

    Write-Host "System Drive: $($bitlocker.MountPoint)"
    Write-Host "Protection Status: $($bitlocker.ProtectionStatus)"
    Write-Host "Encryption Method: $($bitlocker.EncryptionMethod)"

    if ($bitlocker.ProtectionStatus -eq "On") {
        Write-Host "[PASS] BitLocker protection is enabled." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] BitLocker protection is not enabled." -ForegroundColor Yellow
    }

}
catch {
    Write-Host "[INFO] BitLocker status could not be retrieved." -ForegroundColor Yellow
}

# ---------------------------------------------------------
# User Account Control
# ---------------------------------------------------------

Write-Host "`n--- User Account Control (UAC) ---" -ForegroundColor Cyan

try {

    $uac = Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name EnableLUA `
        -ErrorAction Stop

    if ($uac.EnableLUA -eq 1) {
        Write-Host "[PASS] User Account Control is enabled." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] User Account Control is disabled." -ForegroundColor Yellow
    }

}
catch {
    Write-Host "[ERROR] Unable to determine UAC status." -ForegroundColor Red
}

# ---------------------------------------------------------
# Windows Update Service
# ---------------------------------------------------------

Write-Host "`n--- Windows Update Service ---" -ForegroundColor Cyan

try {

    $windowsUpdate = Get-Service -Name wuauserv -ErrorAction Stop

    Write-Host "Status: $($windowsUpdate.Status)"
    Write-Host "Start Type: $($windowsUpdate.StartType)"

    if ($windowsUpdate.StartType -eq "Disabled") {
        Write-Host "[WARNING] Windows Update service is disabled." -ForegroundColor Yellow
    }
    else {
        Write-Host "[PASS] Windows Update service is not disabled." -ForegroundColor Green
    }

}
catch {
    Write-Host "[ERROR] Unable to retrieve Windows Update service status." -ForegroundColor Red
}

# ---------------------------------------------------------
# Remote Desktop
# ---------------------------------------------------------

Write-Host "`n--- Remote Desktop ---" -ForegroundColor Cyan

try {

    $rdp = Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name fDenyTSConnections `
        -ErrorAction Stop

    if ($rdp.fDenyTSConnections -eq 0) {
        Write-Host "[INFO] Remote Desktop is enabled." -ForegroundColor Yellow
    }
    else {
        Write-Host "[PASS] Remote Desktop is disabled." -ForegroundColor Green
    }

}
catch {
    Write-Host "[ERROR] Unable to determine Remote Desktop status." -ForegroundColor Red
}

# ---------------------------------------------------------
# SMBv1
# ---------------------------------------------------------

Write-Host "`n--- SMBv1 Protocol ---" -ForegroundColor Cyan

try {

    $smb1 = Get-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol `
        -ErrorAction Stop

    if ($smb1.State -eq "Enabled") {
        Write-Host "[WARNING] SMBv1 is enabled." -ForegroundColor Yellow
        Write-Host "SMBv1 is obsolete and should normally remain disabled." -ForegroundColor Yellow
    }
    else {
        Write-Host "[PASS] SMBv1 is disabled." -ForegroundColor Green
    }

}
catch {
    Write-Host "[INFO] Unable to determine SMBv1 status." -ForegroundColor Yellow
}

# ---------------------------------------------------------
# Final Message
# ---------------------------------------------------------

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Security check complete." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan