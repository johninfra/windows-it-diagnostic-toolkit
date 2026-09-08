Write-Host "=== System Information ===" -ForegroundColor Cyan

Write-Host "`nComputer:" -ForegroundColor Yellow
Write-Host $env:COMPUTERNAME

Write-Host "`nCurrent User:" -ForegroundColor Yellow
Write-Host $env:USERNAME

Write-Host "`nOperating System:" -ForegroundColor Yellow
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, OSArchitecture |
    Format-Table -AutoSize |
    Out-Host

Write-Host "`nIP Configuration:" -ForegroundColor Yellow
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" } |
    Select-Object InterfaceAlias, IPAddress |
    Format-Table -AutoSize |
    Out-Host

Write-Host "`nDisk Space:" -ForegroundColor Yellow
Get-Volume |
    Where-Object DriveLetter |
    Select-Object DriveLetter,
        @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
        @{Name="FreeGB";Expression={[math]::Round($_.SizeRemaining/1GB,2)}} |
    Format-Table -AutoSize |
    Out-Host