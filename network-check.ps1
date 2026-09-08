Write-Host "=== Network Check ===" -ForegroundColor Cyan

Write-Host "`nIP Configuration:" -ForegroundColor Yellow
Get-NetIPConfiguration |
    Select-Object InterfaceAlias,
                  IPv4Address,
                  IPv4DefaultGateway,
                  DNSServer

Write-Host "`nTesting Internet Connectivity:" -ForegroundColor Yellow

if (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet) {
    Write-Host "Internet connectivity: PASS" -ForegroundColor Green
}
else {
    Write-Host "Internet connectivity: FAIL" -ForegroundColor Red
}

Write-Host "`nTesting DNS Resolution:" -ForegroundColor Yellow

try {
    Resolve-DnsName microsoft.com -ErrorAction Stop | Out-Null
    Write-Host "DNS resolution: PASS" -ForegroundColor Green
}
catch {
    Write-Host "DNS resolution: FAIL" -ForegroundColor Red
}