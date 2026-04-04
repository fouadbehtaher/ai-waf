$ErrorActionPreference = "Stop"

$ruleName = "WAF AI LAN 5000"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if (-not $existing) {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5000 `
        -Profile Private | Out-Null
    Write-Host "Firewall rule created: $ruleName"
} else {
    Write-Host "Firewall rule already exists: $ruleName"
}
