# Launches the Live Deception Split-Screen Demo verification on Windows.
param(
    [switch]$OpenBrowser
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   DECEPTION SOC - LIVE IN-SESSION DIVERSION SHOWCASE     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Check services
$proxyUp = $false
try {
    $res = Invoke-WebRequest -Uri "http://127.0.0.1:8200/" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res.StatusCode -lt 500) { $proxyUp = $true }
} catch {
    $proxyUp = $false
}

$coreUp = $false
try {
    $res = Invoke-WebRequest -Uri "http://127.0.0.1:8090/healthz" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res.StatusCode -eq 200) { $coreUp = $true }
} catch {
    $coreUp = $false
}

$dashUp = $false
try {
    $res = Invoke-WebRequest -Uri "http://127.0.0.1:3000/login" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res.StatusCode -lt 500) { $dashUp = $true }
} catch {
    $dashUp = $false
}

Write-Host "Service Status:" -ForegroundColor Yellow
Write-Host "  Divert Proxy (:8200) : " -NoNewline
if ($proxyUp) { Write-Host "ONLINE" -ForegroundColor Green } else { Write-Host "OFFLINE (run cmd/divert-proxy)" -ForegroundColor Red }

Write-Host "  Go Core API  (:8090) : " -NoNewline
if ($coreUp) { Write-Host "ONLINE" -ForegroundColor Green } else { Write-Host "OFFLINE (run scripts/dev-up.ps1)" -ForegroundColor Red }

Write-Host "  Dashboard    (:3000) : " -NoNewline
if ($dashUp) { Write-Host "ONLINE" -ForegroundColor Green } else { Write-Host "OFFLINE (run npm run dev in frontend/nextjs)" -ForegroundColor Red }

Write-Host ""
Write-Host "Live Split Demo URL:" -ForegroundColor Yellow
Write-Host "  http://localhost:3000/live-demo" -ForegroundColor Cyan
Write-Host ""

if ($OpenBrowser -or $dashUp) {
    Start-Process "http://localhost:3000/live-demo"
}

