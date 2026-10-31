# Start all Deception SOC components on Windows
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "     Starting Deception SOC Services     " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Stop any previous instances
if (Test-Path "$ScriptDir\dev-down.ps1") {
    & "$ScriptDir\dev-down.ps1"
}

# Create log and data directories
$LogDir = Join-Path $RootDir ".logs"
$DataDir = Join-Path $RootDir ".data"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (!(Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

# Load .env into process environment
$EnvPath = Join-Path $RootDir ".env"
if (!(Test-Path $EnvPath)) {
    Write-Error "Missing .env file in $RootDir"
    exit 1
}

Get-Content $EnvPath | Where-Object { $_ -match '^\s*([^#=]+)=(.*)$' } | ForEach-Object {
    $name = $matches[1].Trim()
    $val = $matches[2].Trim().Trim("'").Trim('"')
    Set-Item -Path "env:$name" -Value $val
}

$env:SENSOR_ADDR = "127.0.0.1:8443"
$env:ANALYST_ADDR = "127.0.0.1:8090"
$env:CORE_URL = "http://127.0.0.1:8443"

$BinDir = Join-Path $RootDir "backend\go\bin"
$SeedDir = Join-Path $RootDir "backend\go\seed"

# Ensure seed exists
if (!(Test-Path "$SeedDir\out\tokens.json")) {
    Write-Host "Generating seed tokens and persona..." -ForegroundColor Yellow
    Push-Location "$RootDir\backend\go"
    go run ./cmd/seed
    Pop-Location
}

# 1. Start Core
Write-Host "`n[1/6] Starting Core (sensor :8443, analyst :8090)..." -ForegroundColor Yellow
$CoreLog = Join-Path $LogDir "core.log"
$CoreErr = Join-Path $LogDir "core_err.log"
Start-Process -FilePath "$BinDir\core.exe" -ArgumentList "serve" -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $CoreLog -RedirectStandardError $CoreErr | Out-Null
Start-Sleep -Seconds 3

# Wait for core to be healthy
$coreOk = $false
for ($i = 0; $i -lt 15; $i++) {
    try {
        $res = Invoke-WebRequest -Uri "http://127.0.0.1:8090/healthz" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($res.StatusCode -eq 200) { $coreOk = $true; break }
    } catch {}
    Start-Sleep -Seconds 1
}
if ($coreOk) {
    Write-Host "  Core is UP and healthy!" -ForegroundColor Green
} else {
    Write-Host "  Core starting up (check $CoreErr)" -ForegroundColor Yellow
}

# 2. Start SSH Decoy (:2222)
Write-Host "`n[2/6] Starting SSH Decoy (:2222)..." -ForegroundColor Yellow
$SshData = Join-Path $DataDir "ssh"
if (!(Test-Path $SshData)) { New-Item -ItemType Directory -Path $SshData -Force | Out-Null }
$SshLog = Join-Path $LogDir "decoy-ssh.log"
$SshErr = Join-Path $LogDir "decoy-ssh_err.log"
Set-Item -Path "env:SENSOR_ID" -Value "ssh-01"
Set-Item -Path "env:SENSOR_KEY" -Value $env:KEY_SSH
Set-Item -Path "env:LISTEN_ADDR" -Value ":2222"
Set-Item -Path "env:DATA_DIR" -Value $SshData
Set-Item -Path "env:SEED_DIR" -Value $SeedDir
Start-Process -FilePath "$BinDir\decoy-ssh.exe" -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $SshLog -RedirectStandardError $SshErr | Out-Null
Write-Host "  SSH Decoy running on :2222" -ForegroundColor Green

# 3. Start Web Decoy (:8080)
Write-Host "`n[3/6] Starting Web Decoy (:8080)..." -ForegroundColor Yellow
$WebData = Join-Path $DataDir "web"
if (!(Test-Path $WebData)) { New-Item -ItemType Directory -Path $WebData -Force | Out-Null }
$WebLog = Join-Path $LogDir "decoy-web.log"
$WebErr = Join-Path $LogDir "decoy-web_err.log"
Set-Item -Path "env:SENSOR_ID" -Value "web-01"
Set-Item -Path "env:SENSOR_KEY" -Value $env:KEY_WEB
Set-Item -Path "env:LISTEN_ADDR" -Value ":8080"
Set-Item -Path "env:DATA_DIR" -Value $WebData
Start-Process -FilePath "$BinDir\decoy-web.exe" -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $WebLog -RedirectStandardError $WebErr | Out-Null
Write-Host "  Web Decoy running on :8080" -ForegroundColor Green

# 4. Start Beacon Decoy (:8088)
Write-Host "`n[4/6] Starting Beacon Decoy (:8088)..." -ForegroundColor Yellow
$BeaconData = Join-Path $DataDir "beacon"
if (!(Test-Path $BeaconData)) { New-Item -ItemType Directory -Path $BeaconData -Force | Out-Null }
$BeaconLog = Join-Path $LogDir "decoy-beacon.log"
$BeaconErr = Join-Path $LogDir "decoy-beacon_err.log"
Set-Item -Path "env:SENSOR_ID" -Value "beacon-01"
Set-Item -Path "env:SENSOR_KEY" -Value $env:KEY_BEACON
Set-Item -Path "env:LISTEN_ADDR" -Value ":8088"
Set-Item -Path "env:DATA_DIR" -Value $BeaconData
Start-Process -FilePath "$BinDir\decoy-beacon.exe" -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $BeaconLog -RedirectStandardError $BeaconErr | Out-Null
Write-Host "  Beacon Decoy running on :8088" -ForegroundColor Green

# 5. Start Kubernetes API Decoy (:6443)
Write-Host "`n[5/6] Starting Kubernetes Decoy (:6443)..." -ForegroundColor Yellow
$K8sData = Join-Path $DataDir "k8s"
if (!(Test-Path $K8sData)) { New-Item -ItemType Directory -Path $K8sData -Force | Out-Null }
$K8sLog = Join-Path $LogDir "decoy-k8s.log"
$K8sErr = Join-Path $LogDir "decoy-k8s_err.log"
Set-Item -Path "env:SENSOR_ID" -Value "k8s-01"
Set-Item -Path "env:SENSOR_KEY" -Value $env:KEY_K8S
Set-Item -Path "env:LISTEN_ADDR" -Value ":6443"
Set-Item -Path "env:DATA_DIR" -Value $K8sData
Start-Process -FilePath "$BinDir\decoy-k8s.exe" -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $K8sLog -RedirectStandardError $K8sErr | Out-Null
Write-Host "  K8s API Decoy running on :6443" -ForegroundColor Green

# 6. Start Dashboard (:3000)
Write-Host "`n[6/6] Starting Dashboard (http://localhost:3000)..." -ForegroundColor Yellow
$DashLog = Join-Path $LogDir "dashboard.log"
$DashErr = Join-Path $LogDir "dashboard_err.log"
$FrontendDir = Join-Path $RootDir "frontend\nextjs"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm run dev" -WorkingDirectory $FrontendDir -RedirectStandardOutput $DashLog -RedirectStandardError $DashErr | Out-Null
Write-Host "  Dashboard starting on http://localhost:3000" -ForegroundColor Green

# Optional: Start Divert Proxy if built and lab is present
$DivertExe = Join-Path $BinDir "divert-proxy.exe"
if (Test-Path $DivertExe) {
    $AeteesData = Join-Path $DataDir "aetees"
    if (!(Test-Path $AeteesData)) { New-Item -ItemType Directory -Path $AeteesData -Force | Out-Null }
    $DivertLog = Join-Path $LogDir "divert-proxy.log"
    $DivertErr = Join-Path $LogDir "divert-proxy_err.log"
    Set-Item -Path "env:SENSOR_ID" -Value "aetees-01"
    Set-Item -Path "env:SENSOR_KEY" -Value ($env:KEY_AETEES)
    Set-Item -Path "env:LISTEN_ADDR" -Value ":8200"
    Set-Item -Path "env:REAL_URL" -Value "http://127.0.0.1:3100"
    Set-Item -Path "env:CLONE_URL" -Value "http://127.0.0.1:3101"
    Set-Item -Path "env:DATA_DIR" -Value $AeteesData
    Start-Process -FilePath $DivertExe -WorkingDirectory "$RootDir\backend\go" -RedirectStandardOutput $DivertLog -RedirectStandardError $DivertErr | Out-Null
    Write-Host "  Divert Proxy running on :8200" -ForegroundColor Green
}

Start-Sleep -Seconds 3

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "             All Services Running!                      " -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Dashboard:     http://localhost:3000" -ForegroundColor White
Write-Host "                 User:     $($env:SOC_ADMIN_EMAIL)" -ForegroundColor Gray
Write-Host "                 Password: $($env:SOC_ADMIN_PASSWORD)" -ForegroundColor Gray
Write-Host "  Web Decoy:     http://localhost:8080" -ForegroundColor White
Write-Host "  SSH Decoy:     ssh -p 2222 deploy@localhost" -ForegroundColor White
Write-Host "  Beacon Decoy:  http://localhost:8088" -ForegroundColor White
Write-Host "  K8s API Decoy: https://localhost:6443" -ForegroundColor White
if (Test-Path $DivertExe) {
    Write-Host "  Divert Proxy:  http://localhost:8200" -ForegroundColor White
}
Write-Host "========================================================" -ForegroundColor Green
Write-Host "To stop all services anytime, run: .\scripts\dev-down.ps1`n" -ForegroundColor DarkGray
