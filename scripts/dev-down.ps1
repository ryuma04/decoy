# Stop all running Deception SOC processes
Write-Host "Stopping Deception SOC processes..." -ForegroundColor Cyan

$targets = @("core", "decoy-ssh", "decoy-web", "decoy-k8s", "decoy-beacon")
foreach ($t in $targets) {
    Get-Process -Name $t -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Stopping $($_.ProcessName) (PID $($_.Id))" -ForegroundColor Yellow
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

# Kill node process listening on port 3000
$port3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($port3000) {
    $pids = $port3000 | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($p in $pids) {
        if ($p -gt 0) {
            Write-Host "  Stopping process on port 3000 (PID $p)" -ForegroundColor Yellow
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "All processes stopped." -ForegroundColor Green

