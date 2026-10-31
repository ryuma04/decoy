# Decoys must never execute anything (06, backend/CLAUDE.md). Fails if decoy code imports process-starting APIs.
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir
Set-Location $BaseDir

$dirs = @("internal/decoy", "cmd/decoy-ssh", "cmd/decoy-web", "cmd/decoy-k8s", "cmd/decoy-beacon", "cmd/decoy-db", "internal/sensorkit", "internal/fakefs", "internal/divert", "cmd/divert-proxy")
$pattern = '"os/exec"|syscall\.(Exec|ForkExec|StartProcess)|os\.StartProcess|"plugin"|unsafe\.'
$bad = @()

foreach ($d in $dirs) {
    if (Test-Path $d) {
        $files = Get-ChildItem -Path $d -Filter "*.go" -Recurse
        foreach ($f in $files) {
            $matches = Select-String -Path $f.FullName -Pattern $pattern
            if ($matches) {
                $bad += $matches
            }
        }
    }
}

if ($bad.Count -gt 0) {
    Write-Host "check-no-exec: forbidden API in decoy code:" -ForegroundColor Red
    $bad | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host "check-no-exec: ok ($($dirs -join ' '))"

