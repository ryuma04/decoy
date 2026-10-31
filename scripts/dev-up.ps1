# PowerShell script to load .env and run services locally
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path "$Root\.env")) {
    Write-Error "Missing .env in $Root"
}

Write-Host "Loading environment variables from .env..."
Get-Content "$Root\.env" | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $idx = $line.IndexOf("=")
        if ($idx -gt 0) {
            $key = $line.Substring(0, $idx).Trim()
            $val = $line.Substring($idx + 1).Trim().Trim("'").Trim('"')
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

Write-Host "1. Running seed (persona + tokens)..."
Push-Location "$Root\backend\go"
try {
    go run ./cmd/seed
} finally {
    Pop-Location
}

Write-Host "`nEnvironment seeded successfully!"
Write-Host "To run the full stack, choose either:"
Write-Host "  A) Docker: docker compose --profile decoys --profile ui up --build"
Write-Host "  B) Local:  Start each service in a separate PowerShell window using the commands provided."

