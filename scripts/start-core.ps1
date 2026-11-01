$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location "$RootDir\backend\go"
Get-Content "$RootDir\.env" | Where-Object { $_ -match '^\s*([^#=]+)=(.*)$' } | ForEach-Object {
    $name = $matches[1].Trim()
    $val = $matches[2].Trim().Trim("'").Trim('"')
    Set-Item -Path "env:$name" -Value $val
}
$env:SENSOR_ADDR = "127.0.0.1:8443"
$env:ANALYST_ADDR = "127.0.0.1:8090"
$env:CORE_URL = "http://127.0.0.1:8443"
& "$RootDir\backend\go\bin\core.exe" serve
