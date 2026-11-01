$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location "$RootDir\backend\go"
Get-Content "$RootDir\.env" | Where-Object { $_ -match '^\s*([^#=]+)=(.*)$' } | ForEach-Object {
    $name = $matches[1].Trim()
    $val = $matches[2].Trim().Trim("'").Trim('"')
    Set-Item -Path "env:$name" -Value $val
}
$env:SENSOR_ID = "aetees-01"
$env:SENSOR_KEY = $env:KEY_AETEES
$env:LISTEN_ADDR = ":8200"
$env:REAL_URL = "http://127.0.0.1:3100"
$env:CLONE_URL = "http://127.0.0.1:3101"
$env:CORE_URL = "http://127.0.0.1:8443"
$env:DATA_DIR = "$RootDir\.data\aetees"
& "$RootDir\backend\go\bin\divert-proxy.exe"

