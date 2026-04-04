$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Python virtual environment was not found at $python"
}

$samplePidFile = Join-Path $projectRoot ".sample_backend.pid"
$serverPidFile = Join-Path $projectRoot ".server.pid"

function Start-ManagedProcess {
    param(
        [string]$ScriptPath,
        [string]$PidFile,
        [hashtable]$Environment = @{}
    )

    if (Test-Path $PidFile) {
        $existingId = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($existingId) {
            try {
                Get-Process -Id ([int]$existingId) -ErrorAction Stop | Out-Null
                return [int]$existingId
            } catch {
            }
        }
    }

    $argumentList = @($ScriptPath)
    $process = Start-Process -FilePath $python -ArgumentList $argumentList -PassThru -WindowStyle Hidden
    $process.Id | Set-Content $PidFile
    return $process.Id
}

$env:WAF_HOST = "0.0.0.0"
$env:WAF_TRANSPARENT_PROXY = "true"

$samplePid = Start-ManagedProcess -ScriptPath "sample_backend.py" -PidFile $samplePidFile
$wafPid = Start-ManagedProcess -ScriptPath "serve.py" -PidFile $serverPidFile

Write-Host "Sample backend PID: $samplePid"
Write-Host "WAF PID: $wafPid"
Write-Host "LAN URL: http://192.168.69.7:5000/"
Write-Host "Dashboard: http://192.168.69.7:5000/dashboard/"
