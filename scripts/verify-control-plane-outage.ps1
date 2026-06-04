param(
    [string]$ChenHost = "chen-win",
    [string]$CoordinatorProcessName = "wink-coordinator",
    [string]$RestartTaskName = "WinkYouCoordinator",
    [string]$WinkPath = "dist\wink-windows-amd64.exe",
    [string]$ConfigPath = "$env:LOCALAPPDATA\Temp\winkyou-p2p-test\local-a.yaml",
    [string]$StatePath = "$env:LOCALAPPDATA\Temp\winkyou-p2p-test\local.runtime.json",
    [string]$PingTarget = "10.88.0.1",
    [int]$ObserveSeconds = 20
)

$ErrorActionPreference = "Stop"

function Invoke-Ssh {
    param(
        [string]$HostName,
        [string]$Command
    )
    ssh -o BatchMode=yes -o ConnectTimeout=8 $HostName $Command
}

function Show-Peers {
    param([string]$Label)
    Write-Host ""
    Write-Host "== $Label =="
    & $WinkPath --config $ConfigPath --state $StatePath peers
}

function Test-OverlayPing {
    param([string]$Label)
    Write-Host ""
    Write-Host "== $Label ping $PingTarget =="
    ping -n 3 $PingTarget
}

if (!(Test-Path $WinkPath)) {
    throw "wink binary not found: $WinkPath"
}
if (!(Test-Path $ConfigPath)) {
    throw "config not found: $ConfigPath"
}
if (!(Test-Path $StatePath)) {
    throw "runtime state not found: $StatePath"
}

Write-Host "Checking SSH access to $ChenHost..."
Invoke-Ssh -HostName $ChenHost -Command "hostname" | Out-Host

Show-Peers -Label "before coordinator stop"
Test-OverlayPing -Label "before coordinator stop"

try {
    Write-Host ""
    Write-Host "Stopping coordinator process on $ChenHost without touching natpierce/underlay..."
    $stopCommand = "powershell -NoProfile -Command `"Get-Process -Name '$CoordinatorProcessName' -ErrorAction SilentlyContinue | Stop-Process -Force`""
    Invoke-Ssh -HostName $ChenHost -Command $stopCommand | Out-Host

    Start-Sleep -Seconds $ObserveSeconds

    Show-Peers -Label "after coordinator stop"
    Test-OverlayPing -Label "after coordinator stop"
} finally {
    if ($RestartTaskName -ne "") {
        Write-Host ""
        Write-Host "Restarting coordinator task on ${ChenHost}: $RestartTaskName"
        $restartCommand = "powershell -NoProfile -Command `"Start-ScheduledTask -TaskName '$RestartTaskName'`""
        try {
            Invoke-Ssh -HostName $ChenHost -Command $restartCommand | Out-Host
        } catch {
            Write-Warning "failed to restart scheduled task '$RestartTaskName': $_"
        }
    }
}
