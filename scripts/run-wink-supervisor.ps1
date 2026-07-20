#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$WinkExe = "",

    [string]$Config = "",

    [string]$State = "",

    [string]$WorkingDirectory = "",

    [string]$SupervisorLog = "",

    [string]$StopFile = "",

    [string]$LockFile = "",

    [ValidateRange(1, 3600)]
    [int]$RestartDelaySeconds = 5,

    [ValidateRange(1, 3600)]
    [int]$MaximumRestartDelaySeconds = 60,

    [ValidateRange(1, 86400)]
    [int]$StableRunSeconds = 300,

    [ValidateRange(0, 1000000)]
    [int]$MaximumConsecutiveFailures = 0,

    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-SupervisorPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [switch]$MustExist,

        [switch]$Container
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path must not be empty"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($MustExist) {
        $pathType = if ($Container) { "Container" } else { "Leaf" }
        if (-not (Test-Path -LiteralPath $fullPath -PathType $pathType)) {
            throw "$Label path does not exist or has the wrong type: $fullPath"
        }
    }
    return $fullPath
}

function ConvertTo-SupervisorArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value.IndexOf([char]0) -ge 0 -or $Value.Contains('"')) {
        throw "supervisor child argument contains an unsupported quote or NUL"
    }
    $escaped = $Value -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Get-RestartDelaySeconds {
    param(
        [Parameter(Mandatory = $true)]
        [int]$FailureCount,

        [Parameter(Mandatory = $true)]
        [int]$InitialDelaySeconds,

        [Parameter(Mandatory = $true)]
        [int]$MaximumDelaySeconds
    )

    if ($FailureCount -le 1) {
        return [Math]::Min($InitialDelaySeconds, $MaximumDelaySeconds)
    }
    $exponent = [Math]::Min($FailureCount - 1, 20)
    $scaled = [double]$InitialDelaySeconds * [Math]::Pow(2, $exponent)
    return [int][Math]::Min($scaled, $MaximumDelaySeconds)
}

function Write-SupervisorEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,

        [hashtable]$Fields = @{}
    )

    $record = [ordered]@{
        timestamp = [DateTimeOffset]::UtcNow.ToString("o")
        event = $Event
    }
    foreach ($key in @($Fields.Keys | Sort-Object)) {
        $record[$key] = $Fields[$key]
    }
    $line = ([pscustomobject]$record | ConvertTo-Json -Compress -Depth 5)
    try {
        Add-Content -LiteralPath $script:ResolvedSupervisorLog -Value $line -Encoding UTF8
    } catch {
        # Losing the supervisor log must not stop connectivity recovery. Emit
        # the diagnostic to the inherited task stream as a best effort.
        [Console]::Error.WriteLine("wink supervisor log failure: " + $_.Exception.Message)
    }
}

function Wait-RestartDelay {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Seconds
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $script:ResolvedStopFile -PathType Leaf) {
            return $false
        }
        $remaining = ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds
        Start-Sleep -Milliseconds ([Math]::Max(1, [Math]::Min(1000, [int]$remaining)))
    }
    return -not (Test-Path -LiteralPath $script:ResolvedStopFile -PathType Leaf)
}

function Open-SupervisorLock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        return [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        throw "another WinkYou supervisor already owns lock file: $Path"
    }
}

function Assert-DistinctSupervisorFilePaths {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Paths
    )

    $seen = @{}
    foreach ($label in @($Paths.Keys | Sort-Object)) {
        $path = [System.IO.Path]::GetFullPath($Paths[$label])
        $key = $path.ToUpperInvariant()
        if ($seen.ContainsKey($key)) {
            throw "$label path conflicts with $($seen[$key]) path: $path"
        }
        $seen[$key] = $label
    }
}

if ($SelfTest) {
    $quoted = ConvertTo-SupervisorArgument '--state=C:\Program Files\WinkYou\wink.runtime.json'
    if ($quoted -ne '"--state=C:\Program Files\WinkYou\wink.runtime.json"') {
        throw "self-test failed: child argument quoting"
    }
    if ((ConvertTo-SupervisorArgument 'C:\') -ne '"C:\\"') {
        throw "self-test failed: trailing backslash quoting"
    }
    if ((Get-RestartDelaySeconds -FailureCount 1 -InitialDelaySeconds 5 -MaximumDelaySeconds 60) -ne 5 -or
        (Get-RestartDelaySeconds -FailureCount 4 -InitialDelaySeconds 5 -MaximumDelaySeconds 60) -ne 40 -or
        (Get-RestartDelaySeconds -FailureCount 8 -InitialDelaySeconds 5 -MaximumDelaySeconds 60) -ne 60) {
        throw "self-test failed: bounded exponential restart delay"
    }
    $pathConflictRejected = $false
    try {
        Assert-DistinctSupervisorFilePaths -Paths @{
            config = 'C:\WinkYou\config.yaml'
            log = 'C:\WinkYou\config.yaml'
        }
    } catch {
        $pathConflictRejected = $_.Exception.Message -match 'path conflicts with'
    }
    if (-not $pathConflictRejected) {
        throw "self-test failed: conflicting supervisor file roles were accepted"
    }
    $temporaryLock = [System.IO.Path]::GetTempFileName()
    $firstLock = $null
    try {
        $firstLock = Open-SupervisorLock -Path $temporaryLock
        $duplicateRejected = $false
        try {
            $duplicateLock = Open-SupervisorLock -Path $temporaryLock
            $duplicateLock.Dispose()
        } catch {
            $duplicateRejected = $_.Exception.Message -match 'already owns lock file'
        }
        if (-not $duplicateRejected) {
            throw "self-test failed: duplicate supervisor lock was accepted"
        }
    } finally {
        if ($null -ne $firstLock) {
            $firstLock.Dispose()
        }
        Remove-Item -LiteralPath $temporaryLock -Force -ErrorAction SilentlyContinue
    }
    [pscustomobject][ordered]@{
        ok = $true
        tests = 5
        first_restart_seconds = 5
        capped_restart_seconds = 60
    }
    return
}

$resolvedExe = Resolve-SupervisorPath -Path $WinkExe -Label "Wink executable" -MustExist
$resolvedConfig = Resolve-SupervisorPath -Path $Config -Label "Wink configuration" -MustExist
$resolvedState = Resolve-SupervisorPath -Path $State -Label "runtime state"
$stateDirectory = Split-Path -Parent $resolvedState
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    throw "runtime-state directory does not exist: $stateDirectory"
}
if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $resolvedExe
}
$resolvedWorkingDirectory = Resolve-SupervisorPath `
    -Path $WorkingDirectory `
    -Label "working directory" `
    -MustExist `
    -Container

if ([string]::IsNullOrWhiteSpace($SupervisorLog)) {
    $SupervisorLog = $resolvedState + ".supervisor.log"
}
if ([string]::IsNullOrWhiteSpace($StopFile)) {
    $StopFile = $resolvedState + ".supervisor.stop"
}
if ([string]::IsNullOrWhiteSpace($LockFile)) {
    $LockFile = $resolvedState + ".supervisor.lock"
}
$script:ResolvedSupervisorLog = Resolve-SupervisorPath -Path $SupervisorLog -Label "supervisor log"
$script:ResolvedStopFile = Resolve-SupervisorPath -Path $StopFile -Label "supervisor stop file"
$resolvedLockFile = Resolve-SupervisorPath -Path $LockFile -Label "supervisor lock file"
Assert-DistinctSupervisorFilePaths -Paths @{
    'Wink executable' = $resolvedExe
    'Wink configuration' = $resolvedConfig
    'runtime state' = $resolvedState
    'supervisor log' = $script:ResolvedSupervisorLog
    'supervisor stop file' = $script:ResolvedStopFile
    'supervisor lock file' = $resolvedLockFile
}
foreach ($parent in @(
    (Split-Path -Parent $script:ResolvedSupervisorLog),
    (Split-Path -Parent $script:ResolvedStopFile),
    (Split-Path -Parent $resolvedLockFile))) {
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "supervisor state directory does not exist: $parent"
    }
}

$script:SupervisorLockStream = Open-SupervisorLock -Path $resolvedLockFile

$childArguments = @(
    ConvertTo-SupervisorArgument "--config=$resolvedConfig"
    ConvertTo-SupervisorArgument "--state=$resolvedState"
    "up"
) -join " "

Write-SupervisorEvent "supervisor_started" @{
    supervisor_pid = $PID
    executable = $resolvedExe
    config = $resolvedConfig
    state = $resolvedState
    lock_file = $resolvedLockFile
}

$consecutiveFailures = 0
while ($true) {
    if (Test-Path -LiteralPath $script:ResolvedStopFile -PathType Leaf) {
        Write-SupervisorEvent "stop_marker_observed" @{ supervisor_pid = $PID }
        exit 0
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = [System.Diagnostics.ProcessStartInfo]@{
        FileName = $resolvedExe
        Arguments = $childArguments
        WorkingDirectory = $resolvedWorkingDirectory
        UseShellExecute = $false
        CreateNoWindow = $true
    }
    $startedAt = [DateTimeOffset]::UtcNow
    $stopMarkerObserved = $false
    try {
        if (-not $process.Start()) {
            throw "Process.Start returned false"
        }
        Write-SupervisorEvent "child_started" @{
            supervisor_pid = $PID
            child_pid = $process.Id
            consecutive_failures = $consecutiveFailures
        }
        while (-not $process.WaitForExit(1000)) {
            if (-not $stopMarkerObserved -and
                (Test-Path -LiteralPath $script:ResolvedStopFile -PathType Leaf)) {
                $stopMarkerObserved = $true
                Write-SupervisorEvent "stop_marker_waiting_for_child" @{
                    supervisor_pid = $PID
                    child_pid = $process.Id
                }
            }
        }
        $exitCode = $process.ExitCode
    } catch {
        $exitCode = -1
        Write-SupervisorEvent "child_start_or_wait_failed" @{
            supervisor_pid = $PID
            error = $_.Exception.Message
        }
    } finally {
        $process.Dispose()
    }

    $runSeconds = [Math]::Max(0, [int]([DateTimeOffset]::UtcNow - $startedAt).TotalSeconds)
    Write-SupervisorEvent "child_exited" @{
        supervisor_pid = $PID
        exit_code = $exitCode
        run_seconds = $runSeconds
    }

    if ($stopMarkerObserved -or
        (Test-Path -LiteralPath $script:ResolvedStopFile -PathType Leaf)) {
        Write-SupervisorEvent "stop_marker_observed" @{ supervisor_pid = $PID }
        exit 0
    }

    if ($exitCode -eq 0) {
        Write-SupervisorEvent "clean_child_exit" @{ supervisor_pid = $PID }
        exit 0
    }
    if ($runSeconds -ge $StableRunSeconds) {
        $consecutiveFailures = 0
    }
    $consecutiveFailures++
    if ($MaximumConsecutiveFailures -gt 0 -and $consecutiveFailures -ge $MaximumConsecutiveFailures) {
        Write-SupervisorEvent "failure_limit_reached" @{
            supervisor_pid = $PID
            consecutive_failures = $consecutiveFailures
        }
        exit $exitCode
    }

    $delay = Get-RestartDelaySeconds `
        -FailureCount $consecutiveFailures `
        -InitialDelaySeconds $RestartDelaySeconds `
        -MaximumDelaySeconds $MaximumRestartDelaySeconds
    Write-SupervisorEvent "restart_scheduled" @{
        supervisor_pid = $PID
        delay_seconds = $delay
        consecutive_failures = $consecutiveFailures
    }
    if (-not (Wait-RestartDelay -Seconds $delay)) {
        Write-SupervisorEvent "stop_marker_observed" @{ supervisor_pid = $PID }
        exit 0
    }
}
