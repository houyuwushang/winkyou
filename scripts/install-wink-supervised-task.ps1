#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$WinkExe = "",

    [string]$Config = "",

    [string]$State = "",

    [string]$WorkingDirectory = "",

    [string]$SupervisorScript = "",

    [string]$SupervisorLog = "",

    [string]$StopFile = "",

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = "WinkYou",

    [ValidateRange(1, 255)]
    [int]$RestartCount = 3,

    [ValidateRange(1, 1440)]
    [int]$RestartIntervalMinutes = 1,

    [ValidateRange(1, 3600)]
    [int]$ChildRestartDelaySeconds = 5,

    [ValidateRange(1, 3600)]
    [int]$MaximumChildRestartDelaySeconds = 60,

    [switch]$StartNow,

    [switch]$Force,

    [switch]$AllowUnsafeSystemPaths,

    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-AbsolutePath {
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

function ConvertTo-ScheduledTaskArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value.IndexOf([char]0) -ge 0 -or $Value.Contains('"')) {
        throw "scheduled-task argument contains an unsupported quote or NUL"
    }
    # A trailing backslash must be doubled before the closing quote under the
    # Windows CommandLineToArgvW rules. Embedded quotes are rejected above.
    $escaped = $Value -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-SIDValue {
    param(
        [Parameter(Mandatory = $true)]
        $Identity
    )

    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    try {
        return ([System.Security.Principal.SecurityIdentifier][string]$Identity).Value
    } catch {
        return ([System.Security.Principal.NTAccount][string]$Identity).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    }
}

function Get-UntrustedSystemPathFinding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $targets = [System.Collections.Generic.List[string]]::new()
    $targets.Add($Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $targets.Add((Split-Path -Parent $Path))
    }

    $trustedWriteSIDs = @{
        'S-1-5-18' = 'SYSTEM'
        'S-1-5-32-544' = 'Builtin Administrators'
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = 'TrustedInstaller'
    }
    # Do not OR the composite Modify value into this mask: Modify also contains
    # read/execute bits, which would misclassify an ordinary RX grant as writable.
    $writeRights = [int64]([System.Security.AccessControl.FileSystemRights]::Write `
        -bor [System.Security.AccessControl.FileSystemRights]::Delete `
        -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $genericWriteRights = [int64]0x50000000

    foreach ($target in @($targets | Select-Object -Unique)) {
        try {
            $acl = Get-Acl -LiteralPath $target
        } catch {
            return "$Label ACL could not be verified at ${target}: $($_.Exception.Message)"
        }
        try {
            $ownerSID = ConvertTo-SIDValue -Identity $acl.Owner
        } catch {
            return "$Label owner could not be verified at ${target}: $($acl.Owner)"
        }
        if (-not $trustedWriteSIDs.ContainsKey($ownerSID)) {
            return "$Label has an untrusted owner at ${target}: $($acl.Owner) ($ownerSID)"
        }
        foreach ($rule in $acl.Access) {
            $rawRights = [int64]$rule.FileSystemRights
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                (($rawRights -band $writeRights) -eq 0 -and
                    ($rawRights -band $genericWriteRights) -eq 0)) {
                continue
            }
            try {
                $sid = ConvertTo-SIDValue -Identity $rule.IdentityReference
            } catch {
                return "$Label has an unresolved writable principal at ${target}: $($rule.IdentityReference)"
            }
            if (-not $trustedWriteSIDs.ContainsKey($sid)) {
                return "$Label is writable through an untrusted principal at ${target}: $($rule.IdentityReference) ($sid), $($rule.FileSystemRights)"
            }
        }
    }
    return $null
}

function Assert-SystemTaskInputTrust {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Paths,

        [switch]$AllowUnsafe
    )

    if ($AllowUnsafe) {
        return
    }
    foreach ($label in @($Paths.Keys | Sort-Object)) {
        $finding = Get-UntrustedSystemPathFinding -Path $Paths[$label] -Label $label
        if (-not [string]::IsNullOrWhiteSpace($finding)) {
            throw "$finding. Refusing to register a SYSTEM task. Install inputs under administrator-protected paths, or pass -AllowUnsafeSystemPaths only for an isolated development host."
        }
    }
}

function Assert-DistinctFilePaths {
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

function Test-IsManagedWinkTask {
    param(
        [Parameter(Mandatory = $true)]
        $Task
    )

    if ($Task.Description -ne 'Run the WinkYou child supervisor at startup' -and
        $Task.Description -ne 'WinkYou managed child supervisor task (schema v1)') {
        return $false
    }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or
        [System.IO.Path]::GetFileName([string]$actions[0].Execute) -ine 'powershell.exe' -or
        [string]$actions[0].Arguments -notmatch '(?i)run-wink-supervisor\.ps1') {
        return $false
    }
    return $true
}

function New-WinkScheduledTaskDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PowerShellPath,

        [Parameter(Mandatory = $true)]
        [string]$SupervisorPath,

        [Parameter(Mandatory = $true)]
        [string]$WinkExecutablePath,

        [Parameter(Mandatory = $true)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory = $true)]
        [string]$RuntimeStatePath,

        [Parameter(Mandatory = $true)]
        [string]$TaskWorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$SupervisorLogPath,

        [Parameter(Mandatory = $true)]
        [string]$SupervisorStopFile,

        [Parameter(Mandatory = $true)]
        [int]$ChildFailureRestartDelaySeconds,

        [Parameter(Mandatory = $true)]
        [int]$MaximumChildFailureRestartDelaySeconds,

        [Parameter(Mandatory = $true)]
        [int]$FailureRestartCount,

        [Parameter(Mandatory = $true)]
        [int]$FailureRestartIntervalMinutes
    )

    $arguments = @(
        "-NoLogo"
        "-NoProfile"
        "-NonInteractive"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        ConvertTo-ScheduledTaskArgument $SupervisorPath
        "-WinkExe"
        ConvertTo-ScheduledTaskArgument $WinkExecutablePath
        "-Config"
        ConvertTo-ScheduledTaskArgument $ConfigurationPath
        "-State"
        ConvertTo-ScheduledTaskArgument $RuntimeStatePath
        "-WorkingDirectory"
        ConvertTo-ScheduledTaskArgument $TaskWorkingDirectory
        "-SupervisorLog"
        ConvertTo-ScheduledTaskArgument $SupervisorLogPath
        "-StopFile"
        ConvertTo-ScheduledTaskArgument $SupervisorStopFile
        "-RestartDelaySeconds"
        [string]$ChildFailureRestartDelaySeconds
        "-MaximumRestartDelaySeconds"
        [string]$MaximumChildFailureRestartDelaySeconds
    ) -join " "

    $action = New-ScheduledTaskAction `
        -Execute $PowerShellPath `
        -Argument $arguments `
        -WorkingDirectory $TaskWorkingDirectory
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount $FailureRestartCount `
        -RestartInterval (New-TimeSpan -Minutes $FailureRestartIntervalMinutes) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    return [pscustomobject]@{
        Definition = New-ScheduledTask `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "WinkYou managed child supervisor task (schema v1)"
        Arguments = $arguments
    }
}

if ($SelfTest) {
    $quoted = ConvertTo-ScheduledTaskArgument '--config=C:\Program Files\WinkYou\config.yaml'
    if ($quoted -ne '"--config=C:\Program Files\WinkYou\config.yaml"') {
        throw "self-test failed: scheduled-task argument quoting"
    }
    if ((ConvertTo-ScheduledTaskArgument 'C:\') -ne '"C:\\"') {
        throw "self-test failed: trailing backslash quoting"
    }
    $quoteRejected = $false
    try {
        [void](ConvertTo-ScheduledTaskArgument '--config=C:\bad"path.yaml')
    } catch {
        $quoteRejected = $true
    }
    if (-not $quoteRejected) {
        throw "self-test failed: embedded quote was accepted"
    }

    $hostExecutable = (Get-Process -Id $PID).Path
    $definition = New-WinkScheduledTaskDefinition `
        -PowerShellPath $hostExecutable `
        -SupervisorPath 'C:\Program Files\WinkYou\run-wink-supervisor.ps1' `
        -WinkExecutablePath 'C:\Program Files\WinkYou\wink.exe' `
        -ConfigurationPath 'C:\Program Files\WinkYou\config.yaml' `
        -RuntimeStatePath 'C:\ProgramData\WinkYou\wink.runtime.json' `
        -TaskWorkingDirectory 'C:\Program Files\WinkYou' `
        -SupervisorLogPath 'C:\ProgramData\WinkYou\wink.supervisor.log' `
        -SupervisorStopFile 'C:\ProgramData\WinkYou\wink.supervisor.stop' `
        -ChildFailureRestartDelaySeconds 5 `
        -MaximumChildFailureRestartDelaySeconds 60 `
        -FailureRestartCount 7 `
        -FailureRestartIntervalMinutes 1
    if ($definition.Definition.Principal.UserId -ne 'SYSTEM' -or
        $definition.Definition.Settings.MultipleInstances -ne 'IgnoreNew' -or
        $definition.Definition.Settings.RestartCount -ne 7 -or
        $definition.Definition.Settings.ExecutionTimeLimit -ne 'PT0S' -or
        $definition.Arguments -notmatch [regex]::Escape('run-wink-supervisor.ps1')) {
        throw "self-test failed: scheduled-task safety settings"
    }
    [pscustomobject][ordered]@{
        ok = $true
        tests = 4
        principal = $definition.Definition.Principal.UserId
        multiple_instances = [string]$definition.Definition.Settings.MultipleInstances
        restart_count = $definition.Definition.Settings.RestartCount
        restart_interval = [string]$definition.Definition.Settings.RestartInterval
        execution_time_limit = [string]$definition.Definition.Settings.ExecutionTimeLimit
    }
    return
}

if (-not (Test-IsAdministrator)) {
    throw "install-wink-supervised-task.ps1 must run from an elevated PowerShell session"
}
if ([string]::IsNullOrWhiteSpace($TaskName) -or $TaskName -match '[\\/*?\[\]]') {
    throw "TaskName must be a non-empty root task name without path separators or wildcard characters"
}

$resolvedExe = Resolve-AbsolutePath -Path $WinkExe -Label "Wink executable" -MustExist
$resolvedConfig = Resolve-AbsolutePath -Path $Config -Label "Wink configuration" -MustExist
$resolvedState = Resolve-AbsolutePath -Path $State -Label "runtime state"
$stateDirectory = Split-Path -Parent $resolvedState
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    throw "runtime-state directory does not exist: $stateDirectory"
}
if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $resolvedExe
}
$resolvedWorkingDirectory = Resolve-AbsolutePath `
    -Path $WorkingDirectory `
    -Label "working directory" `
    -MustExist `
    -Container
if ([string]::IsNullOrWhiteSpace($SupervisorScript)) {
    $SupervisorScript = Join-Path $PSScriptRoot "run-wink-supervisor.ps1"
}
$resolvedSupervisorScript = Resolve-AbsolutePath `
    -Path $SupervisorScript `
    -Label "supervisor script" `
    -MustExist
if ([string]::IsNullOrWhiteSpace($SupervisorLog)) {
    $SupervisorLog = $resolvedState + ".supervisor.log"
}
if ([string]::IsNullOrWhiteSpace($StopFile)) {
    $StopFile = $resolvedState + ".supervisor.stop"
}
$resolvedSupervisorLog = Resolve-AbsolutePath -Path $SupervisorLog -Label "supervisor log"
$resolvedStopFile = Resolve-AbsolutePath -Path $StopFile -Label "supervisor stop file"
$resolvedLockFile = Resolve-AbsolutePath -Path ($resolvedState + ".supervisor.lock") -Label "supervisor lock file"
foreach ($parent in @((Split-Path -Parent $resolvedSupervisorLog), (Split-Path -Parent $resolvedStopFile))) {
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "supervisor state directory does not exist: $parent"
    }
}
$filePaths = @{
    'Wink executable' = $resolvedExe
    'Wink configuration' = $resolvedConfig
    'runtime state' = $resolvedState
    'supervisor script' = $resolvedSupervisorScript
    'supervisor log' = $resolvedSupervisorLog
    'supervisor stop file' = $resolvedStopFile
    'supervisor lock file' = $resolvedLockFile
}
Assert-DistinctFilePaths -Paths $filePaths
foreach ($label in @('runtime state', 'supervisor log', 'supervisor stop file', 'supervisor lock file')) {
    $path = $filePaths[$label]
    if ((Test-Path -LiteralPath $path) -and
        -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$label path exists but is not a file: $path"
    }
}
$systemTaskTrustPaths = @{
    'Wink executable' = $resolvedExe
    'Wink configuration' = $resolvedConfig
    'supervisor script' = $resolvedSupervisorScript
    'working directory' = $resolvedWorkingDirectory
    'runtime state directory' = $stateDirectory
    'supervisor log directory' = (Split-Path -Parent $resolvedSupervisorLog)
    'supervisor stop directory' = (Split-Path -Parent $resolvedStopFile)
    'supervisor lock directory' = (Split-Path -Parent $resolvedLockFile)
}
foreach ($label in @('runtime state', 'supervisor log', 'supervisor stop file', 'supervisor lock file')) {
    $path = $filePaths[$label]
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $systemTaskTrustPaths["existing $label"] = $path
    }
}
Assert-SystemTaskInputTrust -Paths $systemTaskTrustPaths -AllowUnsafe:$AllowUnsafeSystemPaths

$powerShellExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$resolvedPowerShellExe = Resolve-AbsolutePath `
    -Path $powerShellExe `
    -Label "Windows PowerShell executable" `
    -MustExist

$taskDefinition = New-WinkScheduledTaskDefinition `
    -PowerShellPath $resolvedPowerShellExe `
    -SupervisorPath $resolvedSupervisorScript `
    -WinkExecutablePath $resolvedExe `
    -ConfigurationPath $resolvedConfig `
    -RuntimeStatePath $resolvedState `
    -TaskWorkingDirectory $resolvedWorkingDirectory `
    -SupervisorLogPath $resolvedSupervisorLog `
    -SupervisorStopFile $resolvedStopFile `
    -ChildFailureRestartDelaySeconds $ChildRestartDelaySeconds `
    -MaximumChildFailureRestartDelaySeconds $MaximumChildRestartDelaySeconds `
    -FailureRestartCount $RestartCount `
    -FailureRestartIntervalMinutes $RestartIntervalMinutes

$existingTask = Get-ScheduledTask -TaskPath "\" -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    if (-not (Test-IsManagedWinkTask -Task $existingTask)) {
        throw "refusing to overwrite a task that is not owned by WinkYou: $TaskName"
    }
    if (-not $Force) {
        throw "scheduled task already exists; stop it and pass -Force to replace it: $TaskName"
    }
    if ($existingTask.State -eq "Running") {
        throw "refusing to replace a running scheduled task; disable it and gracefully stop WinkYou first: $TaskName"
    }
}
if ($StartNow -and (Test-Path -LiteralPath $resolvedState -PathType Leaf)) {
    try {
        $runtimeState = Get-Content -LiteralPath $resolvedState -Raw | ConvertFrom-Json
        $runtimePID = [int]$runtimeState.pid
        if ($runtimePID -gt 0 -and $null -ne (Get-Process -Id $runtimePID -ErrorAction SilentlyContinue)) {
            throw "runtime state refers to live pid $runtimePID; gracefully stop the existing WinkYou process before -StartNow"
        }
    } catch {
        if ($_.Exception.Message -match '^runtime state refers to live pid') {
            throw
        }
        # Wink up performs the authoritative stale-state and process-generation
        # checks while holding the runtime lock. A malformed or unreadable stale
        # file is not silently deleted by the installer.
    }
}

if ($PSCmdlet.ShouldProcess($TaskName, "register SYSTEM startup task with child supervisor")) {
    [void](Register-ScheduledTask `
        -TaskName $TaskName `
        -InputObject $taskDefinition.Definition `
        -Force)
    $registeredTask = Get-ScheduledTask -TaskPath "\" -TaskName $TaskName -ErrorAction Stop
    $registeredActions = @($registeredTask.Actions)
    if ($registeredTask.Principal.UserId -ine 'SYSTEM' -or
        $registeredActions.Count -ne 1 -or
        [string]$registeredActions[0].Execute -ine $resolvedPowerShellExe -or
        [string]$registeredActions[0].Arguments -cne $taskDefinition.Arguments) {
        throw "registered task definition does not match the requested WinkYou supervisor definition: $TaskName"
    }
    # Registering or replacing the task deliberately arms its next run. Clear
    # the persistent stop marker only after registration was verified.
    Remove-Item -LiteralPath $resolvedStopFile -Force -ErrorAction SilentlyContinue
}
if ($StartNow -and $PSCmdlet.ShouldProcess($TaskName, "start scheduled task")) {
    Start-ScheduledTask -TaskName $TaskName
}

[pscustomobject][ordered]@{
    task_name = $TaskName
    task_executable = $resolvedPowerShellExe
    task_arguments = $taskDefinition.Arguments
    supervisor_script = $resolvedSupervisorScript
    wink_executable = $resolvedExe
    working_directory = $resolvedWorkingDirectory
    supervisor_log = $resolvedSupervisorLog
    stop_file = $resolvedStopFile
    lock_file = $resolvedLockFile
    principal = "SYSTEM"
    trigger = "AtStartup"
    outer_restart_count = $RestartCount
    outer_restart_interval_minutes = $RestartIntervalMinutes
    child_restart_delay_seconds = $ChildRestartDelaySeconds
    maximum_child_restart_delay_seconds = $MaximumChildRestartDelaySeconds
    execution_time_limit = "none"
    multiple_instances = "IgnoreNew"
    start_requested = [bool]$StartNow
    unsafe_system_paths_accepted = [bool]$AllowUnsafeSystemPaths
}
