#Requires -Version 5.1

<#
.SYNOPSIS
Observes the A/B/C WinkYou direct triangle without repairing or changing it.

.DESCRIPTION
The default run lasts two hours. Every 10 seconds it samples /v1/status on
all three nodes. Every 30 seconds it sends the six directed control pings, and
every 60 seconds it opens a fresh A-to-B SSH connection through the routed TCP
listener on 127.0.0.1:22024.

Only these remote operations are used:
  * GET  /v1/status
  * POST /v1/ping
  * hostname (over the A-to-B routed SSH service)

The script never calls peer, neighbor, or shortcut mutation endpoints. It does
not reconnect, restart, repunch, or alter the topology after a failure.

B and C use public-key BatchMode by default. To use SSH_ASKPASS for a node,
provide both its AskPassPath and PasswordEnvironmentVariable parameters and set
that named variable in the monitor process before launch. The password value is
passed only through child-process environment blocks; it is never added to argv,
events, logs, or run.state.json.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor-three-node-soak.ps1

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor-three-node-soak.ps1 -Background

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor-three-node-soak.ps1 -DurationSeconds 120 -SampleIntervalSeconds 5

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor-three-node-soak.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 604800)]
    [int]$DurationSeconds = 7200,

    [ValidateRange(1, 3600)]
    [int]$SampleIntervalSeconds = 10,

    [ValidateRange(1, 3600)]
    [int]$PingIntervalSeconds = 30,

    [ValidateRange(1, 3600)]
    [int]$SshIntervalSeconds = 60,

    [ValidateRange(1, 120)]
    [int]$PingTimeoutSeconds = 4,

    [ValidateRange(1, 180)]
    [int]$CommandTimeoutSeconds = 9,

    [string]$AApiBase = "http://127.0.0.1:32110",
    [string]$RemoteApiBase = "http://127.0.0.1:32110",

    [string]$BUser = "node-b-user",
    [string]$BHost = "127.0.0.1",
    [ValidateRange(1, 65535)]
    [int]$BPort = 22024,
    [string]$BProxyCommand = "",
    [string]$BRemoteCurl = "curl.exe",
    [string]$BExpectedHostname = "",
    [string]$BAskPassPath = "",
    [string]$BPasswordEnvironmentVariable = "",

    [string]$ABAttemptID = "",
    [string]$BCAttemptID = "",
    [string]$ACAttemptID = "",
    [ValidateSet("A", "B")]
    [string]$ABInitiatorID = "A",
    [ValidateSet("B", "C")]
    [string]$BCInitiatorID = "B",
    [ValidateSet("A", "C")]
    [string]$ACInitiatorID = "C",
    [string]$AExpectedStartedAt = "",
    [string]$BExpectedStartedAt = "",
    [string]$CExpectedStartedAt = "",

    [string]$CUser = "node-c-user",
    [string]$CHost = "127.0.0.1",
    [ValidateRange(1, 65535)]
    [int]$CPort = 22022,
    [string]$CProxyCommand = "",
    [string]$CRemoteCurl = "curl",
    [string]$CAskPassPath = "",
    [string]$CPasswordEnvironmentVariable = "",

    [string]$SshExecutable = "ssh.exe",
    [string]$CurlExecutable = "curl.exe",
    [string]$OutputDirectory = "",

    [switch]$Background,
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
# Process.StandardInput inherits this encoding in Windows PowerShell 5.1.
# A BOM would make meshnode's strict JSON decoder reject every POST body.
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)

$script:Policy = "observe_only_no_reconnect_no_repunch_no_topology_change"
$script:EventWriter = $null
$script:ProbeStates = @{}
$script:NodeStates = @{}
$script:Nodes = $null
$script:SensitiveValues = New-Object 'System.Collections.Generic.List[string]'
$abTargetID = if ($ABInitiatorID -eq "A") { "B" } else { "A" }
$bcTargetID = if ($BCInitiatorID -eq "B") { "C" } else { "B" }
$acTargetID = if ($ACInitiatorID -eq "A") { "C" } else { "A" }
$script:ExpectedEdges = @(
    [pscustomobject][ordered]@{ edge = "A-B"; attempt_id = $ABAttemptID.Trim(); initiator_id = $ABInitiatorID; target_id = $abTargetID; coordinator_id = "C" },
    [pscustomobject][ordered]@{ edge = "B-C"; attempt_id = $BCAttemptID.Trim(); initiator_id = $BCInitiatorID; target_id = $bcTargetID; coordinator_id = "A" },
    [pscustomobject][ordered]@{ edge = "A-C"; attempt_id = $ACAttemptID.Trim(); initiator_id = $ACInitiatorID; target_id = $acTargetID; coordinator_id = "B" }
)
$script:ExpectedStartedAt = [ordered]@{
    A = $AExpectedStartedAt.Trim()
    B = $BExpectedStartedAt.Trim()
    C = $CExpectedStartedAt.Trim()
}
$script:RunID = $null
$script:RunStartedUtc = $null
$script:StatusSamplesAttempted = 0
$script:PingRoundsAttempted = 0
$script:SshProbesAttempted = 0
$script:MissedStatusSlots = 0
$script:MissedPingSlots = 0
$script:MissedSshSlots = 0

function Get-PropertyValue {
    param(
        [object]$InputObject,
        [string]$Name,
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }
    return $property.Value
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append([char]92, (2 * $backslashes) + 1)
            [void]$builder.Append([char]34)
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]92, $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]92, 2 * $backslashes)
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param([string[]]$Arguments)

    return (($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' ')
}

function Limit-Text {
    param(
        [AllowNull()][string]$Value,
        [int]$MaximumLength = 2048
    )

    if ($null -eq $Value) {
        return ""
    }
    $clean = Protect-SensitiveText -Value $Value
    $clean = $clean.Trim()
    if ($clean.Length -le $MaximumLength) {
        return $clean
    }
    return $clean.Substring(0, $MaximumLength) + "...<truncated>"
}

function Protect-SensitiveText {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return ""
    }
    $protected = $Value
    foreach ($secret in @($script:SensitiveValues)) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $protected = $protected.Replace($secret, "<redacted>")
        }
    }
    return $protected
}

function Get-SshAuthenticationConfiguration {
    param(
        [AllowEmptyString()][string]$AskPassPath,
        [AllowEmptyString()][string]$PasswordEnvironmentVariable
    )

    $hasAskPass = -not [string]::IsNullOrWhiteSpace($AskPassPath)
    $hasPasswordName = -not [string]::IsNullOrWhiteSpace($PasswordEnvironmentVariable)
    if (-not $hasAskPass -and -not $hasPasswordName) {
        return [pscustomobject][ordered]@{
            UseAskPass = $false
            EnvironmentVariables = @{}
        }
    }
    if (-not $hasAskPass -or -not $hasPasswordName) {
        throw "SSH_ASKPASS path and password environment-variable name must be configured together"
    }
    if ($PasswordEnvironmentVariable -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        throw "SSH password environment-variable name is invalid"
    }
    foreach ($value in @($AskPassPath, $PasswordEnvironmentVariable)) {
        if ($value.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) {
            throw "SSH_ASKPASS configuration must not contain NUL or line breaks"
        }
    }

    $resolvedAskPass = [System.IO.Path]::GetFullPath($AskPassPath)
    if (-not (Test-Path -LiteralPath $resolvedAskPass -PathType Leaf)) {
        throw "SSH_ASKPASS executable not found"
    }
    $password = [Environment]::GetEnvironmentVariable($PasswordEnvironmentVariable, "Process")
    if ([string]::IsNullOrEmpty($password)) {
        throw "configured SSH password environment variable is empty or unavailable"
    }
    if ($password.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) {
        throw "configured SSH password contains an unsupported control character"
    }
    if (-not $script:SensitiveValues.Contains($password)) {
        $script:SensitiveValues.Add($password)
    }

    return [pscustomobject][ordered]@{
        UseAskPass = $true
        EnvironmentVariables = @{
            SSH_ASKPASS = $resolvedAskPass
            SSH_ASKPASS_REQUIRE = "force"
            DISPLAY = "winkyou-soak-monitor"
            $PasswordEnvironmentVariable = $password
        }
    }
}

function Start-CapturedProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [AllowNull()][string]$InputText = $null,
        [AllowNull()][hashtable]$EnvironmentVariables = $null,
        [switch]$CompleteOnOutputLine
    )

    $process = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $startedUtc = [DateTimeOffset]::UtcNow
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = Join-NativeArguments -Arguments $Arguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.RedirectStandardInput = $true
        if ($null -ne $EnvironmentVariables) {
            foreach ($entry in $EnvironmentVariables.GetEnumerator()) {
                $name = [string]$entry.Key
                if ([string]::IsNullOrWhiteSpace($name) -or
                    $name.IndexOfAny([char[]]@([char]0, [char]61)) -ge 0) {
                    throw "invalid child-process environment-variable name"
                }
                $startInfo.EnvironmentVariables[$name] = [string]$entry.Value
            }
        }

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $stdoutTask = $null
        $stdoutLineTask = $null
        if ($CompleteOnOutputLine) {
            # WinkYou status, ping, and hostname probes each return exactly one
            # line. Reading that line independently lets us recognize a complete
            # business response even when Windows OpenSSH hangs while closing
            # its local forwarded socket after stdout has already arrived.
            $stdoutLineTask = $process.StandardOutput.ReadLineAsync()
        } else {
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $InputText) {
            # StandardInput.Write() in Windows PowerShell 5.1 emits a BOM that
            # Go's strict JSON decoder rejects. Write explicit BOM-less UTF-8.
            $inputBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($InputText)
            $process.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
            $process.StandardInput.BaseStream.Flush()
        }
        $process.StandardInput.Close()

        return [pscustomobject][ordered]@{
            Process = $process
            StdoutTask = $stdoutTask
            StdoutLineTask = $stdoutLineTask
            StderrTask = $stderrTask
            Stopwatch = $stopwatch
            StartedUtc = $startedUtc
            FilePath = $FilePath
            CompleteOnOutputLine = [bool]$CompleteOnOutputLine
            StartError = $null
        }
    } catch {
        if ($null -ne $process) {
            try { $process.Kill() } catch { }
            try { $process.Dispose() } catch { }
        }
        $stopwatch.Stop()
        return [pscustomobject][ordered]@{
            Process = $null
            StdoutTask = $null
            StdoutLineTask = $null
            StderrTask = $null
            Stopwatch = $stopwatch
            StartedUtc = $startedUtc
            FilePath = $FilePath
            CompleteOnOutputLine = [bool]$CompleteOnOutputLine
            StartError = $_.Exception.Message
        }
    }
}

function Complete-CapturedProcess {
    param(
        [object]$Handle,
        [int]$TimeoutMilliseconds,
        [ValidateRange(0, 5000)]
        [int]$OutputCloseGraceMilliseconds = 500
    )

    if ($null -ne $Handle.StartError) {
        return [pscustomobject][ordered]@{
            ok = $false
            timed_out = $false
            complete_output_line = $false
            terminated_after_complete_output = $false
            transport_close_anomaly = $false
            exit_code = -1
            stdout = ""
            stderr = $Handle.StartError
            elapsed_ms = [math]::Round($Handle.Stopwatch.Elapsed.TotalMilliseconds, 3)
        }
    }

    $process = $Handle.Process
    $timedOut = $false
    $completeOutputLine = $false
    $terminatedAfterCompleteOutput = $false
    try {
        if ($Handle.CompleteOnOutputLine) {
            while ($true) {
                if ($Handle.StdoutLineTask.IsCompleted) {
                    $completeOutputLine = $true
                    if (-not $process.WaitForExit($OutputCloseGraceMilliseconds)) {
                        $terminatedAfterCompleteOutput = $true
                        try { $process.Kill() } catch { }
                        [void]$process.WaitForExit(2000)
                    } else {
                        $process.WaitForExit()
                    }
                    break
                }
                $remaining = $TimeoutMilliseconds - [int]$Handle.Stopwatch.ElapsedMilliseconds
                if ($remaining -le 0) {
                    $timedOut = $true
                    try { $process.Kill() } catch { }
                    [void]$process.WaitForExit(2000)
                    break
                }
                if ($process.WaitForExit([int][math]::Min(25, $remaining))) {
                    $process.WaitForExit()
                    break
                }
            }
        } else {
            $remaining = $TimeoutMilliseconds - [int]$Handle.Stopwatch.ElapsedMilliseconds
            if ($remaining -lt 0) {
                $remaining = 0
            }
            if (-not $process.WaitForExit($remaining)) {
                $timedOut = $true
                try { $process.Kill() } catch { }
                [void]$process.WaitForExit(2000)
            } else {
                # Ensures asynchronous stdout/stderr readers have observed EOF.
                $process.WaitForExit()
            }
        }

        $stdout = ""
        $stderr = ""
        if ($Handle.CompleteOnOutputLine) {
            try {
                if (-not $Handle.StdoutLineTask.IsCompleted) {
                    [void]$Handle.StdoutLineTask.Wait(2000)
                }
                if ($Handle.StdoutLineTask.IsCompleted -and $null -ne $Handle.StdoutLineTask.Result) {
                    $stdout = [string]$Handle.StdoutLineTask.Result
                }
                $remainingStdout = $process.StandardOutput.ReadToEnd()
                if (-not [string]::IsNullOrEmpty($remainingStdout)) {
                    if (-not [string]::IsNullOrEmpty($stdout)) {
                        $stdout += [Environment]::NewLine
                    }
                    $stdout += $remainingStdout
                }
            } catch {
                $stderr = $_.Exception.Message
            }
        } else {
            try { $stdout = $Handle.StdoutTask.Result } catch { $stderr = $_.Exception.Message }
        }
        try { $stderrFromTask = $Handle.StderrTask.Result } catch { $stderrFromTask = $_.Exception.Message }
        if (-not [string]::IsNullOrWhiteSpace($stderrFromTask)) {
            if ([string]::IsNullOrWhiteSpace($stderr)) {
                $stderr = $stderrFromTask
            } else {
                $stderr = $stderr + [Environment]::NewLine + $stderrFromTask
            }
        }
        $exitCode = if ($timedOut -or $terminatedAfterCompleteOutput) { -1 } else { $process.ExitCode }
        $knownWindowsCloseError = (-not [string]::IsNullOrWhiteSpace($stderr) -and
            $stderr -match 'close\s+-\s+IO is still pending on closed socket')
        $transportCloseAnomaly = ($completeOutputLine -and
            ($terminatedAfterCompleteOutput -or ($exitCode -ne 0 -and $knownWindowsCloseError)))
        return [pscustomobject][ordered]@{
            ok = (-not $timedOut -and -not $terminatedAfterCompleteOutput -and $exitCode -eq 0)
            timed_out = $timedOut
            complete_output_line = $completeOutputLine
            terminated_after_complete_output = $terminatedAfterCompleteOutput
            transport_close_anomaly = $transportCloseAnomaly
            exit_code = $exitCode
            stdout = $stdout
            stderr = $stderr
            elapsed_ms = [math]::Round($Handle.Stopwatch.Elapsed.TotalMilliseconds, 3)
        }
    } finally {
        $Handle.Stopwatch.Stop()
        try { $process.Dispose() } catch { }
    }
}

function New-SshArguments {
    param(
        [string]$User,
        [string]$HostName,
        [int]$Port,
        [AllowEmptyString()][string]$ProxyCommand = "",
        [string]$RemoteCommand,
        [switch]$UsesStandardInput,
        [switch]$UseAskPass
    )

    if ([string]::IsNullOrWhiteSpace($User)) {
        throw "SSH user must not be empty"
    }
    if ([string]::IsNullOrWhiteSpace($HostName)) {
        throw "SSH host must not be empty"
    }
    foreach ($value in @($User, $HostName, $ProxyCommand)) {
        if ($value.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) {
            throw "SSH user, host, and ProxyCommand must not contain NUL or line breaks"
        }
    }

    $arguments = @("-T")
    if ($UseAskPass) {
        $arguments += @(
            "-o", "BatchMode=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no"
        )
    } else {
        # Preserve the original r12/public-key behavior when no per-node
        # SSH_ASKPASS configuration is supplied.
        $arguments += @(
            "-o", "BatchMode=yes",
            "-o", "NumberOfPasswordPrompts=0",
            "-o", "PreferredAuthentications=publickey"
        )
    }
    $arguments += @(
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=NUL",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1",
        "-o", "ControlMaster=no"
    )
    if ([string]::IsNullOrWhiteSpace($ProxyCommand)) {
        $arguments += @("-o", "ProxyJump=none")
    } else {
        # Keep the complete command in one argv item. Start-CapturedProcess then
        # applies Windows-native escaping exactly once when it builds Arguments.
        $arguments += @("-o", "ProxyCommand=$ProxyCommand")
    }
    if (-not $UsesStandardInput) {
        $arguments += "-n"
    }
    $arguments += @("-p", [string]$Port, "${User}@${HostName}", $RemoteCommand)
    return $arguments
}

function Test-ProcessResultOutputCandidate {
    param(
        [object]$Result,
        [switch]$IsSsh
    )

    return ($Result.ok -or ($IsSsh -and $Result.transport_close_anomaly))
}

function Start-NodeApiRequest {
    param(
        [string]$NodeID,
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Path,
        [AllowNull()][string]$Body = $null
    )

    $node = $script:Nodes[$NodeID]
    $curlArguments = @(
        "--silent",
        "--show-error",
        "--fail",
        "--max-time", [string]([math]::Max(1, $CommandTimeoutSeconds - 2))
    )
    if ($Method -eq "POST") {
        $curlArguments += @(
            "--request", "POST",
            "--header", "Content-Type:application/json",
            "--data-binary", "@-"
        )
    }

    if ($node.Access -eq "local") {
        $curlArguments += $node.ApiBase.TrimEnd('/') + $Path
        return Start-CapturedProcess -FilePath $CurlExecutable -Arguments $curlArguments -InputText $Body
    }

    $curlArguments += $node.ApiBase.TrimEnd('/') + $Path
    # All curl arguments above are intentionally whitespace-free. Joining them
    # avoids shell-specific quoting differences between B (Windows) and C (Linux).
    $remoteCommand = $node.RemoteCurl + " " + ($curlArguments -join " ")
    $authentication = Get-SshAuthenticationConfiguration -AskPassPath $node.AskPassPath -PasswordEnvironmentVariable $node.PasswordEnvironmentVariable
    $sshArguments = New-SshArguments -User $node.User -HostName $node.HostName -Port $node.Port -ProxyCommand $node.ProxyCommand -RemoteCommand $remoteCommand -UsesStandardInput:($Method -eq "POST") -UseAskPass:$authentication.UseAskPass
    return Start-CapturedProcess -FilePath $SshExecutable -Arguments $sshArguments -InputText $Body -EnvironmentVariables $authentication.EnvironmentVariables -CompleteOnOutputLine
}

function Get-ProcessFailureText {
    param([object]$Result)

    if ($Result.timed_out) {
        return "command timed out"
    }
    $stderr = Limit-Text -Value $Result.stderr
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        return "exit $($Result.exit_code): $stderr"
    }
    return "exit $($Result.exit_code)"
}

function Write-JsonLine {
    param([object]$Value)

    if ($null -eq $script:EventWriter) {
        throw "event writer is not initialized"
    }
    $json = $Value | ConvertTo-Json -Compress -Depth 16
    $script:EventWriter.WriteLine($json)
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 16
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $encoding)
}

function Get-OrCreateProbeState {
    param(
        [string]$Key,
        [string]$Kind
    )

    if (-not $script:ProbeStates.ContainsKey($Key)) {
        $script:ProbeStates[$Key] = [pscustomobject][ordered]@{
            Key = $Key
            Kind = $Kind
            Attempts = 0
            Successes = 0
            Failures = 0
            ConsecutiveFailures = 0
            MaxConsecutiveFailures = 0
            CurrentFailureStartedUtc = $null
            FirstFailureUtc = $null
            LastFailureUtc = $null
            LastSuccessUtc = $null
            LastError = ""
            RttMilliseconds = (New-Object 'System.Collections.Generic.List[double]')
            ObservedMilliseconds = (New-Object 'System.Collections.Generic.List[double]')
        }
    }
    return $script:ProbeStates[$Key]
}

function Update-ProbeState {
    param(
        [string]$Key,
        [string]$Kind,
        [bool]$Succeeded,
        [DateTimeOffset]$TimestampUtc,
        [AllowNull()][Nullable[double]]$RttMilliseconds = $null,
        [AllowNull()][Nullable[double]]$ObservedMilliseconds = $null,
        [string]$ErrorText = ""
    )

    $ErrorText = Protect-SensitiveText -Value $ErrorText
    $state = Get-OrCreateProbeState -Key $Key -Kind $Kind
    $state.Attempts++
    if ($null -ne $ObservedMilliseconds) {
        $state.ObservedMilliseconds.Add([double]$ObservedMilliseconds)
    }

    $recoveredFailures = 0
    $recoveredDurationSeconds = 0.0
    if ($Succeeded) {
        $state.Successes++
        $state.LastSuccessUtc = $TimestampUtc
        if ($state.ConsecutiveFailures -gt 0) {
            $recoveredFailures = $state.ConsecutiveFailures
            if ($null -ne $state.CurrentFailureStartedUtc) {
                $recoveredDurationSeconds = [math]::Round(($TimestampUtc - $state.CurrentFailureStartedUtc).TotalSeconds, 3)
            }
        }
        $state.ConsecutiveFailures = 0
        $state.CurrentFailureStartedUtc = $null
        $state.LastError = ""
        if ($null -ne $RttMilliseconds) {
            $state.RttMilliseconds.Add([double]$RttMilliseconds)
        }
    } else {
        $state.Failures++
        if ($state.ConsecutiveFailures -eq 0) {
            $state.CurrentFailureStartedUtc = $TimestampUtc
        }
        $state.ConsecutiveFailures++
        if ($state.ConsecutiveFailures -gt $state.MaxConsecutiveFailures) {
            $state.MaxConsecutiveFailures = $state.ConsecutiveFailures
        }
        if ($null -eq $state.FirstFailureUtc) {
            $state.FirstFailureUtc = $TimestampUtc
        }
        $state.LastFailureUtc = $TimestampUtc
        $state.LastError = $ErrorText
    }

    $failureStreakSeconds = 0.0
    if (-not $Succeeded -and $null -ne $state.CurrentFailureStartedUtc) {
        $failureStreakSeconds = [math]::Round(($TimestampUtc - $state.CurrentFailureStartedUtc).TotalSeconds, 3)
    }
    return [pscustomobject][ordered]@{
        consecutive_failures = $state.ConsecutiveFailures
        max_consecutive_failures = $state.MaxConsecutiveFailures
        failure_streak_seconds = $failureStreakSeconds
        recovered_failures = $recoveredFailures
        recovered_failure_seconds = $recoveredDurationSeconds
    }
}

function Get-Distribution {
    param([object]$Values)

    $array = @($Values | ForEach-Object { [double]$_ } | Sort-Object)
    if ($array.Count -eq 0) {
        return [pscustomobject][ordered]@{ count = 0 }
    }
    $p50Index = [math]::Max(0, [math]::Ceiling(0.50 * $array.Count) - 1)
    $p95Index = [math]::Max(0, [math]::Ceiling(0.95 * $array.Count) - 1)
    $sum = 0.0
    foreach ($value in $array) { $sum += $value }
    return [pscustomobject][ordered]@{
        count = $array.Count
        minimum = [math]::Round($array[0], 3)
        p50 = [math]::Round($array[$p50Index], 3)
        p95 = [math]::Round($array[$p95Index], 3)
        maximum = [math]::Round($array[$array.Count - 1], 3)
        mean = [math]::Round($sum / $array.Count, 3)
    }
}

function Get-ProbeSummary {
    param([object]$State)

    $currentFailureSeconds = 0.0
    if ($State.ConsecutiveFailures -gt 0 -and $null -ne $State.CurrentFailureStartedUtc) {
        $currentFailureSeconds = [math]::Round(([DateTimeOffset]::UtcNow - $State.CurrentFailureStartedUtc).TotalSeconds, 3)
    }
    return [pscustomobject][ordered]@{
        key = $State.Key
        kind = $State.Kind
        attempts = $State.Attempts
        successes = $State.Successes
        failures = $State.Failures
        consecutive_failures_at_end = $State.ConsecutiveFailures
        current_failure_seconds_at_end = $currentFailureSeconds
        max_consecutive_failures = $State.MaxConsecutiveFailures
        first_failure_at = if ($null -eq $State.FirstFailureUtc) { $null } else { $State.FirstFailureUtc.ToString('o') }
        last_failure_at = if ($null -eq $State.LastFailureUtc) { $null } else { $State.LastFailureUtc.ToString('o') }
        last_success_at = if ($null -eq $State.LastSuccessUtc) { $null } else { $State.LastSuccessUtc.ToString('o') }
        last_error = $State.LastError
        api_rtt_ms = Get-Distribution -Values $State.RttMilliseconds
        observed_ms = Get-Distribution -Values $State.ObservedMilliseconds
    }
}

function Get-ProbeRollup {
    param([string[]]$ExpectedKeys)

    $missing = @($ExpectedKeys | Where-Object { -not $script:ProbeStates.ContainsKey($_) })
    $states = @($ExpectedKeys | Where-Object { $script:ProbeStates.ContainsKey($_) } | ForEach-Object {
            $script:ProbeStates[$_]
        })
    $attempts = 0
    $successes = 0
    $failures = 0
    foreach ($state in $states) {
        $attempts += $state.Attempts
        $successes += $state.Successes
        $failures += $state.Failures
    }
    return [pscustomobject][ordered]@{
        expected_probe_series = $ExpectedKeys.Count
        observed_probe_series = $states.Count
        missing_probe_series = $missing
        attempts = $attempts
        successes = $successes
        failures = $failures
        probe_series_with_failures = @($states | Where-Object { $_.Failures -gt 0 }).Count
    }
}

function Get-DimensionVerdict {
    param(
        [bool]$Observed,
        [bool]$CriterionMet,
        [string]$CompletionReason
    )

    if (-not $Observed) { return "not_observed" }
    if (-not $CriterionMet) { return "fail" }
    if ($CompletionReason -ne "duration_completed") { return "incomplete" }
    return "pass"
}

function Normalize-NodeStatus {
    param([object]$Status)

    $neighbors = @(@(Get-PropertyValue -InputObject $Status -Name "neighbors" -Default @()) | ForEach-Object { [string]$_ } | Sort-Object)
    $routes = @()
    foreach ($route in @(Get-PropertyValue -InputObject $Status -Name "routes" -Default @())) {
        $routes += [pscustomobject][ordered]@{
            destination = [string](Get-PropertyValue $route "destination" "")
            next_hop = [string](Get-PropertyValue $route "next_hop" "")
            hop_count = [int](Get-PropertyValue $route "hop_count" 0)
            rtt_millis = [long](Get-PropertyValue $route "rtt_millis" 0)
            path = @((Get-PropertyValue $route "path" @()) | ForEach-Object { [string]$_ })
        }
    }
    $routes = @($routes | Sort-Object destination)

    $stableShortcuts = @()
    foreach ($shortcut in @(Get-PropertyValue -InputObject $Status -Name "shortcuts" -Default @())) {
        if ([string](Get-PropertyValue $shortcut "phase" "") -ne "stable") {
            continue
        }
        $stableShortcuts += [pscustomobject][ordered]@{
            attempt_id = [string](Get-PropertyValue $shortcut "attempt_id" "")
            initiator_id = [string](Get-PropertyValue $shortcut "initiator_id" "")
            target_id = [string](Get-PropertyValue $shortcut "target_id" "")
            coordinator_id = [string](Get-PropertyValue $shortcut "coordinator_id" "")
            strategy = [string](Get-PropertyValue $shortcut "strategy" "")
            local_role = [string](Get-PropertyValue $shortcut "local_role" "")
            direct_peer_id = [string](Get-PropertyValue $shortcut "direct_peer_id" "")
            path_id = [string](Get-PropertyValue $shortcut "path_id" "")
            connection_type = [string](Get-PropertyValue $shortcut "connection_type" "")
            remote_addr = [string](Get-PropertyValue $shortcut "remote_addr" "")
            path_role = [string](Get-PropertyValue $shortcut "path_role" "")
            dependencies = @((Get-PropertyValue $shortcut "dependencies" @()))
            started_at = [string](Get-PropertyValue $shortcut "started_at" "")
            updated_at = [string](Get-PropertyValue $shortcut "updated_at" "")
        }
    }
    $stableShortcuts = @($stableShortcuts | Sort-Object attempt_id, local_role)
    $stableAttemptIDs = @($stableShortcuts | ForEach-Object { $_.attempt_id } | Where-Object { $_ } | Sort-Object -Unique)
    $directPeerIDs = @($stableShortcuts | Where-Object {
            $_.connection_type -eq "direct" -and -not [string]::IsNullOrWhiteSpace($_.direct_peer_id)
        } | ForEach-Object { $_.direct_peer_id } | Sort-Object -Unique)

    $maintainedPeersProperty = $Status.PSObject.Properties["maintained_direct_peers"]
    $maintainedPeersPresent = ($null -ne $maintainedPeersProperty)
    $maintainedPeers = @()
    foreach ($peer in @(Get-PropertyValue -InputObject $Status -Name "maintained_direct_peers" -Default @())) {
        $maintainedPeers += [pscustomobject][ordered]@{
            peer_id = [string](Get-PropertyValue $peer "peer_id" "")
            owner_id = [string](Get-PropertyValue $peer "owner_id" "")
            state = [string](Get-PropertyValue $peer "state" "")
            neighbor_kind = [string](Get-PropertyValue $peer "neighbor_kind" "")
            protected_direct = [bool](Get-PropertyValue $peer "protected_direct" $false)
            reachable = [bool](Get-PropertyValue $peer "reachable" $false)
            route_path = @((Get-PropertyValue $peer "route_path" @()) | ForEach-Object { [string]$_ })
            route_hop_count = [int](Get-PropertyValue $peer "route_hop_count" 0)
            coordinator_id = [string](Get-PropertyValue $peer "coordinator_id" "")
            attempt_id = [string](Get-PropertyValue $peer "attempt_id" "")
            attempt_phase = [string](Get-PropertyValue $peer "attempt_phase" "")
            failures = [int](Get-PropertyValue $peer "failures" 0)
            last_error = [string](Get-PropertyValue $peer "last_error" "")
        }
    }
    $maintainedPeers = @($maintainedPeers | Sort-Object peer_id)

    $desiredPeers = Get-PropertyValue -InputObject $Status -Name "desired_bootstrap_peers" -Default ([pscustomobject]@{})
    $desiredPeerIDs = @($desiredPeers.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object -Unique)
    $counters = Get-PropertyValue -InputObject $Status -Name "counters" -Default ([pscustomobject]@{})
    return [pscustomobject][ordered]@{
        node_id = [string](Get-PropertyValue $Status "node_id" "")
        started_at = [string](Get-PropertyValue $Status "started_at" "")
        uptime = [string](Get-PropertyValue $Status "uptime" "")
        neighbors = $neighbors
        desired_bootstrap_peers = $desiredPeers
        routes = $routes
        stable_shortcuts = $stableShortcuts
        stable_attempt_ids = $stableAttemptIDs
        stable_direct_peer_ids = $directPeerIDs
        maintained_direct_peers_present = $maintainedPeersPresent
        maintained_direct_peers = $maintainedPeers
        desired_bootstrap_peer_ids = $desiredPeerIDs
        counters = $counters
        infrastructure_coordinator_started = [bool](Get-PropertyValue $Status "infrastructure_coordinator_started" $false)
    }
}

function Test-StringSetEqual {
    param(
        [object[]]$Left,
        [object[]]$Right
    )

    $leftValues = @($Left | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $rightValues = @($Right | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($leftValues.Count -ne $rightValues.Count) {
        return $false
    }
    for ($index = 0; $index -lt $leftValues.Count; $index++) {
        if ($leftValues[$index] -ne $rightValues[$index]) {
            return $false
        }
    }
    return $true
}

function Get-TopologyHealth {
    param([object]$NormalizedStatus)

    $nodeID = $NormalizedStatus.node_id
    $expectedPeers = @($script:Nodes.Keys | Where-Object { $_ -ne $nodeID } | Sort-Object)
    $actualNeighbors = @($NormalizedStatus.neighbors | Sort-Object)
    $actualDirectPeers = @($NormalizedStatus.stable_direct_peer_ids | Sort-Object)
    $participantRecords = @($NormalizedStatus.stable_shortcuts | Where-Object {
            $_.local_role -in @("initiator", "target") -and -not [string]::IsNullOrWhiteSpace($_.direct_peer_id)
        })
    $actualDirectAttemptIDs = @($participantRecords | ForEach-Object { $_.attempt_id } | Sort-Object -Unique)
    $neighborsMatch = Test-StringSetEqual -Left $expectedPeers -Right $actualNeighbors
    $legacyDirectPeersMatch = ($participantRecords.Count -eq $expectedPeers.Count -and
        (Test-StringSetEqual -Left $expectedPeers -Right $actualDirectPeers))
    $maintainedPeersPresent = [bool]$NormalizedStatus.maintained_direct_peers_present
    $maintainedPeers = @($NormalizedStatus.maintained_direct_peers)
    $maintainedPeerIDs = @($maintainedPeers | ForEach-Object { $_.peer_id } | Sort-Object -Unique)
    $maintainedPeersHealthy = ($maintainedPeers.Count -eq $expectedPeers.Count -and
        (Test-StringSetEqual -Left $expectedPeers -Right $maintainedPeerIDs) -and
        @($maintainedPeers | Where-Object {
                $_.state -ne "healthy" -or $_.neighbor_kind -ne "packet" -or
                -not $_.protected_direct -or -not $_.reachable
            }).Count -eq 0)
    $directEvidenceSource = if ($maintainedPeersPresent) { "maintained_direct_peers" } else { "stable_shortcuts" }
    $directPeersMatch = if ($maintainedPeersPresent) { $maintainedPeersHealthy } else { $legacyDirectPeersMatch }
    $desiredPeersEmpty = @($NormalizedStatus.desired_bootstrap_peer_ids).Count -eq 0
    $legacyDirectMetadataValid = @($participantRecords | Where-Object {
            $_.strategy -ne "birthday_punch" -or $_.connection_type -ne "direct" -or
            $_.path_id -ne "birthdaypunch/direct" -or $_.path_role -ne "protected_direct" -or
            [string]::IsNullOrWhiteSpace($_.remote_addr) -or @($_.dependencies).Count -ne 0
        }).Count -eq 0
    $directMetadataValid = if ($maintainedPeersPresent) { $maintainedPeersHealthy } else { $legacyDirectMetadataValid }
    $noInfrastructureCoordinator = -not $NormalizedStatus.infrastructure_coordinator_started

    $routeDestinations = @($NormalizedStatus.routes | ForEach-Object { $_.destination })
    $oneHopRoutes = ($NormalizedStatus.routes.Count -eq $expectedPeers.Count -and
        (Test-StringSetEqual -Left $expectedPeers -Right $routeDestinations))
    foreach ($peerID in $expectedPeers) {
        $matchingRoutes = @($NormalizedStatus.routes | Where-Object { $_.destination -eq $peerID })
        if ($matchingRoutes.Count -ne 1) {
            $oneHopRoutes = $false
            break
        }
        $route = $matchingRoutes[0]
        if ($route.next_hop -ne $peerID -or $route.hop_count -ne 1) {
            $oneHopRoutes = $false
            break
        }
        $path = @($route.path)
        if ($path.Count -ne 2 -or $path[0] -ne $nodeID -or $path[1] -ne $peerID) {
            $oneHopRoutes = $false
            break
        }
    }

    $configuredEdges = @($script:ExpectedEdges | Where-Object { -not [string]::IsNullOrWhiteSpace($_.attempt_id) })
    $manifestConfigured = ($configuredEdges.Count -eq 0 -or $configuredEdges.Count -eq 3)
    $incidentEdges = @($configuredEdges | Where-Object { $_.initiator_id -eq $nodeID -or $_.target_id -eq $nodeID })
    $manifestChecks = @()
    $edgeManifestMatch = $manifestConfigured
    if ($configuredEdges.Count -eq 3) {
        if ($participantRecords.Count -ne $incidentEdges.Count) {
            $edgeManifestMatch = $false
        }
        foreach ($edge in $incidentEdges) {
            $records = @($participantRecords | Where-Object { $_.attempt_id -eq $edge.attempt_id })
            $expectedRole = if ($edge.initiator_id -eq $nodeID) { "initiator" } else { "target" }
            $expectedPeer = if ($edge.initiator_id -eq $nodeID) { $edge.target_id } else { $edge.initiator_id }
            $valid = ($records.Count -eq 1)
            if ($valid) {
                $record = $records[0]
                $valid = ($record.initiator_id -eq $edge.initiator_id -and
                    $record.target_id -eq $edge.target_id -and $record.coordinator_id -eq $edge.coordinator_id -and
                    $record.local_role -eq $expectedRole -and $record.direct_peer_id -eq $expectedPeer -and
                    $record.strategy -eq "birthday_punch" -and $record.connection_type -eq "direct" -and
                    $record.path_id -eq "birthdaypunch/direct" -and $record.path_role -eq "protected_direct" -and
                    -not [string]::IsNullOrWhiteSpace($record.remote_addr) -and @($record.dependencies).Count -eq 0)
            }
            if (-not $valid) { $edgeManifestMatch = $false }
            $manifestChecks += [pscustomobject][ordered]@{
                edge = $edge.edge; attempt_id = $edge.attempt_id; expected_role = $expectedRole
                expected_peer = $expectedPeer; matching_records = $records.Count; valid = $valid
            }
        }
        foreach ($edge in @($configuredEdges | Where-Object { $_.coordinator_id -eq $nodeID })) {
            $records = @($NormalizedStatus.stable_shortcuts | Where-Object { $_.attempt_id -eq $edge.attempt_id })
            $valid = ($records.Count -eq 0)
            if ($records.Count -eq 1) {
                $record = $records[0]
                $valid = ($record.initiator_id -eq $edge.initiator_id -and $record.target_id -eq $edge.target_id -and
                    $record.coordinator_id -eq $edge.coordinator_id -and $record.local_role -eq "coordinator")
            } elseif ($records.Count -gt 1) {
                $valid = $false
            }
            if (-not $valid) { $edgeManifestMatch = $false }
            $manifestChecks += [pscustomobject][ordered]@{
                edge = $edge.edge; attempt_id = $edge.attempt_id; expected_role = "coordinator_or_absent"
                expected_peer = ""; matching_records = $records.Count; valid = $valid
            }
        }
    }

    $configuredStartedAtCount = @($script:ExpectedStartedAt.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    $startedAtManifestConfigured = ($configuredStartedAtCount -eq 0 -or $configuredStartedAtCount -eq 3)
    $expectedStartedAt = [string]$script:ExpectedStartedAt[$nodeID]
    $startedAtMatches = ($startedAtManifestConfigured -and
        ([string]::IsNullOrWhiteSpace($expectedStartedAt) -or $NormalizedStatus.started_at -eq $expectedStartedAt))
    return [pscustomobject][ordered]@{
        expected_peers = $expectedPeers
        complete_neighbor_set = $neighborsMatch
        one_hop_routes = $oneHopRoutes
        stable_direct_shortcuts_to_both_peers = $legacyDirectPeersMatch
        maintained_direct_peers_present = $maintainedPeersPresent
        maintained_direct_peers_healthy = $maintainedPeersHealthy
        direct_evidence_source = $directEvidenceSource
        direct_evidence_to_both_peers = $directPeersMatch
        desired_bootstrap_peers_empty = $desiredPeersEmpty
        local_stable_direct_attempt_ids = $actualDirectAttemptIDs
        edge_manifest_configured = ($configuredEdges.Count -eq 3)
        edge_manifest_matches = $edgeManifestMatch
        edge_manifest_checks = $manifestChecks
        expected_started_at = $expectedStartedAt
        started_at_matches = $startedAtMatches
        direct_shortcut_metadata_valid = $legacyDirectMetadataValid
        direct_evidence_metadata_valid = $directMetadataValid
        infrastructure_coordinator_stopped = $noInfrastructureCoordinator
        complete_direct_triangle_locally = ($neighborsMatch -and $oneHopRoutes -and $directPeersMatch -and
            $desiredPeersEmpty -and $edgeManifestMatch -and $startedAtMatches -and
            $directMetadataValid -and $noInfrastructureCoordinator)
    }
}

function Get-OrCreateNodeState {
    param([string]$NodeID)

    if (-not $script:NodeStates.ContainsKey($NodeID)) {
        $script:NodeStates[$NodeID] = [pscustomobject][ordered]@{
            NodeID = $NodeID
            StartedAtValues = (New-Object 'System.Collections.Generic.HashSet[string]')
            FirstStartedAt = ""
            LastStartedAt = ""
            RestartChanges = 0
            FirstNeighborSignature = $null
            LastNeighborSignature = $null
            NeighborChanges = 0
            FirstRouteSignature = $null
            LastRouteSignature = $null
            RouteChanges = 0
            FirstDirectSignature = $null
            LastDirectSignature = $null
            StableDirectChanges = 0
            SuccessfulStatusSamples = 0
            DirectTriangleSamples = 0
            LastStatus = $null
            LastHealth = $null
        }
    }
    return $script:NodeStates[$NodeID]
}

function Write-ContinuityChange {
    param(
        [string]$NodeID,
        [string]$ChangeKind,
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [int]$SampleIndex
    )

    Write-JsonLine ([pscustomobject][ordered]@{
            schema_version = 1
            event = "continuity_change"
            timestamp = [DateTimeOffset]::UtcNow.ToString('o')
            elapsed_seconds = [math]::Round(([DateTimeOffset]::UtcNow - $script:RunStartedUtc).TotalSeconds, 3)
            sample_index = $SampleIndex
            node_id = $NodeID
            change_kind = $ChangeKind
            previous = $Previous
            current = $Current
            action_taken = "none"
            policy = $script:Policy
        })
}

function Update-NodeContinuity {
    param(
        [object]$NormalizedStatus,
        [object]$Health,
        [int]$SampleIndex
    )

    $nodeID = $NormalizedStatus.node_id
    $state = Get-OrCreateNodeState -NodeID $nodeID
    $state.SuccessfulStatusSamples++
    if ($Health.complete_direct_triangle_locally) {
        $state.DirectTriangleSamples++
    }

    $startedAt = $NormalizedStatus.started_at
    if (-not [string]::IsNullOrWhiteSpace($startedAt)) {
        [void]$state.StartedAtValues.Add($startedAt)
        if ([string]::IsNullOrWhiteSpace($state.FirstStartedAt)) {
            $state.FirstStartedAt = $startedAt
        } elseif ($state.LastStartedAt -ne $startedAt) {
            $state.RestartChanges++
            Write-ContinuityChange -NodeID $nodeID -ChangeKind "started_at" -Previous $state.LastStartedAt -Current $startedAt -SampleIndex $SampleIndex
        }
        $state.LastStartedAt = $startedAt
    }

    $neighborSignature = (@($NormalizedStatus.neighbors | Sort-Object) -join ',')
    $routeSignature = (@($NormalizedStatus.routes | ForEach-Object {
                $_.destination + '|' + $_.next_hop + '|' + $_.hop_count + '|' + (@($_.path) -join '>')
            } | Sort-Object) -join ';')
    if ($NormalizedStatus.maintained_direct_peers_present) {
        $directSignature = (@($NormalizedStatus.maintained_direct_peers | ForEach-Object {
                    $_.peer_id + '|' + $_.state + '|' + $_.neighbor_kind + '|' +
                    [string]$_.protected_direct + '|' + [string]$_.reachable
                } | Sort-Object) -join ';')
        $directChangeKind = "maintained_direct_peers"
    } else {
        $directSignature = (@($NormalizedStatus.stable_shortcuts | Where-Object {
                    $_.connection_type -eq "direct" -and -not [string]::IsNullOrWhiteSpace($_.direct_peer_id)
                } | ForEach-Object {
                    $_.attempt_id + '|' + $_.direct_peer_id + '|' + $_.remote_addr + '|' + $_.path_id + '|' + $_.path_role
                } | Sort-Object) -join ';')
        $directChangeKind = "stable_direct_shortcuts"
    }

    if ($null -eq $state.FirstNeighborSignature) {
        $state.FirstNeighborSignature = $neighborSignature
    } elseif ($state.LastNeighborSignature -ne $neighborSignature) {
        $state.NeighborChanges++
        Write-ContinuityChange -NodeID $nodeID -ChangeKind "neighbors" -Previous $state.LastNeighborSignature -Current $neighborSignature -SampleIndex $SampleIndex
    }
    if ($null -eq $state.FirstRouteSignature) {
        $state.FirstRouteSignature = $routeSignature
    } elseif ($state.LastRouteSignature -ne $routeSignature) {
        $state.RouteChanges++
        Write-ContinuityChange -NodeID $nodeID -ChangeKind "routes" -Previous $state.LastRouteSignature -Current $routeSignature -SampleIndex $SampleIndex
    }
    if ($null -eq $state.FirstDirectSignature) {
        $state.FirstDirectSignature = $directSignature
    } elseif ($state.LastDirectSignature -ne $directSignature) {
        $state.StableDirectChanges++
        Write-ContinuityChange -NodeID $nodeID -ChangeKind $directChangeKind -Previous $state.LastDirectSignature -Current $directSignature -SampleIndex $SampleIndex
    }

    $state.LastNeighborSignature = $neighborSignature
    $state.LastRouteSignature = $routeSignature
    $state.LastDirectSignature = $directSignature
    $state.LastStatus = $NormalizedStatus
    $state.LastHealth = $Health
}

function Invoke-StatusSample {
    param(
        [int]$SampleIndex,
        [DateTimeOffset]$ScheduledUtc
    )

    $handles = [ordered]@{}
    foreach ($nodeID in $script:Nodes.Keys) {
        $handles[$nodeID] = Start-NodeApiRequest -NodeID $nodeID -Method GET -Path "/v1/status"
    }

    foreach ($nodeID in $script:Nodes.Keys) {
        $result = Complete-CapturedProcess -Handle $handles[$nodeID] -TimeoutMilliseconds ($CommandTimeoutSeconds * 1000)
        $timestamp = [DateTimeOffset]::UtcNow
        $isSsh = ($script:Nodes[$nodeID].Access -eq "ssh")
        $succeeded = Test-ProcessResultOutputCandidate -Result $result -IsSsh:$isSsh
        $errorText = ""
        $normalized = $null
        $health = $null
        if ($succeeded) {
            try {
                $decoded = $result.stdout | ConvertFrom-Json
                $normalized = Normalize-NodeStatus -Status $decoded
                if ($normalized.node_id -ne $nodeID) {
                    throw "expected node_id $nodeID, got $($normalized.node_id)"
                }
                $health = Get-TopologyHealth -NormalizedStatus $normalized
            } catch {
                $succeeded = $false
                $errorText = "invalid status JSON: $($_.Exception.Message)"
            }
        } else {
            $errorText = Get-ProcessFailureText -Result $result
        }

        $streak = Update-ProbeState -Key "status:$nodeID" -Kind "status" -Succeeded $succeeded -TimestampUtc $timestamp -ObservedMilliseconds $result.elapsed_ms -ErrorText $errorText
        $event = [pscustomobject][ordered]@{
            schema_version = 1
            event = "status"
            timestamp = $timestamp.ToString('o')
            elapsed_seconds = [math]::Round(($timestamp - $script:RunStartedUtc).TotalSeconds, 3)
            sample_index = $SampleIndex
            scheduled_at = $ScheduledUtc.ToString('o')
            schedule_lag_ms = [math]::Round(($timestamp - $ScheduledUtc).TotalMilliseconds, 3)
            node_id = $nodeID
            access = $script:Nodes[$nodeID].Description
            ok = $succeeded
            observed_ms = $result.elapsed_ms
            exit_code = $result.exit_code
            raw_transport_ok = $result.ok
            transport_timed_out = $result.timed_out
            complete_output_line = $result.complete_output_line
            transport_close_anomaly = $result.transport_close_anomaly
            accepted_after_transport_close_anomaly = ($succeeded -and $result.transport_close_anomaly)
            transport_stderr = Limit-Text -Value $result.stderr -MaximumLength 512
            error = Limit-Text -Value $errorText
            consecutive_failures = $streak.consecutive_failures
            max_consecutive_failures = $streak.max_consecutive_failures
            failure_streak_seconds = $streak.failure_streak_seconds
            recovered_failures = $streak.recovered_failures
            recovered_failure_seconds = $streak.recovered_failure_seconds
            status = $normalized
            topology_health = $health
        }
        Write-JsonLine $event
        if ($succeeded) {
            Update-NodeContinuity -NormalizedStatus $normalized -Health $health -SampleIndex $SampleIndex
        }
    }
}

function Test-OneHopPingPath {
    param(
        [string]$SourceID,
        [string]$TargetID,
        [object]$PingResult
    )

    $requestPath = @((Get-PropertyValue $PingResult "request_path" @()) | ForEach-Object { [string]$_ })
    $replyPath = @((Get-PropertyValue $PingResult "reply_path" @()) | ForEach-Object { [string]$_ })
    return ($requestPath.Count -eq 2 -and $requestPath[0] -eq $SourceID -and $requestPath[1] -eq $TargetID -and
        $replyPath.Count -eq 2 -and $replyPath[0] -eq $TargetID -and $replyPath[1] -eq $SourceID)
}

function Invoke-PingRound {
    param(
        [int]$RoundIndex,
        [DateTimeOffset]$ScheduledUtc
    )

    $directions = @(
        @("A", "B"), @("A", "C"),
        @("B", "A"), @("B", "C"),
        @("C", "A"), @("C", "B")
    )
    foreach ($direction in $directions) {
        $sourceID = $direction[0]
        $targetID = $direction[1]
        $payload = "soak:$($script:RunID):${RoundIndex}:${sourceID}-${targetID}"
        $body = [pscustomobject][ordered]@{
            target_id = $targetID
            payload = $payload
            timeout = "${PingTimeoutSeconds}s"
        } | ConvertTo-Json -Compress
        $handle = Start-NodeApiRequest -NodeID $sourceID -Method POST -Path "/v1/ping" -Body $body
        # Keep the soak observational and low disturbance. In particular, two
        # simultaneous B probes would open two routed SSH flows over A-B while
        # the status and hostname probes may already use that same edge.
        $result = Complete-CapturedProcess -Handle $handle -TimeoutMilliseconds ($CommandTimeoutSeconds * 1000)
        $completedUtc = [DateTimeOffset]::UtcNow
        $startedUtc = $handle.StartedUtc
        $isSsh = ($script:Nodes[$sourceID].Access -eq "ssh")
        $succeeded = Test-ProcessResultOutputCandidate -Result $result -IsSsh:$isSsh
        $errorText = ""
        $apiRttMilliseconds = $null
        $requestPath = @()
        $replyPath = @()
        $oneHop = $false
        if ($succeeded) {
            try {
                $decoded = $result.stdout | ConvertFrom-Json
                if ([string](Get-PropertyValue $decoded "target_id" "") -ne $targetID) {
                    throw "unexpected ping target_id"
                }
                if ([string](Get-PropertyValue $decoded "payload" "") -ne $payload) {
                    throw "unexpected ping payload"
                }
                $rttNanoseconds = [double](Get-PropertyValue $decoded "rtt" 0)
                $apiRttMilliseconds = [math]::Round($rttNanoseconds / 1000000.0, 6)
                $requestPath = @((Get-PropertyValue $decoded "request_path" @()) | ForEach-Object { [string]$_ })
                $replyPath = @((Get-PropertyValue $decoded "reply_path" @()) | ForEach-Object { [string]$_ })
                $oneHop = Test-OneHopPingPath -SourceID $sourceID -TargetID $targetID -PingResult $decoded
                if (-not $oneHop) {
                    $succeeded = $false
                    $errorText = "ping succeeded but request/reply path was not one-hop direct"
                }
            } catch {
                $succeeded = $false
                $errorText = "invalid ping JSON: $($_.Exception.Message)"
                $apiRttMilliseconds = $null
            }
        } else {
            $errorText = Get-ProcessFailureText -Result $result
        }

        $key = "ping:${sourceID}->${targetID}"
        $streak = Update-ProbeState -Key $key -Kind "ping" -Succeeded $succeeded -TimestampUtc $completedUtc -RttMilliseconds $apiRttMilliseconds -ObservedMilliseconds $result.elapsed_ms -ErrorText $errorText
        Write-JsonLine ([pscustomobject][ordered]@{
                schema_version = 1
                event = "ping"
                timestamp = $completedUtc.ToString('o')
                started_at = $startedUtc.ToString('o')
                completed_at = $completedUtc.ToString('o')
                elapsed_seconds = [math]::Round(($completedUtc - $script:RunStartedUtc).TotalSeconds, 3)
                round_index = $RoundIndex
                scheduled_at = $ScheduledUtc.ToString('o')
                probe_start_lag_ms = [math]::Round(($startedUtc - $ScheduledUtc).TotalMilliseconds, 3)
                source_id = $sourceID
                target_id = $targetID
                access = $script:Nodes[$sourceID].Description
                ok = $succeeded
                api_rtt_ms = $apiRttMilliseconds
                observed_ms = $result.elapsed_ms
                request_path = $requestPath
                reply_path = $replyPath
                one_hop_both_ways = $oneHop
                exit_code = $result.exit_code
                raw_transport_ok = $result.ok
                transport_timed_out = $result.timed_out
                complete_output_line = $result.complete_output_line
                transport_close_anomaly = $result.transport_close_anomaly
                accepted_after_transport_close_anomaly = ($succeeded -and $result.transport_close_anomaly)
                transport_stderr = Limit-Text -Value $result.stderr -MaximumLength 512
                error = Limit-Text -Value $errorText
                consecutive_failures = $streak.consecutive_failures
                max_consecutive_failures = $streak.max_consecutive_failures
                failure_streak_seconds = $streak.failure_streak_seconds
                recovered_failures = $streak.recovered_failures
                recovered_failure_seconds = $streak.recovered_failure_seconds
            })
    }
}

function Invoke-DirectSshProbe {
    param(
        [int]$ProbeIndex,
        [DateTimeOffset]$ScheduledUtc
    )

    $authentication = Get-SshAuthenticationConfiguration -AskPassPath $BAskPassPath -PasswordEnvironmentVariable $BPasswordEnvironmentVariable
    $arguments = New-SshArguments -User $BUser -HostName $BHost -Port $BPort -ProxyCommand $BProxyCommand -RemoteCommand "hostname" -UseAskPass:$authentication.UseAskPass
    $handle = Start-CapturedProcess -FilePath $SshExecutable -Arguments $arguments -EnvironmentVariables $authentication.EnvironmentVariables -CompleteOnOutputLine
    $result = Complete-CapturedProcess -Handle $handle -TimeoutMilliseconds ($CommandTimeoutSeconds * 1000)
    $timestamp = [DateTimeOffset]::UtcNow
    $hostnameLines = @($result.stdout -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $hostname = if ($hostnameLines.Count -eq 1) { Limit-Text -Value $hostnameLines[0] -MaximumLength 256 } else { "" }
    $outputCandidate = Test-ProcessResultOutputCandidate -Result $result -IsSsh
    $succeeded = ($outputCandidate -and $hostnameLines.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($hostname))
    $errorText = ""
    if (-not $succeeded) {
        if (-not $outputCandidate) {
            $errorText = Get-ProcessFailureText -Result $result
        } else {
            $errorText = "hostname did not return exactly one non-empty line"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($BExpectedHostname) -and $hostname.Trim() -ne $BExpectedHostname.Trim()) {
        $succeeded = $false
        $errorText = "expected hostname '$BExpectedHostname', got '$hostname'"
    }

    $streak = Update-ProbeState -Key "ssh:A->B" -Kind "direct_ssh" -Succeeded $succeeded -TimestampUtc $timestamp -ObservedMilliseconds $result.elapsed_ms -ErrorText $errorText
    Write-JsonLine ([pscustomobject][ordered]@{
            schema_version = 1
            event = "direct_ssh"
            timestamp = $timestamp.ToString('o')
            elapsed_seconds = [math]::Round(($timestamp - $script:RunStartedUtc).TotalSeconds, 3)
            probe_index = $ProbeIndex
            scheduled_at = $ScheduledUtc.ToString('o')
            source_id = "A"
            target_id = "B"
            endpoint = "${BHost}:$BPort"
            proxy_jump = if ([string]::IsNullOrWhiteSpace($BProxyCommand)) { "none" } else { "proxy_command" }
            command = "hostname"
            ok = $succeeded
            hostname = $hostname
            observed_ms = $result.elapsed_ms
            exit_code = $result.exit_code
            raw_transport_ok = $result.ok
            transport_timed_out = $result.timed_out
            complete_output_line = $result.complete_output_line
            transport_close_anomaly = $result.transport_close_anomaly
            accepted_after_transport_close_anomaly = ($succeeded -and $result.transport_close_anomaly)
            stderr = Limit-Text -Value $result.stderr -MaximumLength 512
            error = Limit-Text -Value $errorText
            consecutive_failures = $streak.consecutive_failures
            max_consecutive_failures = $streak.max_consecutive_failures
            failure_streak_seconds = $streak.failure_streak_seconds
            recovered_failures = $streak.recovered_failures
            recovered_failure_seconds = $streak.recovered_failure_seconds
        })
}

function Get-ListenerSnapshot {
    param([int]$Port)

    try {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop |
            Where-Object { $_.LocalAddress -eq "127.0.0.1" } |
            Select-Object -First 1
        if ($null -eq $listener) {
            return [pscustomobject][ordered]@{ found = $false; port = $Port }
        }
        $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        return [pscustomobject][ordered]@{
            found = $true
            address = $listener.LocalAddress
            port = $listener.LocalPort
            owning_pid = $listener.OwningProcess
            process_name = if ($null -eq $process) { "" } else { $process.ProcessName }
            process_started_at = if ($null -eq $process) { "" } else { $process.StartTime.ToString('o') }
        }
    } catch {
        return [pscustomobject][ordered]@{
            found = $false
            port = $Port
            inspection_error = $_.Exception.Message
        }
    }
}

function Get-NodeSummary {
    param([string]$NodeID)

    $state = Get-OrCreateNodeState -NodeID $NodeID
    return [pscustomobject][ordered]@{
        node_id = $NodeID
        successful_status_samples = $state.SuccessfulStatusSamples
        direct_triangle_samples = $state.DirectTriangleSamples
        all_successful_samples_were_direct_triangle = ($state.SuccessfulStatusSamples -gt 0 -and $state.DirectTriangleSamples -eq $state.SuccessfulStatusSamples)
        first_started_at = $state.FirstStartedAt
        last_started_at = $state.LastStartedAt
        distinct_started_at = @($state.StartedAtValues | Sort-Object)
        restart_changes = $state.RestartChanges
        first_neighbor_signature = $state.FirstNeighborSignature
        last_neighbor_signature = $state.LastNeighborSignature
        neighbor_changes = $state.NeighborChanges
        first_route_signature = $state.FirstRouteSignature
        last_route_signature = $state.LastRouteSignature
        route_changes = $state.RouteChanges
        first_stable_direct_signature = $state.FirstDirectSignature
        last_stable_direct_signature = $state.LastDirectSignature
        stable_direct_changes = $state.StableDirectChanges
        last_status = $state.LastStatus
        last_topology_health = $state.LastHealth
    }
}

function New-FinalSummary {
    param(
        [DateTimeOffset]$EndedUtc,
        [string]$CompletionReason,
        [string]$FatalError,
        [string]$EventsPath
    )

    $probeSummaries = @($script:ProbeStates.Keys | Sort-Object | ForEach-Object {
            Get-ProbeSummary -State $script:ProbeStates[$_]
        })
    $nodeSummaries = @($script:Nodes.Keys | ForEach-Object { Get-NodeSummary -NodeID $_ })
    $probeFailures = @($script:ProbeStates.Values | Where-Object { $_.Failures -gt 0 }).Count
    $continuityChanges = 0
    $finalTriangle = $true
    $allSuccessfulSamplesDirect = $true
    foreach ($nodeSummary in $nodeSummaries) {
        $continuityChanges += $nodeSummary.restart_changes + $nodeSummary.neighbor_changes + $nodeSummary.route_changes + $nodeSummary.stable_direct_changes
        if ($null -eq $nodeSummary.last_topology_health -or -not $nodeSummary.last_topology_health.complete_direct_triangle_locally) {
            $finalTriangle = $false
        }
        if (-not $nodeSummary.all_successful_samples_were_direct_triangle) {
            $allSuccessfulSamplesDirect = $false
        }
    }
    $statusProbeKeys = @("status:A", "status:B", "status:C")
    $pingProbeKeys = @("ping:A->B", "ping:A->C", "ping:B->A", "ping:B->C", "ping:C->A", "ping:C->B")
    $sshProbeKeys = @("ssh:A->B")
    $expectedProbeKeys = @($statusProbeKeys) + @($pingProbeKeys) + @($sshProbeKeys)
    $missingProbeSeries = @($expectedProbeKeys | Where-Object { -not $script:ProbeStates.ContainsKey($_) })
    $missedSlots = $script:MissedStatusSlots + $script:MissedPingSlots + $script:MissedSshSlots
    $cleanSoak = ($CompletionReason -eq "duration_completed" -and $missingProbeSeries.Count -eq 0 -and
        $probeFailures -eq 0 -and $continuityChanges -eq 0 -and $missedSlots -eq 0 -and
        $finalTriangle -and $allSuccessfulSamplesDirect)

    $statusRollup = Get-ProbeRollup -ExpectedKeys $statusProbeKeys
    $pingRollup = Get-ProbeRollup -ExpectedKeys $pingProbeKeys
    $sshRollup = Get-ProbeRollup -ExpectedKeys $sshProbeKeys
    $topologyObserved = @($nodeSummaries | Where-Object { $_.successful_status_samples -eq 0 }).Count -eq 0
    $topologyCriterionMet = ($topologyObserved -and $continuityChanges -eq 0 -and $finalTriangle -and $allSuccessfulSamplesDirect)
    $managementCriterionMet = ($statusRollup.missing_probe_series.Count -eq 0 -and $statusRollup.failures -eq 0)
    $pingCriterionMet = ($pingRollup.missing_probe_series.Count -eq 0 -and $pingRollup.failures -eq 0)
    $sshCriterionMet = ($sshRollup.missing_probe_series.Count -eq 0 -and $sshRollup.failures -eq 0)
    $scheduleCriterionMet = ($missedSlots -eq 0)

    $dimensions = [pscustomobject][ordered]@{
        topology_continuity = [pscustomobject][ordered]@{
            verdict = Get-DimensionVerdict -Observed $topologyObserved -CriterionMet $topologyCriterionMet -CompletionReason $CompletionReason
            criterion_met = $topologyCriterionMet
            continuity_change_count = $continuityChanges
            final_complete_direct_triangle = $finalTriangle
            all_successful_status_samples_were_direct_triangle = $allSuccessfulSamplesDirect
            successful_status_samples = $statusRollup.successes
            unobserved_status_samples = $statusRollup.failures
        }
        management_status = [pscustomobject][ordered]@{
            verdict = Get-DimensionVerdict -Observed ($statusRollup.missing_probe_series.Count -eq 0) -CriterionMet $managementCriterionMet -CompletionReason $CompletionReason
            criterion_met = $managementCriterionMet
            attempts = $statusRollup.attempts
            successes = $statusRollup.successes
            failures = $statusRollup.failures
            probe_series_with_failures = $statusRollup.probe_series_with_failures
            missing_probe_series = $statusRollup.missing_probe_series
        }
        best_effort_control_ping_zero_loss = [pscustomobject][ordered]@{
            verdict = Get-DimensionVerdict -Observed ($pingRollup.missing_probe_series.Count -eq 0) -CriterionMet $pingCriterionMet -CompletionReason $CompletionReason
            criterion_met = $pingCriterionMet
            attempts = $pingRollup.attempts
            successes = $pingRollup.successes
            failures = $pingRollup.failures
            probe_series_with_failures = $pingRollup.probe_series_with_failures
            missing_probe_series = $pingRollup.missing_probe_series
        }
        routed_ssh = [pscustomobject][ordered]@{
            verdict = Get-DimensionVerdict -Observed ($sshRollup.missing_probe_series.Count -eq 0) -CriterionMet $sshCriterionMet -CompletionReason $CompletionReason
            criterion_met = $sshCriterionMet
            attempts = $sshRollup.attempts
            successes = $sshRollup.successes
            failures = $sshRollup.failures
            probe_series_with_failures = $sshRollup.probe_series_with_failures
            missing_probe_series = $sshRollup.missing_probe_series
        }
        schedule = [pscustomobject][ordered]@{
            verdict = Get-DimensionVerdict -Observed $true -CriterionMet $scheduleCriterionMet -CompletionReason $CompletionReason
            criterion_met = $scheduleCriterionMet
            duration_completed = ($CompletionReason -eq "duration_completed")
            missed_slots = $missedSlots
            missed_status_slots = $script:MissedStatusSlots
            missed_ping_slots = $script:MissedPingSlots
            missed_ssh_slots = $script:MissedSshSlots
        }
    }

    return [pscustomobject][ordered]@{
        schema_version = 1
        run_id = $script:RunID
        policy = $script:Policy
        started_at = $script:RunStartedUtc.ToString('o')
        ended_at = $EndedUtc.ToString('o')
        observed_seconds = [math]::Round(($EndedUtc - $script:RunStartedUtc).TotalSeconds, 3)
        configured_duration_seconds = $DurationSeconds
        expected_edges = $script:ExpectedEdges
        expected_started_at = $script:ExpectedStartedAt
        completion_reason = $CompletionReason
        fatal_error = $FatalError
        verdict = if ($cleanSoak) { "pass" } else { "observed_failures_or_changes" }
        clean_soak = $cleanSoak
        final_complete_direct_triangle = $finalTriangle
        all_successful_status_samples_were_direct_triangle = $allSuccessfulSamplesDirect
        missing_probe_series = $missingProbeSeries
        probe_series_with_failures = $probeFailures
        continuity_change_count = $continuityChanges
        missed_schedule_slots = $missedSlots
        dimensions = $dimensions
        schedule = [pscustomobject][ordered]@{
            status_interval_seconds = $SampleIntervalSeconds
            ping_interval_seconds = $PingIntervalSeconds
            ssh_interval_seconds = $SshIntervalSeconds
            status_samples_attempted = $script:StatusSamplesAttempted
            ping_rounds_attempted = $script:PingRoundsAttempted
            ssh_probes_attempted = $script:SshProbesAttempted
            missed_status_slots = $script:MissedStatusSlots
            missed_ping_slots = $script:MissedPingSlots
            missed_ssh_slots = $script:MissedSshSlots
        }
        probes = $probeSummaries
        nodes = $nodeSummaries
        artifacts = [pscustomobject][ordered]@{
            events_jsonl = $EventsPath
        }
    }
}

function Get-DefaultOutputDirectory {
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    return Join-Path $repositoryRoot ".live-run\runs\three-node-soak-$stamp"
}

function Initialize-OutputDirectory {
    param([string]$RequestedPath)

    $path = $RequestedPath
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = Get-DefaultOutputDirectory
    }
    $fullPath = [System.IO.Path]::GetFullPath($path)
    [void][System.IO.Directory]::CreateDirectory($fullPath)
    $eventsPath = Join-Path $fullPath "events.jsonl"
    $summaryPath = Join-Path $fullPath "summary.json"
    if (Test-Path -LiteralPath $eventsPath) {
        throw "refusing to overwrite existing event log: $eventsPath"
    }
    if (Test-Path -LiteralPath $summaryPath) {
        throw "refusing to overwrite existing summary: $summaryPath"
    }
    return $fullPath
}

function Start-BackgroundMonitor {
    param([string]$RunDirectory)

    $hostExecutable = if ($PSVersionTable.PSEdition -eq "Core") {
        Join-Path $PSHOME "pwsh.exe"
    } else {
        Join-Path $PSHOME "powershell.exe"
    }
    if (-not (Test-Path -LiteralPath $hostExecutable)) {
        throw "PowerShell executable not found: $hostExecutable"
    }

    $childArguments = New-BackgroundMonitorArguments -RunDirectory $RunDirectory
    $stdoutPath = Join-Path $RunDirectory "monitor.stdout.log"
    $stderrPath = Join-Path $RunDirectory "monitor.stderr.log"
    [System.IO.File]::WriteAllText($stdoutPath, "")
    [System.IO.File]::WriteAllText($stderrPath, "")
    # Do not redirect the long-lived child through Start-Process: Windows
    # PowerShell 5.1 may then retain the redirected handles and wait for it.
    # A hidden child without redirection returns immediately and, unlike a WMI
    # provider-created process, inherits the caller's process environment. That
    # inheritance is required for password values named by the per-node
    # SSH_ASKPASS parameters; values never enter argv, logs, or run.state.json.
    $argumentLine = Join-NativeArguments -Arguments $childArguments
    $backgroundProcess = Start-Process -FilePath $hostExecutable -ArgumentList $argumentLine `
        -WorkingDirectory (Split-Path -Parent $PSScriptRoot) -WindowStyle Hidden -PassThru
    if ($null -eq $backgroundProcess) {
        throw "failed to start background monitor"
    }
    $processID = [int]$backgroundProcess.Id
    $statePath = Join-Path $RunDirectory "run.state.json"
    $eventsPath = Join-Path $RunDirectory "events.jsonl"
    $ready = $false
    for ($attempt = 0; $attempt -lt 200; $attempt++) {
        $process = Get-Process -Id $processID -ErrorAction SilentlyContinue
        if ($null -eq $process) {
            $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -Raw -LiteralPath $stderrPath } else { "" }
            throw "background monitor exited before readiness: $(Limit-Text $stderr)"
        }
        if ((Test-Path -LiteralPath $statePath) -and (Test-Path -LiteralPath $eventsPath) -and
            (Get-Item -LiteralPath $eventsPath).Length -gt 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) {
        try { Stop-Process -Id $processID -Force -ErrorAction SilentlyContinue } catch { }
        throw "background monitor did not become ready within 20 seconds"
    }
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $monitorPID = [int]$state.monitor_pid
    if ($monitorPID -ne $processID -or $null -eq (Get-Process -Id $monitorPID -ErrorAction SilentlyContinue)) {
        throw "background monitor PID/readiness validation failed"
    }
    try { $backgroundProcess.Dispose() } catch { }
    [System.IO.File]::WriteAllText((Join-Path $RunDirectory "monitor.pid"), [string]$monitorPID + [Environment]::NewLine)
    return [pscustomobject][ordered]@{
        started = $true
        ready = $true
        monitor_pid = $monitorPID
        output_directory = $RunDirectory
        events_jsonl = Join-Path $RunDirectory "events.jsonl"
        summary_json = Join-Path $RunDirectory "summary.json"
        policy = $script:Policy
    }
}

function New-BackgroundMonitorArguments {
    param([string]$RunDirectory)

    return @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-DurationSeconds", [string]$DurationSeconds,
        "-SampleIntervalSeconds", [string]$SampleIntervalSeconds,
        "-PingIntervalSeconds", [string]$PingIntervalSeconds,
        "-SshIntervalSeconds", [string]$SshIntervalSeconds,
        "-PingTimeoutSeconds", [string]$PingTimeoutSeconds,
        "-CommandTimeoutSeconds", [string]$CommandTimeoutSeconds,
        "-AApiBase", $AApiBase,
        "-RemoteApiBase", $RemoteApiBase,
        "-BUser", $BUser,
        "-BHost", $BHost,
        "-BPort", [string]$BPort,
        "-BProxyCommand", $BProxyCommand,
        "-BRemoteCurl", $BRemoteCurl,
        "-BExpectedHostname", $BExpectedHostname,
        "-BAskPassPath", $BAskPassPath,
        "-BPasswordEnvironmentVariable", $BPasswordEnvironmentVariable,
        "-ABAttemptID", $ABAttemptID,
        "-BCAttemptID", $BCAttemptID,
        "-ACAttemptID", $ACAttemptID,
        "-ABInitiatorID", $ABInitiatorID,
        "-BCInitiatorID", $BCInitiatorID,
        "-ACInitiatorID", $ACInitiatorID,
        "-AExpectedStartedAt", $AExpectedStartedAt,
        "-BExpectedStartedAt", $BExpectedStartedAt,
        "-CExpectedStartedAt", $CExpectedStartedAt,
        "-CUser", $CUser,
        "-CHost", $CHost,
        "-CPort", [string]$CPort,
        "-CProxyCommand", $CProxyCommand,
        "-CRemoteCurl", $CRemoteCurl,
        "-CAskPassPath", $CAskPassPath,
        "-CPasswordEnvironmentVariable", $CPasswordEnvironmentVariable,
        "-SshExecutable", $SshExecutable,
        "-CurlExecutable", $CurlExecutable,
        "-OutputDirectory", $RunDirectory
    )
}

function Assert-SelfTest {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw "self-test failed: $Message"
    }
}

function Invoke-SelfTest {
    $script:ProbeStates = @{}
    $script:Nodes = [ordered]@{ A = $null; B = $null; C = $null }
    $sample = @'
{
  "node_id":"A",
  "started_at":"2026-07-17T10:00:00Z",
  "uptime":"1m0s",
  "neighbors":["C","B"],
  "desired_bootstrap_peers":{},
  "routes":[
    {"destination":"C","next_hop":"C","hop_count":1,"rtt_millis":2,"path":["A","C"]},
    {"destination":"B","next_hop":"B","hop_count":1,"rtt_millis":1,"path":["A","B"]}
  ],
  "shortcuts":[
    {"attempt_id":"old","phase":"failed","direct_peer_id":"B"},
    {"attempt_id":"live","phase":"stable","direct_peer_id":"B","connection_type":"direct","path_id":"birthdaypunch/direct","path_role":"protected_direct","remote_addr":"192.0.2.1:1234"}
  ],
  "counters":{"data_forwarded":0},
  "infrastructure_coordinator_started":false
}
'@ | ConvertFrom-Json
    $normalized = Normalize-NodeStatus -Status $sample
    Assert-SelfTest ($normalized.neighbors.Count -eq 2 -and $normalized.neighbors[0] -eq "B") "neighbors are sorted"
    Assert-SelfTest ($normalized.routes.Count -eq 2 -and $normalized.routes[0].destination -eq "B") "routes are sorted"
    Assert-SelfTest ($normalized.stable_shortcuts.Count -eq 1 -and $normalized.stable_shortcuts[0].attempt_id -eq "live") "only stable shortcuts are retained"
    Assert-SelfTest ($normalized.stable_direct_peer_ids.Count -eq 1 -and $normalized.stable_direct_peer_ids[0] -eq "B") "direct peer extraction"
    $health = Get-TopologyHealth -NormalizedStatus $normalized
    Assert-SelfTest (-not $health.stable_direct_shortcuts_to_both_peers) "an incomplete direct peer set is reported without throwing"

    $productSample = @'
{
  "node_id":"A",
  "started_at":"2026-07-19T10:00:00Z",
  "uptime":"1m0s",
  "neighbors":["B","C"],
  "desired_bootstrap_peers":{},
  "routes":[
    {"destination":"B","next_hop":"B","hop_count":1,"rtt_millis":1,"path":["A","B"]},
    {"destination":"C","next_hop":"C","hop_count":1,"rtt_millis":2,"path":["A","C"]}
  ],
  "shortcuts":[
    {"attempt_id":"stale","phase":"stable","local_role":"initiator","direct_peer_id":"B","connection_type":"direct","path_role":"primary_candidate"}
  ],
  "maintained_direct_peers":[
    {"peer_id":"B","owner_id":"A","state":"healthy","neighbor_kind":"packet","protected_direct":true,"reachable":true,"route_path":["A","B"],"route_hop_count":1},
    {"peer_id":"C","owner_id":"A","state":"healthy","neighbor_kind":"packet","protected_direct":true,"reachable":true,"route_path":["A","C"],"route_hop_count":1}
  ],
  "counters":{"data_forwarded":0},
  "infrastructure_coordinator_started":false
}
'@ | ConvertFrom-Json
    $productNormalized = Normalize-NodeStatus -Status $productSample
    $productHealth = Get-TopologyHealth -NormalizedStatus $productNormalized
    Assert-SelfTest ($productHealth.direct_evidence_source -eq "maintained_direct_peers" -and $productHealth.maintained_direct_peers_healthy) "product status prefers maintained-direct evidence"
    Assert-SelfTest ($productHealth.complete_direct_triangle_locally -and -not $productHealth.stable_direct_shortcuts_to_both_peers) "healthy maintained peers make product topology healthy despite stale shortcut rows"

    $productSample.maintained_direct_peers[0].protected_direct = $false
    $degradedProductHealth = Get-TopologyHealth -NormalizedStatus (Normalize-NodeStatus -Status $productSample)
    Assert-SelfTest (-not $degradedProductHealth.complete_direct_triangle_locally -and -not $degradedProductHealth.maintained_direct_peers_healthy) "present maintained-direct evidence fails closed when a peer is not protected direct"

    $r12Sample = @'
{
  "node_id":"A",
  "started_at":"2026-07-18T10:00:00Z",
  "uptime":"1m0s",
  "neighbors":["B","C"],
  "desired_bootstrap_peers":{},
  "routes":[
    {"destination":"B","next_hop":"B","hop_count":1,"rtt_millis":1,"path":["A","B"]},
    {"destination":"C","next_hop":"C","hop_count":1,"rtt_millis":2,"path":["A","C"]}
  ],
  "shortcuts":[
    {"attempt_id":"ab","phase":"stable","strategy":"birthday_punch","local_role":"initiator","direct_peer_id":"B","connection_type":"direct","path_id":"birthdaypunch/direct","path_role":"protected_direct","remote_addr":"192.0.2.1:1","dependencies":[]},
    {"attempt_id":"ac","phase":"stable","strategy":"birthday_punch","local_role":"initiator","direct_peer_id":"C","connection_type":"direct","path_id":"birthdaypunch/direct","path_role":"protected_direct","remote_addr":"192.0.2.2:1","dependencies":[]}
  ],
  "counters":{"data_forwarded":0},
  "infrastructure_coordinator_started":false
}
'@ | ConvertFrom-Json
    $r12Health = Get-TopologyHealth -NormalizedStatus (Normalize-NodeStatus -Status $r12Sample)
    Assert-SelfTest ($r12Health.direct_evidence_source -eq "stable_shortcuts" -and $r12Health.complete_direct_triangle_locally) "r12 status without maintained peers retains shortcut fallback"

    $now = [DateTimeOffset]::UtcNow
    $first = Update-ProbeState -Key "test" -Kind "test" -Succeeded $false -TimestampUtc $now -ErrorText "one"
    $second = Update-ProbeState -Key "test" -Kind "test" -Succeeded $false -TimestampUtc $now.AddSeconds(1) -ErrorText "two"
    $third = Update-ProbeState -Key "test" -Kind "test" -Succeeded $true -TimestampUtc $now.AddSeconds(2) -RttMilliseconds 20 -ObservedMilliseconds 30
    Assert-SelfTest ($first.consecutive_failures -eq 1) "first failure streak"
    Assert-SelfTest ($second.consecutive_failures -eq 2 -and $second.max_consecutive_failures -eq 2) "maximum failure streak"
    Assert-SelfTest ($third.consecutive_failures -eq 0 -and $third.recovered_failures -eq 2) "failure recovery"

    $distribution = Get-Distribution -Values @(10, 20, 30, 40)
    Assert-SelfTest ($distribution.p50 -eq 20 -and $distribution.p95 -eq 40) "percentile calculation"
    Assert-SelfTest ((ConvertTo-NativeArgument "two words") -eq '"two words"') "native argument quoting"

    $directSshArguments = @(New-SshArguments -User "node-b-user" -HostName "127.0.0.1" -Port 22024 -RemoteCommand "hostname")
    Assert-SelfTest ($directSshArguments[-2] -eq "node-b-user@127.0.0.1" -and $directSshArguments[-1] -eq "hostname") "direct SSH destination uses the configured host"
    Assert-SelfTest ($directSshArguments -contains "ProxyJump=none" -and @($directSshArguments | Where-Object { $_ -like "ProxyCommand=*" }).Count -eq 0) "direct SSH explicitly disables inherited ProxyJump"
    Assert-SelfTest ($directSshArguments -contains "BatchMode=yes" -and $directSshArguments -contains "PreferredAuthentications=publickey") "unconfigured SSH retains public-key BatchMode behavior"

    $askPassArguments = @(New-SshArguments -User "node-b-user" -HostName "127.0.0.1" -Port 22024 -RemoteCommand "hostname" -UseAskPass)
    Assert-SelfTest ($askPassArguments -contains "BatchMode=no" -and $askPassArguments -contains "PreferredAuthentications=password,keyboard-interactive" -and $askPassArguments -contains "PubkeyAuthentication=no") "configured SSH enables forced askpass-compatible authentication"

    $selfTestPasswordName = "WINKYOU_SOAK_SELFTEST_PASSWORD"
    $selfTestPassword = "soak-self-test-secret"
    $previousSelfTestPassword = [Environment]::GetEnvironmentVariable($selfTestPasswordName, "Process")
    try {
        [Environment]::SetEnvironmentVariable($selfTestPasswordName, $selfTestPassword, "Process")
        $askPassConfiguration = Get-SshAuthenticationConfiguration -AskPassPath $PSCommandPath -PasswordEnvironmentVariable $selfTestPasswordName
    } finally {
        [Environment]::SetEnvironmentVariable($selfTestPasswordName, $previousSelfTestPassword, "Process")
    }
    Assert-SelfTest ($askPassConfiguration.UseAskPass -and $askPassConfiguration.EnvironmentVariables.SSH_ASKPASS_REQUIRE -eq "force") "askpass configuration builds the required child environment"
    Assert-SelfTest ($askPassConfiguration.EnvironmentVariables[$selfTestPasswordName] -eq $selfTestPassword -and ($askPassArguments -join ' ') -notlike "*$selfTestPassword*") "password is carried only in the child environment"
    [void]$script:SensitiveValues.Remove($selfTestPassword)

    $syntheticProxyCommand = 'ssh.exe -T -p 22024 node-b-user@127.0.0.1 ncat.exe 10.20.0.1 22'
    $proxiedSshArguments = @(New-SshArguments -User "node-c-user" -HostName "10.20.0.1" -Port 22 -ProxyCommand $syntheticProxyCommand -RemoteCommand "hostname")
    Assert-SelfTest ($proxiedSshArguments[-2] -eq "node-c-user@10.20.0.1" -and $proxiedSshArguments[-1] -eq "hostname") "proxied SSH destination uses the configured host"
    Assert-SelfTest ($proxiedSshArguments -contains "ProxyCommand=$syntheticProxyCommand" -and $proxiedSshArguments -notcontains "ProxyJump=none") "ProxyCommand remains one argv item and does not compete with ProxyJump"

    $rejectedLineBreak = $false
    try {
        [void](New-SshArguments -User "node-c-user" -HostName "10.20.0.1" -Port 22 -ProxyCommand "unsafe`ncommand" -RemoteCommand "hostname")
    } catch {
        $rejectedLineBreak = $true
    }
    Assert-SelfTest $rejectedLineBreak "SSH connection fields reject line-break injection"

    $environmentHandle = Start-CapturedProcess -FilePath $env:ComSpec -Arguments @("/d", "/c", "echo", "%WINKYOU_SOAK_SELFTEST_MARKER%") -EnvironmentVariables @{ WINKYOU_SOAK_SELFTEST_MARKER = "SOAK_ENV_OK" }
    $environmentResult = Complete-CapturedProcess -Handle $environmentHandle -TimeoutMilliseconds 5000
    Assert-SelfTest ($environmentResult.ok -and $environmentResult.stdout.Trim() -eq "SOAK_ENV_OK") "captured process injects environment variables through ProcessStartInfo"

    $selfTestHost = if ($PSVersionTable.PSEdition -eq "Core") { Join-Path $PSHOME "pwsh.exe" } else { Join-Path $PSHOME "powershell.exe" }
    $completeLineCommand = '[Console]::Out.WriteLine(''{"ok":true}''); Start-Sleep -Seconds 3'
    $completeLineHandle = Start-CapturedProcess -FilePath $selfTestHost -Arguments @("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", $completeLineCommand) -CompleteOnOutputLine
    $completeLineResult = Complete-CapturedProcess -Handle $completeLineHandle -TimeoutMilliseconds 3000 -OutputCloseGraceMilliseconds 100
    $completeLineJson = $completeLineResult.stdout | ConvertFrom-Json
    Assert-SelfTest ($completeLineResult.transport_close_anomaly -and $completeLineResult.terminated_after_complete_output -and $completeLineJson.ok) "complete JSON line is usable when transport EOF hangs"
    Assert-SelfTest ($completeLineResult.elapsed_ms -lt 2000 -and (Test-ProcessResultOutputCandidate -Result $completeLineResult -IsSsh)) "complete SSH output returns before the command timeout"

    $truncatedLineCommand = '[Console]::Out.WriteLine(''{"ok":''); Start-Sleep -Seconds 3'
    $truncatedLineHandle = Start-CapturedProcess -FilePath $selfTestHost -Arguments @("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", $truncatedLineCommand) -CompleteOnOutputLine
    $truncatedLineResult = Complete-CapturedProcess -Handle $truncatedLineHandle -TimeoutMilliseconds 3000 -OutputCloseGraceMilliseconds 100
    $truncatedJsonRejected = $false
    try {
        [void]($truncatedLineResult.stdout | ConvertFrom-Json)
    } catch {
        $truncatedJsonRejected = $true
    }
    Assert-SelfTest ($truncatedLineResult.transport_close_anomaly -and $truncatedJsonRejected) "truncated JSON is rejected even when an SSH output line arrived"

    $backgroundArguments = @(New-BackgroundMonitorArguments -RunDirectory "self-test-output")
    $bHostIndex = [Array]::IndexOf($backgroundArguments, "-BHost")
    $bProxyIndex = [Array]::IndexOf($backgroundArguments, "-BProxyCommand")
    $cHostIndex = [Array]::IndexOf($backgroundArguments, "-CHost")
    $cProxyIndex = [Array]::IndexOf($backgroundArguments, "-CProxyCommand")
    Assert-SelfTest ($bHostIndex -ge 0 -and $bProxyIndex -ge 0 -and $cHostIndex -ge 0 -and $cProxyIndex -ge 0) "background monitor passes all SSH access parameter names"
    Assert-SelfTest ($backgroundArguments[$bHostIndex + 1] -eq $BHost -and $backgroundArguments[$bProxyIndex + 1] -eq $BProxyCommand -and $backgroundArguments[$cHostIndex + 1] -eq $CHost -and $backgroundArguments[$cProxyIndex + 1] -eq $CProxyCommand) "background monitor preserves all SSH access parameter values"
    foreach ($parameterName in @("-BAskPassPath", "-BPasswordEnvironmentVariable", "-CAskPassPath", "-CPasswordEnvironmentVariable")) {
        Assert-SelfTest ([Array]::IndexOf($backgroundArguments, $parameterName) -ge 0) "background monitor passes $parameterName"
    }
    $bAskPassIndex = [Array]::IndexOf($backgroundArguments, "-BAskPassPath")
    $bPasswordNameIndex = [Array]::IndexOf($backgroundArguments, "-BPasswordEnvironmentVariable")
    $cAskPassIndex = [Array]::IndexOf($backgroundArguments, "-CAskPassPath")
    $cPasswordNameIndex = [Array]::IndexOf($backgroundArguments, "-CPasswordEnvironmentVariable")
    Assert-SelfTest ($backgroundArguments[$bAskPassIndex + 1] -eq $BAskPassPath -and $backgroundArguments[$bPasswordNameIndex + 1] -eq $BPasswordEnvironmentVariable -and
        $backgroundArguments[$cAskPassIndex + 1] -eq $CAskPassPath -and $backgroundArguments[$cPasswordNameIndex + 1] -eq $CPasswordEnvironmentVariable) "background monitor preserves per-node askpass parameter values without password values"

    $abEdge = @($script:ExpectedEdges | Where-Object { $_.edge -eq "A-B" })[0]
    $bcEdge = @($script:ExpectedEdges | Where-Object { $_.edge -eq "B-C" })[0]
    $acEdge = @($script:ExpectedEdges | Where-Object { $_.edge -eq "A-C" })[0]
    Assert-SelfTest ($abEdge.initiator_id -eq $ABInitiatorID -and $abEdge.target_id -eq $abTargetID -and $bcEdge.initiator_id -eq $BCInitiatorID -and $bcEdge.target_id -eq $bcTargetID -and $acEdge.initiator_id -eq $ACInitiatorID -and $acEdge.target_id -eq $acTargetID) "each edge target is derived from its configurable initiator"

    $abInitiatorIndex = [Array]::IndexOf($backgroundArguments, "-ABInitiatorID")
    $bcInitiatorIndex = [Array]::IndexOf($backgroundArguments, "-BCInitiatorID")
    $acInitiatorIndex = [Array]::IndexOf($backgroundArguments, "-ACInitiatorID")
    Assert-SelfTest ($abInitiatorIndex -ge 0 -and $bcInitiatorIndex -ge 0 -and $acInitiatorIndex -ge 0) "background monitor passes all edge initiator parameter names"
    Assert-SelfTest ($backgroundArguments[$abInitiatorIndex + 1] -eq $ABInitiatorID -and $backgroundArguments[$bcInitiatorIndex + 1] -eq $BCInitiatorID -and $backgroundArguments[$acInitiatorIndex + 1] -eq $ACInitiatorID) "background monitor preserves all edge initiator parameter values"

    $processHandle = Start-CapturedProcess -FilePath $env:ComSpec -Arguments @("/d", "/c", "echo", "SOAK_SELF_TEST")
    $processResult = Complete-CapturedProcess -Handle $processHandle -TimeoutMilliseconds 5000
    Assert-SelfTest ($processResult.ok -and $processResult.stdout.Trim() -eq "SOAK_SELF_TEST") "captured process execution"

    # Exercise the final-summary compatibility verdict and the independent
    # dimensions without starting network probes.
    $script:ProbeStates = @{}
    $script:NodeStates = @{}
    $script:RunID = "self-test"
    $script:RunStartedUtc = $now
    $script:StatusSamplesAttempted = 1
    $script:PingRoundsAttempted = 1
    $script:SshProbesAttempted = 1
    $script:MissedStatusSlots = 0
    $script:MissedPingSlots = 0
    $script:MissedSshSlots = 0
    foreach ($nodeID in $script:Nodes.Keys) {
        $nodeState = Get-OrCreateNodeState -NodeID $nodeID
        $nodeState.SuccessfulStatusSamples = 1
        $nodeState.DirectTriangleSamples = 1
        $nodeState.FirstStartedAt = "2026-07-17T10:00:00Z"
        $nodeState.LastStartedAt = "2026-07-17T10:00:00Z"
        [void]$nodeState.StartedAtValues.Add("2026-07-17T10:00:00Z")
        $nodeState.LastHealth = [pscustomobject]@{ complete_direct_triangle_locally = $true }
    }
    foreach ($key in @("status:A", "status:B", "status:C")) {
        [void](Update-ProbeState -Key $key -Kind "status" -Succeeded $true -TimestampUtc $now)
    }
    foreach ($key in @("ping:A->B", "ping:A->C", "ping:B->A", "ping:B->C", "ping:C->A", "ping:C->B")) {
        [void](Update-ProbeState -Key $key -Kind "ping" -Succeeded $true -TimestampUtc $now)
    }
    [void](Update-ProbeState -Key "ssh:A->B" -Kind "direct_ssh" -Succeeded $true -TimestampUtc $now)

    $cleanSummary = New-FinalSummary -EndedUtc $now.AddSeconds($DurationSeconds) -CompletionReason "duration_completed" -FatalError "" -EventsPath "self-test.jsonl"
    Assert-SelfTest ($cleanSummary.clean_soak -and $cleanSummary.dimensions.topology_continuity.verdict -eq "pass") "clean summary and topology dimension"
    Assert-SelfTest ($cleanSummary.dimensions.management_status.verdict -eq "pass" -and $cleanSummary.dimensions.best_effort_control_ping_zero_loss.verdict -eq "pass" -and $cleanSummary.dimensions.routed_ssh.verdict -eq "pass" -and $cleanSummary.dimensions.schedule.verdict -eq "pass") "clean independent dimensions"

    [void](Update-ProbeState -Key "ping:A->B" -Kind "ping" -Succeeded $false -TimestampUtc $now -ErrorText "synthetic ping loss")
    $lossSummary = New-FinalSummary -EndedUtc $now.AddSeconds($DurationSeconds) -CompletionReason "duration_completed" -FatalError "" -EventsPath "self-test.jsonl"
    Assert-SelfTest (-not $lossSummary.clean_soak -and $lossSummary.dimensions.best_effort_control_ping_zero_loss.verdict -eq "fail") "ping loss fails zero-loss dimension and compatibility verdict"
    Assert-SelfTest ($lossSummary.dimensions.topology_continuity.verdict -eq "pass" -and $lossSummary.dimensions.management_status.verdict -eq "pass" -and $lossSummary.dimensions.routed_ssh.verdict -eq "pass") "ping loss does not contaminate independent dimensions"

    [void](Update-ProbeState -Key "status:B" -Kind "status" -Succeeded $false -TimestampUtc $now -ErrorText "synthetic management failure")
    [void](Update-ProbeState -Key "ssh:A->B" -Kind "direct_ssh" -Succeeded $false -TimestampUtc $now -ErrorText "synthetic SSH failure")
    $script:MissedPingSlots = 1
    $separatedSummary = New-FinalSummary -EndedUtc $now.AddSeconds($DurationSeconds) -CompletionReason "duration_completed" -FatalError "" -EventsPath "self-test.jsonl"
    Assert-SelfTest ($separatedSummary.dimensions.management_status.verdict -eq "fail" -and $separatedSummary.dimensions.routed_ssh.verdict -eq "fail" -and $separatedSummary.dimensions.schedule.verdict -eq "fail") "management, routed SSH, and schedule dimensions fail independently"
    Assert-SelfTest ($separatedSummary.dimensions.topology_continuity.verdict -eq "pass") "management observation gaps do not invent a topology change"

    return [pscustomobject][ordered]@{
        ok = $true
        tests = 41
        policy = $script:Policy
    }
}

if ($SelfTest) {
    Invoke-SelfTest | ConvertTo-Json -Depth 4
    exit 0
}

[void](Get-SshAuthenticationConfiguration -AskPassPath $BAskPassPath -PasswordEnvironmentVariable $BPasswordEnvironmentVariable)
[void](Get-SshAuthenticationConfiguration -AskPassPath $CAskPassPath -PasswordEnvironmentVariable $CPasswordEnvironmentVariable)

$OutputDirectory = Initialize-OutputDirectory -RequestedPath $OutputDirectory
if ($Background) {
    Start-BackgroundMonitor -RunDirectory $OutputDirectory
    exit 0
}

$script:RunID = "three-node-soak-" + ([Guid]::NewGuid().ToString("N"))
$script:RunStartedUtc = [DateTimeOffset]::UtcNow
$script:Nodes = [ordered]@{
    A = [pscustomobject][ordered]@{
        NodeID = "A"
        Access = "local"
        ApiBase = $AApiBase
        Description = "local HTTP $AApiBase"
    }
    B = [pscustomobject][ordered]@{
        NodeID = "B"
        Access = "ssh"
        ApiBase = $RemoteApiBase
        User = $BUser
        HostName = $BHost
        Port = $BPort
        ProxyCommand = $BProxyCommand
        RemoteCurl = $BRemoteCurl
        AskPassPath = $BAskPassPath
        PasswordEnvironmentVariable = $BPasswordEnvironmentVariable
        Description = if ([string]::IsNullOrWhiteSpace($BProxyCommand)) { "SSH ${BUser}@${BHost}:$BPort (ProxyJump=none)" } else { "SSH ${BUser}@${BHost}:$BPort via configured ProxyCommand" }
    }
    C = [pscustomobject][ordered]@{
        NodeID = "C"
        Access = "ssh"
        ApiBase = $RemoteApiBase
        User = $CUser
        HostName = $CHost
        Port = $CPort
        ProxyCommand = $CProxyCommand
        RemoteCurl = $CRemoteCurl
        AskPassPath = $CAskPassPath
        PasswordEnvironmentVariable = $CPasswordEnvironmentVariable
        Description = if ([string]::IsNullOrWhiteSpace($CProxyCommand)) { "SSH ${CUser}@${CHost}:$CPort (ProxyJump=none)" } else { "SSH ${CUser}@${CHost}:$CPort via configured ProxyCommand" }
    }
}

$eventsPath = Join-Path $OutputDirectory "events.jsonl"
$summaryPath = Join-Path $OutputDirectory "summary.json"
$statePath = Join-Path $OutputDirectory "run.state.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:EventWriter = New-Object System.IO.StreamWriter($eventsPath, $false, $utf8NoBom)
$script:EventWriter.AutoFlush = $true

$initialState = [pscustomobject][ordered]@{
    schema_version = 1
    run_id = $script:RunID
    monitor_pid = $PID
    state = "running"
    policy = $script:Policy
    started_at = $script:RunStartedUtc.ToString('o')
    configured_end_at = $script:RunStartedUtc.AddSeconds($DurationSeconds).ToString('o')
    expected_edges = $script:ExpectedEdges
    expected_started_at = $script:ExpectedStartedAt
    output_directory = $OutputDirectory
    events_jsonl = $eventsPath
    summary_json = $summaryPath
}
Write-JsonFile -Path $statePath -Value $initialState

Write-JsonLine ([pscustomobject][ordered]@{
        schema_version = 1
        event = "run_start"
        timestamp = $script:RunStartedUtc.ToString('o')
        run_id = $script:RunID
        monitor_pid = $PID
        policy = $script:Policy
        configured_duration_seconds = $DurationSeconds
        expected_edges = $script:ExpectedEdges
        expected_started_at = $script:ExpectedStartedAt
        intervals = [pscustomobject][ordered]@{
            status_seconds = $SampleIntervalSeconds
            ping_seconds = $PingIntervalSeconds
            ssh_seconds = $SshIntervalSeconds
        }
        access = [pscustomobject][ordered]@{
            A = $script:Nodes.A.Description
            B = $script:Nodes.B.Description
            C = $script:Nodes.C.Description
        }
        permitted_operations = @("GET /v1/status", "POST /v1/ping", "A->B SSH hostname")
        forbidden_actions = @("reconnect", "restart", "repunch", "peer mutation", "neighbor mutation", "shortcut creation", "topology repair")
        a_to_b_listener = Get-ListenerSnapshot -Port $BPort
    })

$completionReason = "duration_completed"
$fatalError = ""
$deadlineUtc = $script:RunStartedUtc.AddSeconds($DurationSeconds)
$nextStatusUtc = $script:RunStartedUtc
$nextPingUtc = $script:RunStartedUtc.AddSeconds([math]::Min(2.0, $PingIntervalSeconds / 2.0))
$nextSshUtc = $script:RunStartedUtc.AddSeconds([math]::Min(7.0, $SshIntervalSeconds / 2.0))

try {
    while ([DateTimeOffset]::UtcNow -lt $deadlineUtc) {
        $now = [DateTimeOffset]::UtcNow
        if ($now -ge $nextStatusUtc) {
            $script:StatusSamplesAttempted++
            $scheduled = $nextStatusUtc
            Invoke-StatusSample -SampleIndex $script:StatusSamplesAttempted -ScheduledUtc $scheduled
            do {
                $nextStatusUtc = $nextStatusUtc.AddSeconds($SampleIntervalSeconds)
                if ($nextStatusUtc -le [DateTimeOffset]::UtcNow) {
                    $script:MissedStatusSlots++
                }
            } while ($nextStatusUtc -le [DateTimeOffset]::UtcNow)
        }

        $now = [DateTimeOffset]::UtcNow
        if ($now -ge $nextPingUtc -and $now -lt $deadlineUtc) {
            $script:PingRoundsAttempted++
            $scheduled = $nextPingUtc
            Invoke-PingRound -RoundIndex $script:PingRoundsAttempted -ScheduledUtc $scheduled
            do {
                $nextPingUtc = $nextPingUtc.AddSeconds($PingIntervalSeconds)
                if ($nextPingUtc -le [DateTimeOffset]::UtcNow) {
                    $script:MissedPingSlots++
                }
            } while ($nextPingUtc -le [DateTimeOffset]::UtcNow)
        }

        $now = [DateTimeOffset]::UtcNow
        if ($now -ge $nextSshUtc -and $now -lt $deadlineUtc) {
            $script:SshProbesAttempted++
            $scheduled = $nextSshUtc
            Invoke-DirectSshProbe -ProbeIndex $script:SshProbesAttempted -ScheduledUtc $scheduled
            do {
                $nextSshUtc = $nextSshUtc.AddSeconds($SshIntervalSeconds)
                if ($nextSshUtc -le [DateTimeOffset]::UtcNow) {
                    $script:MissedSshSlots++
                }
            } while ($nextSshUtc -le [DateTimeOffset]::UtcNow)
        }

        $now = [DateTimeOffset]::UtcNow
        if ($now -lt $deadlineUtc) {
            $nextDueUtc = @($nextStatusUtc, $nextPingUtc, $nextSshUtc, $deadlineUtc) | Sort-Object | Select-Object -First 1
            $sleepMilliseconds = [math]::Floor(($nextDueUtc - $now).TotalMilliseconds)
            if ($sleepMilliseconds -gt 0) {
                Start-Sleep -Milliseconds ([int][math]::Min(1000, $sleepMilliseconds))
            }
        }
    }
} catch {
    $completionReason = "fatal_monitor_error"
    $fatalError = $_.Exception.ToString()
    try {
        Write-JsonLine ([pscustomobject][ordered]@{
                schema_version = 1
                event = "monitor_error"
                timestamp = [DateTimeOffset]::UtcNow.ToString('o')
                error = Limit-Text -Value $fatalError -MaximumLength 4096
                action_taken = "none"
                policy = $script:Policy
            })
    } catch { }
} finally {
    $endedUtc = [DateTimeOffset]::UtcNow
    $summary = New-FinalSummary -EndedUtc $endedUtc -CompletionReason $completionReason -FatalError (Limit-Text -Value $fatalError -MaximumLength 4096) -EventsPath $eventsPath
    try {
        Write-JsonLine ([pscustomobject][ordered]@{
                schema_version = 1
                event = "run_end"
                timestamp = $endedUtc.ToString('o')
                completion_reason = $completionReason
                observed_seconds = $summary.observed_seconds
                verdict = $summary.verdict
                clean_soak = $summary.clean_soak
                action_taken = "none"
                policy = $script:Policy
            })
    } finally {
        if ($null -ne $script:EventWriter) {
            $script:EventWriter.Dispose()
            $script:EventWriter = $null
        }
    }
    Write-JsonFile -Path $summaryPath -Value $summary
    Write-JsonFile -Path $statePath -Value ([pscustomobject][ordered]@{
            schema_version = 1
            run_id = $script:RunID
            monitor_pid = $PID
            state = "completed"
            policy = $script:Policy
            started_at = $script:RunStartedUtc.ToString('o')
            ended_at = $endedUtc.ToString('o')
            completion_reason = $completionReason
            summary_json = $summaryPath
            events_jsonl = $eventsPath
        })
}

Write-Output ([pscustomobject][ordered]@{
        completed = ($completionReason -eq "duration_completed")
        completion_reason = $completionReason
        output_directory = $OutputDirectory
        events_jsonl = $eventsPath
        summary_json = $summaryPath
        verdict = $summary.verdict
    })

if ($completionReason -ne "duration_completed") {
    exit 1
}
