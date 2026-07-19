#Requires -Version 5.1

<#
.SYNOPSIS
Builds a five-dimension, offline analysis of a three-node soak run.

.DESCRIPTION
Reads the observation-only monitor's events.jsonl and, when available, its
summary.json. When the summary is absent, run.state.json supplies only run-end
metadata; it never supplies schedule evidence. The events are never changed.
The optional source summary remains authoritative and is the only source for
the monitor's missed-schedule counters, which cannot be reconstructed reliably
from the legacy event timestamps.

The result separates topology/process continuity, management status,
best-effort control-ping loss, routed SSH, and schedule fidelity. It also emits
per-direction nearest-rank RTT distributions and a compact record for every
failed probe.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File `
  scripts\summarize-three-node-soak.ps1 `
  -RunDirectory .live-run\runs\three-node-soak-r7-20260717-202841

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File `
  scripts\summarize-three-node-soak.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [string]$RunDirectory = "",
    [string]$EventsPath = "",
    [string]$SummaryPath = "",
    [string]$RunStatePath = "",
    [string]$OutputPath = "",
    [switch]$Force,
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Get-PropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [string]$Name,
        [AllowNull()][object]$Default = $null
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

function Test-HasProperty {
    param(
        [AllowNull()][object]$InputObject,
        [string]$Name
    )

    return ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name])
}

function Test-FiniteNonNegativeDouble {
    param(
        [AllowNull()][object]$Value,
        [ref]$ParsedValue
    )

    $ParsedValue.Value = 0.0
    if ($null -eq $Value) {
        return $false
    }
    $number = 0.0
    if (-not [double]::TryParse(
            [string]$Value,
            [System.Globalization.NumberStyles]::Float,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$number)) {
        return $false
    }
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt 0) {
        return $false
    }
    $ParsedValue.Value = $number
    return $true
}

function Test-NonNegativeInteger {
    param(
        [AllowNull()][object]$Value,
        [ref]$ParsedValue
    )

    $ParsedValue.Value = [long]0
    if ($null -eq $Value) {
        return $false
    }
    $number = [long]0
    if (-not [long]::TryParse(
            [string]$Value,
            [System.Globalization.NumberStyles]::Integer,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$number)) {
        return $false
    }
    if ($number -lt 0) {
        return $false
    }
    $ParsedValue.Value = $number
    return $true
}

function Test-EffectiveProbeSuccess {
    param([object]$Event)

    if (-not [bool](Get-PropertyValue $Event "ok" $false)) {
        return $false
    }
    if ([string](Get-PropertyValue $Event "event" "") -ne "ping") {
        return $true
    }
    if (-not (Test-HasProperty $Event "api_rtt_ms")) {
        return $false
    }
    $rtt = 0.0
    return (Test-FiniteNonNegativeDouble -Value (Get-PropertyValue $Event "api_rtt_ms" $null) -ParsedValue ([ref]$rtt))
}

function ConvertTo-IsoTimestamp {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed.ToString('o')
    }
    return [string]$Value
}

function Get-NearestRankValue {
    param(
        [double[]]$SortedValues,
        [ValidateRange(0.000001, 1.0)]
        [double]$Percentile
    )

    if ($null -eq $SortedValues -or $SortedValues.Count -eq 0) {
        return $null
    }
    $index = [math]::Ceiling($Percentile * $SortedValues.Count) - 1
    $index = [math]::Max(0, [math]::Min($SortedValues.Count - 1, $index))
    return [math]::Round($SortedValues[$index], 6)
}

function Get-NearestRankDistribution {
    param([AllowNull()][object]$Values)

    $numbers = New-Object 'System.Collections.Generic.List[double]'
    foreach ($value in @($Values)) {
        $number = 0.0
        if (Test-FiniteNonNegativeDouble -Value $value -ParsedValue ([ref]$number)) {
            $numbers.Add($number)
        }
    }
    $sorted = @($numbers.ToArray() | Sort-Object)
    if ($sorted.Count -eq 0) {
        return [pscustomobject][ordered]@{
            count = 0
            method = "nearest_rank"
        }
    }

    $sum = 0.0
    foreach ($number in $sorted) {
        $sum += $number
    }
    return [pscustomobject][ordered]@{
        count = $sorted.Count
        method = "nearest_rank"
        minimum = [math]::Round($sorted[0], 6)
        p50 = Get-NearestRankValue -SortedValues $sorted -Percentile 0.50
        p95 = Get-NearestRankValue -SortedValues $sorted -Percentile 0.95
        p99 = Get-NearestRankValue -SortedValues $sorted -Percentile 0.99
        maximum = [math]::Round($sorted[$sorted.Count - 1], 6)
        mean = [math]::Round($sum / $sorted.Count, 6)
    }
}

function Get-EventProbeKey {
    param([object]$Event)

    $kind = [string](Get-PropertyValue $Event "event" "")
    switch ($kind) {
        "status" {
            return "status:" + [string](Get-PropertyValue $Event "node_id" "")
        }
        "ping" {
            return "ping:" + [string](Get-PropertyValue $Event "source_id" "") + "->" + [string](Get-PropertyValue $Event "target_id" "")
        }
        "direct_ssh" {
            return "ssh:" + [string](Get-PropertyValue $Event "source_id" "A") + "->" + [string](Get-PropertyValue $Event "target_id" "B")
        }
        default {
            return $kind
        }
    }
}

function Get-SeriesSummary {
    param(
        [string]$Key,
        [object[]]$Events
    )

    $successes = 0
    $failures = 0
    $consecutiveFailures = 0
    $maximumConsecutiveFailures = 0
    $rttValues = New-Object 'System.Collections.Generic.List[double]'
    $observedValues = New-Object 'System.Collections.Generic.List[double]'
    $firstFailure = $null
    $lastFailure = $null
    $lastSuccess = $null
    $lastError = ""

    foreach ($event in @($Events)) {
        $ok = Test-EffectiveProbeSuccess -Event $event
        $observed = Get-PropertyValue $event "observed_ms" $null
        if ($null -ne $observed) {
            $number = 0.0
            if ([double]::TryParse([string]$observed, [ref]$number)) {
                $observedValues.Add($number)
            }
        }
        if ($ok) {
            $successes++
            $consecutiveFailures = 0
            $lastSuccess = ConvertTo-IsoTimestamp (Get-PropertyValue $event "timestamp" $null)
            if ([string](Get-PropertyValue $event "event" "") -eq "ping") {
                $number = 0.0
                if (Test-FiniteNonNegativeDouble -Value (Get-PropertyValue $event "api_rtt_ms" $null) -ParsedValue ([ref]$number)) {
                    $rttValues.Add($number)
                }
            }
        } else {
            $failures++
            $consecutiveFailures++
            if ($consecutiveFailures -gt $maximumConsecutiveFailures) {
                $maximumConsecutiveFailures = $consecutiveFailures
            }
            $failureTimestamp = ConvertTo-IsoTimestamp (Get-PropertyValue $event "timestamp" $null)
            if ($null -eq $firstFailure) {
                $firstFailure = $failureTimestamp
            }
            $lastFailure = $failureTimestamp
            $lastError = [string](Get-PropertyValue $event "error" "")
            if ([string](Get-PropertyValue $event "event" "") -eq "ping" -and
                [bool](Get-PropertyValue $event "ok" $false) -and [string]::IsNullOrWhiteSpace($lastError)) {
                $lastError = "ping reported ok but api_rtt_ms was missing, null, non-finite, or negative"
            }
        }
    }

    return [pscustomobject][ordered]@{
        key = $Key
        attempts = @($Events).Count
        successes = $successes
        failures = $failures
        loss_percent = if (@($Events).Count -eq 0) { $null } else { [math]::Round(100.0 * $failures / @($Events).Count, 6) }
        consecutive_failures_at_end = $consecutiveFailures
        max_consecutive_failures = $maximumConsecutiveFailures
        first_failure_at = $firstFailure
        last_failure_at = $lastFailure
        last_success_at = $lastSuccess
        last_error = $lastError
        api_rtt_ms = Get-NearestRankDistribution -Values $rttValues.ToArray()
        observed_ms = Get-NearestRankDistribution -Values $observedValues.ToArray()
    }
}

function Get-EventsForKey {
    param(
        [object[]]$Events,
        [string]$Key
    )

    return @($Events | Where-Object { (Get-EventProbeKey $_) -eq $Key })
}

function Test-StringSetEqual {
    param(
        [AllowNull()][object]$Left,
        [AllowNull()][object]$Right
    )

    $leftValues = @(@($Left) | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $rightValues = @(@($Right) | ForEach-Object { [string]$_ } | Sort-Object -Unique)
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

function Get-NeighborSignature {
    param([object]$Status)

    return (@(@(Get-PropertyValue $Status "neighbors" @()) | ForEach-Object { [string]$_ } | Sort-Object) -join ',')
}

function Get-RouteSignature {
    param([object]$Status)

    $parts = @()
    foreach ($route in @(Get-PropertyValue $Status "routes" @())) {
        $parts += ([string](Get-PropertyValue $route "destination" "") + "|" +
            [string](Get-PropertyValue $route "next_hop" "") + "|" +
            [string](Get-PropertyValue $route "hop_count" "") + "|" +
            (@(Get-PropertyValue $route "path" @()) -join '>'))
    }
    return (@($parts | Sort-Object) -join ';')
}

function Get-DirectSignature {
    param([object]$Status)

    $parts = @()
    foreach ($shortcut in @(Get-PropertyValue $Status "stable_shortcuts" @())) {
        if ([string](Get-PropertyValue $shortcut "connection_type" "") -ne "direct" -or
            [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $shortcut "direct_peer_id" ""))) {
            continue
        }
        $parts += ([string](Get-PropertyValue $shortcut "attempt_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "initiator_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "target_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "coordinator_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "local_role" "") + "|" +
            [string](Get-PropertyValue $shortcut "direct_peer_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "strategy" "") + "|" +
            [string](Get-PropertyValue $shortcut "remote_addr" "") + "|" +
            [string](Get-PropertyValue $shortcut "path_id" "") + "|" +
            [string](Get-PropertyValue $shortcut "path_role" "") + "|" +
            (@(Get-PropertyValue $shortcut "dependencies" @()) -join ','))
    }
    return (@($parts | Sort-Object) -join ';')
}

function Get-LocalTopologyAssessment {
    param(
        [string]$NodeID,
        [object]$Status,
        [AllowNull()][object]$ExpectedEdges
    )

    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $expectedPeers = @(@("A", "B", "C") | Where-Object { $_ -ne $NodeID })
    $neighbors = @(Get-PropertyValue $Status "neighbors" @())
    $neighborsMatch = Test-StringSetEqual -Left $neighbors -Right $expectedPeers
    if (-not $neighborsMatch) {
        $reasons.Add("neighbor_set")
    }

    $desired = Get-PropertyValue $Status "desired_bootstrap_peers" ([pscustomobject]@{})
    $desiredEmpty = ($null -ne $desired -and @($desired.PSObject.Properties).Count -eq 0)
    if (-not $desiredEmpty) {
        $reasons.Add("desired_bootstrap_peers")
    }

    $routes = @(Get-PropertyValue $Status "routes" @())
    $oneHopRoutes = ($routes.Count -eq 2)
    foreach ($peerID in $expectedPeers) {
        $matching = @($routes | Where-Object { [string](Get-PropertyValue $_ "destination" "") -eq $peerID })
        if ($matching.Count -ne 1) {
            $oneHopRoutes = $false
            continue
        }
        $route = $matching[0]
        $path = @(Get-PropertyValue $route "path" @())
        if ([string](Get-PropertyValue $route "next_hop" "") -ne $peerID -or
            [int](Get-PropertyValue $route "hop_count" 0) -ne 1 -or
            $path.Count -ne 2 -or [string]$path[0] -ne $NodeID -or [string]$path[1] -ne $peerID) {
            $oneHopRoutes = $false
        }
    }
    if (-not $oneHopRoutes) {
        $reasons.Add("one_hop_routes")
    }

    $stableShortcuts = @(Get-PropertyValue $Status "stable_shortcuts" @())
    $participantRecords = @($stableShortcuts | Where-Object {
            [string](Get-PropertyValue $_ "connection_type" "") -eq "direct" -and
            -not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $_ "direct_peer_id" ""))
        })
    $directPeers = @($participantRecords | ForEach-Object { [string](Get-PropertyValue $_ "direct_peer_id" "") })
    $directPeersMatch = ($participantRecords.Count -eq 2 -and
        (Test-StringSetEqual -Left $directPeers -Right $expectedPeers))
    if (-not $directPeersMatch) {
        $reasons.Add("stable_direct_peers")
    }

    $directMetadataValid = $true
    foreach ($record in $participantRecords) {
        if ((Test-HasProperty $record "strategy") -and [string](Get-PropertyValue $record "strategy" "") -ne "birthday_punch") {
            $directMetadataValid = $false
        }
        if ((Test-HasProperty $record "path_id") -and [string](Get-PropertyValue $record "path_id" "") -ne "birthdaypunch/direct") {
            $directMetadataValid = $false
        }
        if ((Test-HasProperty $record "path_role") -and [string](Get-PropertyValue $record "path_role" "") -ne "protected_direct") {
            $directMetadataValid = $false
        }
        if ((Test-HasProperty $record "remote_addr") -and
            [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $record "remote_addr" ""))) {
            $directMetadataValid = $false
        }
        if ((Test-HasProperty $record "dependencies") -and @(Get-PropertyValue $record "dependencies" @()).Count -ne 0) {
            $directMetadataValid = $false
        }
    }

    $configuredEdges = @($ExpectedEdges)
    $edgeManifestConfigured = ($configuredEdges.Count -eq 3)
    $edgeManifestMatches = ($configuredEdges.Count -eq 0 -or $edgeManifestConfigured)
    $manifestChecks = @()
    if ($edgeManifestConfigured) {
        $incidentEdges = @($configuredEdges | Where-Object {
                [string](Get-PropertyValue $_ "initiator_id" "") -eq $NodeID -or
                [string](Get-PropertyValue $_ "target_id" "") -eq $NodeID
            })
        if ($incidentEdges.Count -ne 2 -or $participantRecords.Count -ne $incidentEdges.Count) {
            $edgeManifestMatches = $false
        }
        foreach ($edge in $incidentEdges) {
            $attemptID = [string](Get-PropertyValue $edge "attempt_id" "")
            $initiatorID = [string](Get-PropertyValue $edge "initiator_id" "")
            $targetID = [string](Get-PropertyValue $edge "target_id" "")
            $coordinatorID = [string](Get-PropertyValue $edge "coordinator_id" "")
            $expectedRole = if ($initiatorID -eq $NodeID) { "initiator" } else { "target" }
            $expectedPeer = if ($initiatorID -eq $NodeID) { $targetID } else { $initiatorID }
            $matching = @($participantRecords | Where-Object { [string](Get-PropertyValue $_ "attempt_id" "") -eq $attemptID })
            $valid = ($matching.Count -eq 1)
            if ($valid) {
                $record = $matching[0]
                $valid = (-not [string]::IsNullOrWhiteSpace($attemptID) -and
                    [string](Get-PropertyValue $record "initiator_id" "") -eq $initiatorID -and
                    [string](Get-PropertyValue $record "target_id" "") -eq $targetID -and
                    [string](Get-PropertyValue $record "coordinator_id" "") -eq $coordinatorID -and
                    [string](Get-PropertyValue $record "local_role" "") -eq $expectedRole -and
                    [string](Get-PropertyValue $record "direct_peer_id" "") -eq $expectedPeer -and
                    [string](Get-PropertyValue $record "strategy" "") -eq "birthday_punch" -and
                    [string](Get-PropertyValue $record "connection_type" "") -eq "direct" -and
                    [string](Get-PropertyValue $record "path_id" "") -eq "birthdaypunch/direct" -and
                    [string](Get-PropertyValue $record "path_role" "") -eq "protected_direct" -and
                    -not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $record "remote_addr" "")) -and
                    @(Get-PropertyValue $record "dependencies" @()).Count -eq 0)
            }
            if (-not $valid) {
                $edgeManifestMatches = $false
            }
            $manifestChecks += [pscustomobject][ordered]@{
                attempt_id = $attemptID
                expected_role = $expectedRole
                expected_peer = $expectedPeer
                matching_records = $matching.Count
                valid = $valid
            }
        }
        foreach ($edge in @($configuredEdges | Where-Object { [string](Get-PropertyValue $_ "coordinator_id" "") -eq $NodeID })) {
            $attemptID = [string](Get-PropertyValue $edge "attempt_id" "")
            $matching = @($stableShortcuts | Where-Object { [string](Get-PropertyValue $_ "attempt_id" "") -eq $attemptID })
            $valid = ($matching.Count -eq 0)
            if ($matching.Count -eq 1) {
                $record = $matching[0]
                $valid = ([string](Get-PropertyValue $record "initiator_id" "") -eq [string](Get-PropertyValue $edge "initiator_id" "") -and
                    [string](Get-PropertyValue $record "target_id" "") -eq [string](Get-PropertyValue $edge "target_id" "") -and
                    [string](Get-PropertyValue $record "coordinator_id" "") -eq $NodeID -and
                    [string](Get-PropertyValue $record "local_role" "") -eq "coordinator" -and
                    @(Get-PropertyValue $record "dependencies" @()).Count -eq 0)
            } elseif ($matching.Count -gt 1) {
                $valid = $false
            }
            if (-not $valid) {
                $edgeManifestMatches = $false
            }
            $manifestChecks += [pscustomobject][ordered]@{
                attempt_id = $attemptID
                expected_role = "coordinator_or_absent"
                expected_peer = ""
                matching_records = $matching.Count
                valid = $valid
            }
        }
    }
    if (-not $edgeManifestMatches) {
        $reasons.Add("edge_manifest")
    }
    if (-not $directMetadataValid) {
        $reasons.Add("direct_metadata")
    }

    $infrastructureCoordinatorObserved = Test-HasProperty $Status "infrastructure_coordinator_started"
    $infrastructureCoordinatorStopped = (-not $infrastructureCoordinatorObserved -or
        -not [bool](Get-PropertyValue $Status "infrastructure_coordinator_started" $false))
    if (-not $infrastructureCoordinatorStopped) {
        $reasons.Add("infrastructure_coordinator_started")
    }

    return [pscustomobject][ordered]@{
        complete = ($neighborsMatch -and $desiredEmpty -and $oneHopRoutes -and $directPeersMatch -and
            $directMetadataValid -and $edgeManifestMatches -and $infrastructureCoordinatorStopped)
        edge_manifest_configured = $edgeManifestConfigured
        edge_manifest_matches = $edgeManifestMatches
        edge_manifest_checks = $manifestChecks
        direct_metadata_valid = $directMetadataValid
        infrastructure_coordinator_observed = $infrastructureCoordinatorObserved
        infrastructure_coordinator_stopped = $infrastructureCoordinatorStopped
        failure_reasons = $reasons.ToArray()
    }
}

function Get-TransitionCount {
    param([AllowNull()][object]$Values)

    $count = 0
    $hasPrevious = $false
    $previous = $null
    foreach ($value in @($Values)) {
        if ($hasPrevious -and [string]$value -ne [string]$previous) {
            $count++
        }
        $previous = $value
        $hasPrevious = $true
    }
    return $count
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

function Get-TopologyAnalysis {
    param(
        [object[]]$Events,
        [AllowNull()][object]$ExpectedStartedAt,
        [AllowNull()][object]$ExpectedEdges,
        [string]$CompletionReason
    )

    $statusEvents = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "status" })
    $finalEventsByNode = @{}
    $finalSampleIndex = $null
    $finalStatusSetObserved = $true
    foreach ($nodeID in @("A", "B", "C")) {
        $forNode = @($statusEvents | Where-Object { [string](Get-PropertyValue $_ "node_id" "") -eq $nodeID })
        if ($forNode.Count -eq 0) {
            $finalStatusSetObserved = $false
            continue
        }
        $finalEvent = $forNode[$forNode.Count - 1]
        $parsedSampleIndex = [long]0
        if (-not (Test-NonNegativeInteger -Value (Get-PropertyValue $finalEvent "sample_index" $null) -ParsedValue ([ref]$parsedSampleIndex))) {
            $finalStatusSetObserved = $false
            continue
        }
        if ($null -eq $finalSampleIndex) {
            $finalSampleIndex = $parsedSampleIndex
        } elseif ([long]$finalSampleIndex -ne $parsedSampleIndex) {
            $finalStatusSetObserved = $false
        }
        $finalEventsByNode[$nodeID] = $finalEvent
    }
    if ($finalEventsByNode.Count -ne 3) {
        $finalStatusSetObserved = $false
    }
    $finalSynchronizedSuccessful = $finalStatusSetObserved
    if ($finalStatusSetObserved) {
        foreach ($nodeID in @("A", "B", "C")) {
            if (-not (Test-EffectiveProbeSuccess -Event $finalEventsByNode[$nodeID])) {
                $finalSynchronizedSuccessful = $false
            }
        }
    }

    $nodeAnalyses = @()
    $allNodesObserved = $true
    $criterionMet = $true
    $finalTriangle = $finalSynchronizedSuccessful
    foreach ($nodeID in @("A", "B", "C")) {
        $nodeEvents = @($statusEvents | Where-Object { [string](Get-PropertyValue $_ "node_id" "") -eq $nodeID })
        $successful = @($nodeEvents | Where-Object { Test-EffectiveProbeSuccess -Event $_ })
        if ($successful.Count -eq 0) {
            $allNodesObserved = $false
            $criterionMet = $false
        }

        $startedAtValues = @($successful | ForEach-Object {
                $status = Get-PropertyValue $_ "status" $null
                [string](Get-PropertyValue $status "started_at" "")
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $distinctStartedAt = @($startedAtValues | Sort-Object -Unique)
        $expected = [string](Get-PropertyValue $ExpectedStartedAt $nodeID "")
        $manifestMatches = ([string]::IsNullOrWhiteSpace($expected) -or
            @($startedAtValues | Where-Object { $_ -ne $expected }).Count -eq 0)

        $neighborSignatures = @()
        $routeSignatures = @()
        $directSignatures = @()
        $unhealthySamples = 0
        $lastHealthy = $false
        $lastSuccessfulStatusAt = $null
        $lastAssessment = $null
        foreach ($event in $successful) {
            $status = Get-PropertyValue $event "status" $null
            $neighborSignatures += Get-NeighborSignature $status
            $routeSignatures += Get-RouteSignature $status
            $directSignatures += Get-DirectSignature $status
            $assessment = Get-LocalTopologyAssessment -NodeID $nodeID -Status $status -ExpectedEdges $ExpectedEdges
            $health = Get-PropertyValue $event "topology_health" $null
            if ($null -ne $health -and (Test-HasProperty $health "complete_direct_triangle_locally")) {
                $healthy = ($assessment.complete -and [bool](Get-PropertyValue $health "complete_direct_triangle_locally" $false))
            } else {
                $healthy = $assessment.complete
            }
            if (-not $healthy) {
                $unhealthySamples++
            }
            $lastHealthy = $healthy
            $lastAssessment = $assessment
            $lastSuccessfulStatusAt = ConvertTo-IsoTimestamp (Get-PropertyValue $event "timestamp" $null)
        }

        $finalEvent = if ($finalEventsByNode.ContainsKey($nodeID)) { $finalEventsByNode[$nodeID] } else { $null }
        $finalStatusOk = ($null -ne $finalEvent -and (Test-EffectiveProbeSuccess -Event $finalEvent))
        $finalStatusHealthy = $null
        if ($finalStatusOk) {
            $finalStatus = Get-PropertyValue $finalEvent "status" $null
            $finalAssessment = Get-LocalTopologyAssessment -NodeID $nodeID -Status $finalStatus -ExpectedEdges $ExpectedEdges
            $finalHealth = Get-PropertyValue $finalEvent "topology_health" $null
            if ($null -ne $finalHealth -and (Test-HasProperty $finalHealth "complete_direct_triangle_locally")) {
                $finalStatusHealthy = ($finalAssessment.complete -and [bool](Get-PropertyValue $finalHealth "complete_direct_triangle_locally" $false))
            } else {
                $finalStatusHealthy = $finalAssessment.complete
            }
            $finalStartedAt = [string](Get-PropertyValue $finalStatus "started_at" "")
            if (-not [string]::IsNullOrWhiteSpace($expected) -and $finalStartedAt -ne $expected) {
                $finalStatusHealthy = $false
            }
        }
        if (-not $finalStatusOk -or -not [bool]$finalStatusHealthy) {
            $finalTriangle = $false
        }

        $restartTransitions = Get-TransitionCount $startedAtValues
        $neighborTransitions = Get-TransitionCount $neighborSignatures
        $routeTransitions = Get-TransitionCount $routeSignatures
        $directTransitions = Get-TransitionCount $directSignatures
        $nodeCriterion = ($successful.Count -gt 0 -and $distinctStartedAt.Count -eq 1 -and $manifestMatches -and
            $unhealthySamples -eq 0 -and $neighborTransitions -eq 0 -and $routeTransitions -eq 0 -and
            $directTransitions -eq 0)
        if (-not $nodeCriterion) {
            $criterionMet = $false
        }

        $nodeAnalyses += [pscustomobject][ordered]@{
            node_id = $nodeID
            status_attempts = $nodeEvents.Count
            successful_status_samples = $successful.Count
            failed_status_samples = $nodeEvents.Count - $successful.Count
            unhealthy_topology_samples = $unhealthySamples
            last_successful_status_at = $lastSuccessfulStatusAt
            last_successful_status_complete_direct_triangle = if ($successful.Count -eq 0) { $null } else { $lastHealthy }
            final_status_timestamp = if ($null -eq $finalEvent) { $null } else { ConvertTo-IsoTimestamp (Get-PropertyValue $finalEvent "timestamp" $null) }
            final_status_sample_index = if ($null -eq $finalEvent) { $null } else { Get-PropertyValue $finalEvent "sample_index" $null }
            final_status_ok = if ($null -eq $finalEvent) { $null } else { $finalStatusOk }
            final_status_complete_direct_triangle = $finalStatusHealthy
            expected_started_at = $expected
            distinct_started_at = $distinctStartedAt
            started_at_manifest_matches = $manifestMatches
            last_edge_manifest_configured = if ($null -eq $lastAssessment) { $false } else { $lastAssessment.edge_manifest_configured }
            last_edge_manifest_matches = if ($null -eq $lastAssessment) { $null } else { $lastAssessment.edge_manifest_matches }
            last_edge_manifest_checks = if ($null -eq $lastAssessment) { @() } else { $lastAssessment.edge_manifest_checks }
            last_direct_metadata_valid = if ($null -eq $lastAssessment) { $null } else { $lastAssessment.direct_metadata_valid }
            last_infrastructure_coordinator_observed = if ($null -eq $lastAssessment) { $false } else { $lastAssessment.infrastructure_coordinator_observed }
            last_infrastructure_coordinator_stopped = if ($null -eq $lastAssessment) { $null } else { $lastAssessment.infrastructure_coordinator_stopped }
            restart_transitions = $restartTransitions
            neighbor_transitions = $neighborTransitions
            route_transitions = $routeTransitions
            stable_direct_transitions = $directTransitions
            first_neighbor_signature = if ($neighborSignatures.Count -eq 0) { $null } else { $neighborSignatures[0] }
            last_neighbor_signature = if ($neighborSignatures.Count -eq 0) { $null } else { $neighborSignatures[$neighborSignatures.Count - 1] }
            first_route_signature = if ($routeSignatures.Count -eq 0) { $null } else { $routeSignatures[0] }
            last_route_signature = if ($routeSignatures.Count -eq 0) { $null } else { $routeSignatures[$routeSignatures.Count - 1] }
            first_stable_direct_signature = if ($directSignatures.Count -eq 0) { $null } else { $directSignatures[0] }
            last_stable_direct_signature = if ($directSignatures.Count -eq 0) { $null } else { $directSignatures[$directSignatures.Count - 1] }
            criterion_met = $nodeCriterion
        }
    }

    $loggedChanges = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "continuity_change" })
    if ($loggedChanges.Count -gt 0) {
        $criterionMet = $false
    }
    $finalStatusEvidenceComplete = ($finalStatusSetObserved -and $finalSynchronizedSuccessful)
    if (-not $allNodesObserved) {
        $verdict = "not_observed"
    } elseif (-not $criterionMet) {
        $verdict = "fail"
    } elseif (-not $finalStatusEvidenceComplete) {
        $verdict = if ($CompletionReason -eq "duration_completed") { "not_observed" } else { "incomplete" }
    } else {
        $verdict = Get-DimensionVerdict -Observed $true -CriterionMet $finalTriangle -CompletionReason $CompletionReason
    }
    return [pscustomobject][ordered]@{
        verdict = $verdict
        criterion_met = ($criterionMet -and $finalStatusEvidenceComplete -and $finalTriangle)
        observation_scope = "Topology/process continuity is evaluated from successful status documents, and a pass additionally requires one final synchronized successful status sample for A, B, and C. Failed management samples remain observation gaps."
        all_nodes_observed = $allNodesObserved
        final_synchronized_status_set_observed = $finalStatusSetObserved
        final_synchronized_status_sample_index = $finalSampleIndex
        final_synchronized_status_successful = $finalSynchronizedSuccessful
        final_sampled_complete_direct_triangle = $finalTriangle
        logged_continuity_change_events = $loggedChanges.Count
        nodes = $nodeAnalyses
    }
}

function Get-ProbeDimension {
    param(
        [object[]]$Events,
        [string[]]$ExpectedKeys,
        [string]$CompletionReason
    )

    $series = @()
    $attempts = 0
    $successes = 0
    $failures = 0
    $missing = @()
    foreach ($key in $ExpectedKeys) {
        $keyEvents = Get-EventsForKey -Events $Events -Key $key
        $summary = Get-SeriesSummary -Key $key -Events $keyEvents
        $series += $summary
        $attempts += $summary.attempts
        $successes += $summary.successes
        $failures += $summary.failures
        if ($summary.attempts -eq 0) {
            $missing += $key
        }
    }
    $observed = ($missing.Count -eq 0)
    $criterionMet = ($observed -and $failures -eq 0)
    return [pscustomobject][ordered]@{
        verdict = Get-DimensionVerdict -Observed $observed -CriterionMet $criterionMet -CompletionReason $CompletionReason
        criterion_met = $criterionMet
        expected_probe_series = $ExpectedKeys.Count
        observed_probe_series = $ExpectedKeys.Count - $missing.Count
        missing_probe_series = $missing
        attempts = $attempts
        successes = $successes
        failures = $failures
        probe_series_with_failures = @($series | Where-Object { $_.failures -gt 0 }).Count
        series = $series
    }
}

function Get-ScheduleAnalysis {
    param(
        [AllowNull()][object]$SourceSummary,
        [string]$CompletionReason,
        [object[]]$Events
    )

    $sourceSchedule = Get-PropertyValue $SourceSummary "schedule" $null
    $hasStatus = Test-HasProperty $sourceSchedule "missed_status_slots"
    $hasPing = Test-HasProperty $sourceSchedule "missed_ping_slots"
    $hasSsh = Test-HasProperty $sourceSchedule "missed_ssh_slots"
    $parsedStatus = [long]0
    $parsedPing = [long]0
    $parsedSsh = [long]0
    $validStatus = ($hasStatus -and (Test-NonNegativeInteger -Value (Get-PropertyValue $sourceSchedule "missed_status_slots" $null) -ParsedValue ([ref]$parsedStatus)))
    $validPing = ($hasPing -and (Test-NonNegativeInteger -Value (Get-PropertyValue $sourceSchedule "missed_ping_slots" $null) -ParsedValue ([ref]$parsedPing)))
    $validSsh = ($hasSsh -and (Test-NonNegativeInteger -Value (Get-PropertyValue $sourceSchedule "missed_ssh_slots" $null) -ParsedValue ([ref]$parsedSsh)))
    $missedStatus = if ($validStatus) { $parsedStatus } else { $null }
    $missedPing = if ($validPing) { $parsedPing } else { $null }
    $missedSsh = if ($validSsh) { $parsedSsh } else { $null }
    $hasAnyDetailedCounter = ($hasStatus -or $hasPing -or $hasSsh)
    $observed = ($validStatus -and $validPing -and $validSsh)
    $invalidFields = @()
    if ($hasStatus -and -not $validStatus) { $invalidFields += "missed_status_slots" }
    if ($hasPing -and -not $validPing) { $invalidFields += "missed_ping_slots" }
    if ($hasSsh -and -not $validSsh) { $invalidFields += "missed_ssh_slots" }
    if ($observed) {
        $missedTotal = $missedStatus + $missedPing + $missedSsh
    } elseif (-not $hasAnyDetailedCounter -and (Test-HasProperty $SourceSummary "missed_schedule_slots")) {
        $parsedTotal = [long]0
        if (Test-NonNegativeInteger -Value (Get-PropertyValue $SourceSummary "missed_schedule_slots" $null) -ParsedValue ([ref]$parsedTotal)) {
            $missedTotal = $parsedTotal
            $observed = $true
        } else {
            $missedTotal = $null
            $invalidFields += "missed_schedule_slots"
        }
    } else {
        $missedTotal = $null
    }
    $criterionMet = ($observed -and $missedTotal -eq 0)

    return [pscustomobject][ordered]@{
        verdict = Get-DimensionVerdict -Observed $observed -CriterionMet $criterionMet -CompletionReason $CompletionReason
        criterion_met = $criterionMet
        source = if ($observed) { "source_summary" } elseif ($invalidFields.Count -gt 0) { "invalid_source_summary" } else { "unavailable" }
        limitation = "Missed slots are read from the monitor summary; legacy event timestamps are not sufficient to reconstruct them exactly."
        invalid_counter_fields = $invalidFields
        missed_slots = $missedTotal
        missed_status_slots = $missedStatus
        missed_ping_slots = $missedPing
        missed_ssh_slots = $missedSsh
        observed_event_counts = [pscustomobject][ordered]@{
            status = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "status" }).Count
            ping = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "ping" }).Count
            direct_ssh = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "direct_ssh" }).Count
        }
        source_attempt_counts = [pscustomobject][ordered]@{
            status_samples = Get-PropertyValue $sourceSchedule "status_samples_attempted" $null
            ping_rounds = Get-PropertyValue $sourceSchedule "ping_rounds_attempted" $null
            ssh_probes = Get-PropertyValue $sourceSchedule "ssh_probes_attempted" $null
        }
    }
}

function Test-PingEventHasExactTimestamps {
    param([object]$Event)

    if (-not (Test-HasProperty $Event "started_at") -or -not (Test-HasProperty $Event "completed_at")) {
        return $false
    }
    $startedText = [string](Get-PropertyValue $Event "started_at" "")
    $completedText = [string](Get-PropertyValue $Event "completed_at" "")
    if ([string]::IsNullOrWhiteSpace($startedText) -or [string]::IsNullOrWhiteSpace($completedText)) {
        return $false
    }
    $started = [DateTimeOffset]::MinValue
    $completed = [DateTimeOffset]::MinValue
    return ([DateTimeOffset]::TryParse($startedText, [ref]$started) -and
        [DateTimeOffset]::TryParse($completedText, [ref]$completed) -and $completed -ge $started)
}

function Get-PingTimestampAnalysis {
    param([object[]]$Events)

    $pingEvents = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "ping" })
    $exactCount = @($pingEvents | Where-Object { Test-PingEventHasExactTimestamps -Event $_ }).Count
    $legacyCount = $pingEvents.Count - $exactCount
    if ($pingEvents.Count -eq 0) {
        $schema = "not_observed"
    } elseif ($legacyCount -eq $pingEvents.Count) {
        $schema = "legacy_event_timestamp_only"
    } elseif ($legacyCount -gt 0) {
        $schema = "mixed"
    } else {
        $schema = "per_probe_start_and_completion"
    }
    return [pscustomobject][ordered]@{
        schema = $schema
        ping_events = $pingEvents.Count
        legacy_ping_events = $legacyCount
        exact_timestamp_ping_events = $exactCount
        exact_per_direction_timestamps_available = ($pingEvents.Count -gt 0 -and $legacyCount -eq 0)
        limitation = if ($legacyCount -gt 0) {
            "Legacy ping events carry only an event timestamp. Per-direction observed_ms and valid RTT values remain usable, but exact probe start/completion, exact failure time, probe concurrency, and recovery duration cannot be inferred for those events."
        } else {
            "None for events that carry started_at and completed_at."
        }
    }
}

function Get-FailureAnalysis {
    param(
        [object[]]$Events,
        [object]$PingTimestampAnalysis
    )

    $probeEvents = @($Events | Where-Object {
            [string](Get-PropertyValue $_ "event" "") -in @("status", "ping", "direct_ssh")
        })
    $failedEvents = @($probeEvents | Where-Object { -not (Test-EffectiveProbeSuccess -Event $_) })
    $records = @()
    for ($failureIndex = 0; $failureIndex -lt $failedEvents.Count; $failureIndex++) {
        $failure = $failedEvents[$failureIndex]
        $key = Get-EventProbeKey $failure
        $sourceIndex = [array]::IndexOf($Events, $failure)
        $attemptsUntilSuccess = 0
        $nextSuccess = $null
        if ($sourceIndex -ge 0) {
            for ($index = $sourceIndex + 1; $index -lt $Events.Count; $index++) {
                $candidate = $Events[$index]
                if ((Get-EventProbeKey $candidate) -ne $key) {
                    continue
                }
                $attemptsUntilSuccess++
                if (Test-EffectiveProbeSuccess -Event $candidate) {
                    $nextSuccess = $candidate
                    break
                }
            }
        }
        $eventKind = [string](Get-PropertyValue $failure "event" "")
        $eventHasExactPingTimestamps = ($eventKind -eq "ping" -and (Test-PingEventHasExactTimestamps -Event $failure))
        $timestampPrecision = if ($eventKind -eq "ping" -and -not $eventHasExactPingTimestamps) {
            "legacy_event_timestamp_only"
        } elseif ($eventKind -eq "ping") {
            "per_probe_start_and_completion"
        } else {
            "event_completion_timestamp"
        }
        $reportedOk = [bool](Get-PropertyValue $failure "ok" $false)
        $effectiveError = [string](Get-PropertyValue $failure "error" "")
        if ($eventKind -eq "ping" -and $reportedOk -and [string]::IsNullOrWhiteSpace($effectiveError)) {
            $effectiveError = "ping reported ok but api_rtt_ms was missing, null, non-finite, or negative"
        }
        $records += [pscustomobject][ordered]@{
            event = $eventKind
            probe_key = $key
            timestamp = ConvertTo-IsoTimestamp (Get-PropertyValue $failure "timestamp" $null)
            timestamp_precision = $timestampPrecision
            started_at = if ($eventHasExactPingTimestamps) { ConvertTo-IsoTimestamp (Get-PropertyValue $failure "started_at" $null) } else { $null }
            completed_at = if ($eventHasExactPingTimestamps) { ConvertTo-IsoTimestamp (Get-PropertyValue $failure "completed_at" $null) } else { $null }
            sample_index = Get-PropertyValue $failure "sample_index" $null
            round_index = Get-PropertyValue $failure "round_index" $null
            probe_index = Get-PropertyValue $failure "probe_index" $null
            observed_ms = Get-PropertyValue $failure "observed_ms" $null
            exit_code = Get-PropertyValue $failure "exit_code" $null
            reported_ok = $reportedOk
            error = $effectiveError
            consecutive_failures = Get-PropertyValue $failure "consecutive_failures" $null
            later_probe_success_observed = ($null -ne $nextSuccess)
            attempts_until_success = if ($null -eq $nextSuccess) { $null } else { $attemptsUntilSuccess }
            next_success_timestamp = if ($null -eq $nextSuccess) { $null } else { ConvertTo-IsoTimestamp (Get-PropertyValue $nextSuccess "timestamp" $null) }
        }
    }

    $byEvent = @()
    foreach ($kind in @("status", "ping", "direct_ssh")) {
        $count = @($records | Where-Object { $_.event -eq $kind }).Count
        $byEvent += [pscustomobject][ordered]@{ event = $kind; failures = $count }
    }
    $bySeries = @()
    foreach ($key in @($records | ForEach-Object { $_.probe_key } | Sort-Object -Unique)) {
        $bySeries += [pscustomobject][ordered]@{
            probe_key = $key
            failures = @($records | Where-Object { $_.probe_key -eq $key }).Count
        }
    }
    $monitorErrors = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "monitor_error" })
    $continuityChanges = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "continuity_change" })
    return [pscustomobject][ordered]@{
        failed_probe_events = $records.Count
        monitor_error_events = $monitorErrors.Count
        continuity_change_events = $continuityChanges.Count
        by_event = $byEvent
        by_probe_series = $bySeries
        events = $records
    }
}

function Get-RunMetadata {
    param(
        [object[]]$Events,
        [AllowNull()][object]$SourceSummary,
        [AllowNull()][object]$SourceRunState
    )

    $runStart = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "run_start" } | Select-Object -First 1)
    $runEnd = @($Events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "run_end" } | Select-Object -Last 1)
    $start = if ($runStart.Count -eq 0) { $null } else { $runStart[0] }
    $end = if ($runEnd.Count -eq 0) { $null } else { $runEnd[0] }

    $eventRunID = [string](Get-PropertyValue $start "run_id" "")
    $stateRunID = [string](Get-PropertyValue $SourceRunState "run_id" "")
    $summaryRunID = [string](Get-PropertyValue $SourceSummary "run_id" "")
    $runID = if (-not [string]::IsNullOrWhiteSpace($summaryRunID)) {
        $summaryRunID
    } elseif (-not [string]::IsNullOrWhiteSpace($stateRunID)) {
        $stateRunID
    } else {
        $eventRunID
    }

    $summaryCompletion = [string](Get-PropertyValue $SourceSummary "completion_reason" "")
    $stateName = [string](Get-PropertyValue $SourceRunState "state" "")
    $interruptionReason = [string](Get-PropertyValue $SourceRunState "interruption_reason" "")
    $eventCompletion = [string](Get-PropertyValue $end "completion_reason" "")
    if (-not [string]::IsNullOrWhiteSpace($summaryCompletion)) {
        $completionReason = $summaryCompletion
        $completionMetadataSource = "summary"
    } elseif (-not [string]::IsNullOrWhiteSpace($interruptionReason)) {
        $completionReason = $interruptionReason
        $completionMetadataSource = "run_state"
    } elseif (-not [string]::IsNullOrWhiteSpace($stateName) -and $stateName -ne "running") {
        $completionReason = $stateName
        $completionMetadataSource = "run_state"
    } elseif (-not [string]::IsNullOrWhiteSpace($eventCompletion)) {
        $completionReason = $eventCompletion
        $completionMetadataSource = "events"
    } else {
        $completionReason = "in_progress_or_unknown"
        $completionMetadataSource = "events"
    }

    $startedAt = if ($null -ne $SourceSummary -and (Test-HasProperty $SourceSummary "started_at") -and
        $null -ne (Get-PropertyValue $SourceSummary "started_at" $null)) {
        Get-PropertyValue $SourceSummary "started_at" $null
    } elseif ($null -ne $SourceRunState -and (Test-HasProperty $SourceRunState "started_at")) {
        Get-PropertyValue $SourceRunState "started_at" $null
    } else {
        Get-PropertyValue $start "timestamp" $null
    }
    $endedAt = if ($null -ne $SourceSummary -and (Test-HasProperty $SourceSummary "ended_at") -and
        $null -ne (Get-PropertyValue $SourceSummary "ended_at" $null)) {
        Get-PropertyValue $SourceSummary "ended_at" $null
    } elseif ($null -ne $SourceRunState -and (Test-HasProperty $SourceRunState "ended_at")) {
        Get-PropertyValue $SourceRunState "ended_at" $null
    } else {
        Get-PropertyValue $end "timestamp" $null
    }
    $expectedStartedAt = if ($null -ne $SourceSummary -and (Test-HasProperty $SourceSummary "expected_started_at") -and
        $null -ne (Get-PropertyValue $SourceSummary "expected_started_at" $null)) {
        Get-PropertyValue $SourceSummary "expected_started_at" $null
    } elseif ($null -ne $SourceRunState -and (Test-HasProperty $SourceRunState "expected_started_at") -and
        $null -ne (Get-PropertyValue $SourceRunState "expected_started_at" $null)) {
        Get-PropertyValue $SourceRunState "expected_started_at" $null
    } else {
        Get-PropertyValue $start "expected_started_at" ([pscustomobject]@{})
    }
    $expectedEdges = if ($null -ne $SourceSummary -and (Test-HasProperty $SourceSummary "expected_edges") -and
        $null -ne (Get-PropertyValue $SourceSummary "expected_edges" $null)) {
        Get-PropertyValue $SourceSummary "expected_edges" @()
    } elseif ($null -ne $SourceRunState -and (Test-HasProperty $SourceRunState "expected_edges") -and
        $null -ne (Get-PropertyValue $SourceRunState "expected_edges" $null)) {
        Get-PropertyValue $SourceRunState "expected_edges" @()
    } else {
        Get-PropertyValue $start "expected_edges" @()
    }
    $policy = [string](Get-PropertyValue $SourceSummary "policy" "")
    if ([string]::IsNullOrWhiteSpace($policy)) {
        $policy = [string](Get-PropertyValue $SourceRunState "policy" (Get-PropertyValue $start "policy" ""))
    }
    $configuredDuration = Get-PropertyValue $SourceSummary "configured_duration_seconds" $null
    if ($null -eq $configuredDuration) {
        $configuredDuration = Get-PropertyValue $SourceRunState "configured_duration_seconds" (Get-PropertyValue $start "configured_duration_seconds" $null)
    }

    $observedSeconds = Get-PropertyValue $SourceSummary "observed_seconds" $null
    if ($null -eq $observedSeconds) {
        $parsedStart = [DateTimeOffset]::MinValue
        $parsedEnd = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse([string]$startedAt, [ref]$parsedStart) -and
            [DateTimeOffset]::TryParse([string]$endedAt, [ref]$parsedEnd) -and $parsedEnd -ge $parsedStart) {
            $observedSeconds = [math]::Round(($parsedEnd - $parsedStart).TotalSeconds, 3)
        }
    }
    return [pscustomobject][ordered]@{
        run_id = $runID
        completion_reason = $completionReason
        completion_metadata_source = $completionMetadataSource
        run_state = $stateName
        interruption_reason = $interruptionReason
        started_at = ConvertTo-IsoTimestamp $startedAt
        ended_at = ConvertTo-IsoTimestamp $endedAt
        observed_seconds = $observedSeconds
        configured_duration_seconds = $configuredDuration
        policy = $policy
        expected_edges = $expectedEdges
        expected_started_at = $expectedStartedAt
    }
}

function New-SoakAnalysis {
    param(
        [object[]]$Events,
        [AllowNull()][object]$SourceSummary,
        [AllowNull()][object]$SourceRunState,
        [string]$EventsArtifact = "events.jsonl",
        [string]$SummaryArtifact = "",
        [string]$RunStateArtifact = ""
    )

    $metadata = Get-RunMetadata -Events $Events -SourceSummary $SourceSummary -SourceRunState $SourceRunState
    $completionReason = $metadata.completion_reason
    $topology = Get-TopologyAnalysis -Events $Events -ExpectedStartedAt $metadata.expected_started_at -ExpectedEdges $metadata.expected_edges -CompletionReason $completionReason
    $management = Get-ProbeDimension -Events $Events -ExpectedKeys @("status:A", "status:B", "status:C") -CompletionReason $completionReason
    $ping = Get-ProbeDimension -Events $Events -ExpectedKeys @("ping:A->B", "ping:A->C", "ping:B->A", "ping:B->C", "ping:C->A", "ping:C->B") -CompletionReason $completionReason
    $ssh = Get-ProbeDimension -Events $Events -ExpectedKeys @("ssh:A->B") -CompletionReason $completionReason
    $schedule = Get-ScheduleAnalysis -SourceSummary $SourceSummary -CompletionReason $completionReason -Events $Events
    $timestampAnalysis = Get-PingTimestampAnalysis -Events $Events
    $failures = Get-FailureAnalysis -Events $Events -PingTimestampAnalysis $timestampAnalysis
    $dimensions = [pscustomobject][ordered]@{
        topology_and_process_continuity = $topology
        management_status = $management
        best_effort_control_ping_zero_loss = $ping
        routed_ssh = $ssh
        schedule = $schedule
    }

    $dimensionValues = @($dimensions.PSObject.Properties | ForEach-Object { $_.Value })
    $allPass = ($dimensionValues.Count -eq 5 -and @($dimensionValues | Where-Object { $_.verdict -ne "pass" }).Count -eq 0)
    $hasFailure = @($dimensionValues | Where-Object { $_.verdict -eq "fail" }).Count -gt 0
    if ($allPass) {
        $verdict = "pass"
    } elseif (@($dimensionValues | Where-Object { $_.verdict -eq "not_observed" }).Count -gt 0) {
        $verdict = "insufficient_evidence"
    } elseif ($completionReason -ne "duration_completed" -and -not $hasFailure) {
        $verdict = "incomplete"
    } else {
        $verdict = "observed_failures_or_changes"
    }

    $sourceHasDimensions = Test-HasProperty $SourceSummary "dimensions"
    return [pscustomobject][ordered]@{
        schema_version = 1
        analysis_kind = "three_node_soak_offline_five_dimension"
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        run_id = $metadata.run_id
        completion_reason = $completionReason
        completion_metadata_source = $metadata.completion_metadata_source
        run_state = $metadata.run_state
        interruption_reason = $metadata.interruption_reason
        started_at = $metadata.started_at
        ended_at = $metadata.ended_at
        observed_seconds = $metadata.observed_seconds
        configured_duration_seconds = $metadata.configured_duration_seconds
        policy = $metadata.policy
        expected_edges = $metadata.expected_edges
        expected_started_at = $metadata.expected_started_at
        verdict = $verdict
        clean_soak = $allPass
        dimensions = $dimensions
        ping_timestamp_semantics = $timestampAnalysis
        failure_summary = $failures
        source_summary = [pscustomobject][ordered]@{
            supplied = ($null -ne $SourceSummary)
            schema = if ($null -eq $SourceSummary) { "none" } elseif ($sourceHasDimensions) { "five_dimension" } else { "legacy" }
            original_verdict = Get-PropertyValue $SourceSummary "verdict" $null
            original_clean_soak = Get-PropertyValue $SourceSummary "clean_soak" $null
        }
        source_run_state = [pscustomobject][ordered]@{
            supplied = ($null -ne $SourceRunState)
            used_for_completion_metadata = ($metadata.completion_metadata_source -eq "run_state")
            state = $metadata.run_state
            interruption_reason = $metadata.interruption_reason
        }
        artifacts = [pscustomobject][ordered]@{
            events_jsonl = $EventsArtifact
            source_summary_json = $SummaryArtifact
            run_state_json = $RunStateArtifact
        }
    }
}

function Test-LooksLikeIncompleteJsonTail {
    param([string]$Text)

    $trimmed = $Text.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or ($trimmed[0] -ne '{' -and $trimmed[0] -ne '[')) {
        return $false
    }
    $stack = New-Object 'System.Collections.Generic.Stack[char]'
    $inString = $false
    $escaped = $false
    foreach ($character in $trimmed.ToCharArray()) {
        if ($inString) {
            if ($escaped) {
                $escaped = $false
            } elseif ($character -eq '\') {
                $escaped = $true
            } elseif ($character -eq '"') {
                $inString = $false
            }
            continue
        }
        if ($character -eq '"') {
            $inString = $true
            continue
        }
        if ($character -eq '{' -or $character -eq '[') {
            $stack.Push($character)
            continue
        }
        if ($character -eq '}' -or $character -eq ']') {
            if ($stack.Count -eq 0) {
                return $false
            }
            $opening = $stack.Pop()
            if (($character -eq '}' -and $opening -ne '{') -or ($character -eq ']' -and $opening -ne '[')) {
                return $false
            }
        }
    }
    return ($inString -or $stack.Count -gt 0)
}

function Read-JsonLines {
    param([string]$Path)

    $events = New-Object 'System.Collections.Generic.List[object]'
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        $share)
    try {
        $snapshotLength = $stream.Length
        if ($snapshotLength -gt [int]::MaxValue) {
            throw "event log is too large for a single consistent snapshot: $Path"
        }
        $bytes = New-Object byte[] ([int]$snapshotLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                break
            }
            $offset += $read
        }
    } finally {
        $stream.Dispose()
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false, $false)
    $content = $utf8.GetString($bytes, 0, $offset)
    $hasTerminatingNewline = ($content.EndsWith("`n") -or $content.EndsWith("`r"))
    $lines = [System.Text.RegularExpressions.Regex]::Split($content, "`r`n|`n|`r")
    for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
        $line = $lines[$lineIndex]
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            $events.Add(($line | ConvertFrom-Json))
        } catch {
            $isUnterminatedTail = (-not $hasTerminatingNewline -and $lineIndex -eq $lines.Count - 1)
            if ($isUnterminatedTail -and (Test-LooksLikeIncompleteJsonTail -Text $line)) {
                break
            }
            $lineNumber = $lineIndex + 1
            throw "invalid JSON in ${Path} at line ${lineNumber}: $($_.Exception.Message)"
        }
    }
    if ($events.Count -eq 0) {
        throw "event log is empty: $Path"
    }
    return $events.ToArray()
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 24
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $encoding)
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
    $events = New-Object 'System.Collections.Generic.List[object]'
    $expectedStartedAt = [pscustomobject][ordered]@{ A = "A-start"; B = "B-start"; C = "C-start" }
    $expectedEdges = @(
        [pscustomobject][ordered]@{ edge = "A-B"; attempt_id = "attempt-ab"; initiator_id = "A"; target_id = "B"; coordinator_id = "C" },
        [pscustomobject][ordered]@{ edge = "B-C"; attempt_id = "attempt-bc"; initiator_id = "B"; target_id = "C"; coordinator_id = "A" },
        [pscustomobject][ordered]@{ edge = "A-C"; attempt_id = "attempt-ac"; initiator_id = "C"; target_id = "A"; coordinator_id = "B" }
    )
    $events.Add([pscustomobject]@{
            event = "run_start"; timestamp = "2026-07-17T00:00:00Z"; run_id = "self-test"
            configured_duration_seconds = 60; expected_started_at = $expectedStartedAt; expected_edges = $expectedEdges
        })
    $statuses = @{}
    foreach ($nodeID in @("A", "B", "C")) {
        $peers = @(@("A", "B", "C") | Where-Object { $_ -ne $nodeID })
        $routes = @($peers | ForEach-Object {
                [pscustomobject]@{ destination = $_; next_hop = $_; hop_count = 1; path = @($nodeID, $_) }
            })
        $shortcuts = @()
        foreach ($edge in $expectedEdges) {
            if ($edge.initiator_id -eq $nodeID -or $edge.target_id -eq $nodeID) {
                $localRole = if ($edge.initiator_id -eq $nodeID) { "initiator" } else { "target" }
                $directPeer = if ($edge.initiator_id -eq $nodeID) { $edge.target_id } else { $edge.initiator_id }
                $shortcuts += [pscustomobject][ordered]@{
                    attempt_id = $edge.attempt_id; initiator_id = $edge.initiator_id; target_id = $edge.target_id
                    coordinator_id = $edge.coordinator_id; strategy = "birthday_punch"; local_role = $localRole
                    direct_peer_id = $directPeer; connection_type = "direct"; remote_addr = "192.0.2.1:1"
                    path_id = "birthdaypunch/direct"; path_role = "protected_direct"; dependencies = @()
                }
            } elseif ($edge.coordinator_id -eq $nodeID) {
                $shortcuts += [pscustomobject][ordered]@{
                    attempt_id = $edge.attempt_id; initiator_id = $edge.initiator_id; target_id = $edge.target_id
                    coordinator_id = $edge.coordinator_id; strategy = "birthday_punch"; local_role = "coordinator"
                    direct_peer_id = ""; connection_type = ""; remote_addr = ""; path_id = ""; path_role = ""; dependencies = @()
                }
            }
        }
        $statuses[$nodeID] = [pscustomobject]@{
            started_at = "${nodeID}-start"; neighbors = $peers; desired_bootstrap_peers = [pscustomobject]@{}
            routes = $routes; stable_shortcuts = $shortcuts; infrastructure_coordinator_started = $false
        }
        $events.Add([pscustomobject]@{
                event = "status"; timestamp = "2026-07-17T00:00:01Z"; node_id = $nodeID; sample_index = 1
                ok = $true; observed_ms = 1; status = $statuses[$nodeID]
                topology_health = [pscustomobject]@{ complete_direct_triangle_locally = $true }
            })
    }
    foreach ($nodeID in @("A", "B", "C")) {
        if ($nodeID -eq "B") {
            $events.Add([pscustomobject]@{
                    event = "status"; timestamp = "2026-07-17T00:00:02Z"; node_id = $nodeID; sample_index = 2
                    ok = $false; observed_ms = 9; error = "synthetic management failure"
                })
        } else {
            $events.Add([pscustomobject]@{
                    event = "status"; timestamp = "2026-07-17T00:00:02Z"; node_id = $nodeID; sample_index = 2
                    ok = $true; observed_ms = 1; status = $statuses[$nodeID]
                    topology_health = [pscustomobject]@{ complete_direct_triangle_locally = $true }
                })
        }
    }
    foreach ($nodeID in @("A", "B", "C")) {
        $events.Add([pscustomobject]@{
                event = "status"; timestamp = "2026-07-17T00:00:02.500Z"; node_id = $nodeID; sample_index = 3
                ok = $true; observed_ms = 1; status = $statuses[$nodeID]
                topology_health = [pscustomobject]@{ complete_direct_triangle_locally = $true }
            })
    }

    foreach ($direction in @(@("A", "B"), @("A", "C"), @("B", "A"), @("B", "C"), @("C", "A"), @("C", "B"))) {
        $events.Add([pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:03Z"; source_id = $direction[0]; target_id = $direction[1]; ok = $true; api_rtt_ms = 20; observed_ms = 25; round_index = 1 })
    }
    $events.Add([pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:04Z"; source_id = "A"; target_id = "B"; ok = $false; api_rtt_ms = $null; observed_ms = 4000; round_index = 2; error = "synthetic ping loss" })
    $events.Add([pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:05Z"; source_id = "A"; target_id = "B"; ok = $true; api_rtt_ms = 30; observed_ms = 35; round_index = 3 })
    $events.Add([pscustomobject]@{ event = "direct_ssh"; timestamp = "2026-07-17T00:00:06Z"; source_id = "A"; target_id = "B"; ok = $true; observed_ms = 100 })
    $events.Add([pscustomobject]@{ event = "run_end"; timestamp = "2026-07-17T00:01:00Z"; completion_reason = "duration_completed" })

    $summary = [pscustomobject]@{
        run_id = "self-test"; completion_reason = "duration_completed"; started_at = "2026-07-17T00:00:00Z"; ended_at = "2026-07-17T00:01:00Z"
        configured_duration_seconds = 60; expected_started_at = $expectedStartedAt; expected_edges = $expectedEdges
        verdict = "observed_failures_or_changes"; clean_soak = $false
        schedule = [pscustomobject]@{ missed_status_slots = 0; missed_ping_slots = 1; missed_ssh_slots = 0; status_samples_attempted = 1; ping_rounds_attempted = 3; ssh_probes_attempted = 1 }
    }
    $runState = [pscustomobject]@{
        run_id = "self-test"; state = "interrupted"; interruption_reason = "synthetic_interruption"
        started_at = "2026-07-17T00:00:00Z"; ended_at = "2026-07-17T00:00:30Z"
        expected_started_at = $expectedStartedAt; expected_edges = $expectedEdges
    }
    $analysis = New-SoakAnalysis -Events $events.ToArray() -SourceSummary $summary -SourceRunState $runState `
        -SummaryArtifact "summary.json" -RunStateArtifact "run.state.json"
    Assert-SelfTest ($analysis.completion_reason -eq "duration_completed" -and
        $analysis.completion_metadata_source -eq "summary" -and -not $analysis.source_run_state.used_for_completion_metadata) "summary completion metadata has priority over run state"
    Assert-SelfTest ($analysis.dimensions.topology_and_process_continuity.verdict -eq "pass" -and
        $analysis.dimensions.topology_and_process_continuity.final_synchronized_status_successful) "topology requires and accepts a later synchronized successful status sample"
    Assert-SelfTest (@($analysis.dimensions.topology_and_process_continuity.nodes | Where-Object {
                -not $_.last_edge_manifest_configured -or -not $_.last_edge_manifest_matches -or
                -not $_.last_direct_metadata_valid -or -not $_.last_infrastructure_coordinator_stopped
            }).Count -eq 0) "expected edge roles, metadata, dependencies, and infrastructure state"
    Assert-SelfTest ($analysis.dimensions.management_status.verdict -eq "fail" -and $analysis.dimensions.management_status.failures -eq 1) "management failure dimension"
    Assert-SelfTest ($analysis.dimensions.best_effort_control_ping_zero_loss.verdict -eq "fail") "ping loss dimension"
    $ab = @($analysis.dimensions.best_effort_control_ping_zero_loss.series | Where-Object { $_.key -eq "ping:A->B" })[0]
    Assert-SelfTest ($ab.attempts -eq 3 -and $ab.successes -eq 2 -and $ab.failures -eq 1) "per-direction counts"
    Assert-SelfTest ($ab.api_rtt_ms.count -eq 2 -and $ab.api_rtt_ms.p50 -eq 20 -and $ab.api_rtt_ms.p95 -eq 30 -and $ab.api_rtt_ms.p99 -eq 30) "null-filtered nearest-rank RTT"
    Assert-SelfTest ($analysis.dimensions.routed_ssh.verdict -eq "pass") "routed SSH dimension"
    Assert-SelfTest ($analysis.dimensions.schedule.verdict -eq "fail" -and $analysis.dimensions.schedule.missed_slots -eq 1) "schedule counters from source summary"
    Assert-SelfTest ($analysis.failure_summary.failed_probe_events -eq 2 -and $analysis.failure_summary.events[1].later_probe_success_observed -and
        -not (Test-HasProperty $analysis.failure_summary.events[1] "recovered_by_later_success")) "failure summary reports later observation without claiming recovery"
    Assert-SelfTest ($analysis.ping_timestamp_semantics.schema -eq "legacy_event_timestamp_only" -and -not $analysis.ping_timestamp_semantics.exact_per_direction_timestamps_available) "legacy timestamp limitation"
    Assert-SelfTest (-not $analysis.clean_soak -and $analysis.verdict -eq "observed_failures_or_changes") "overall compatibility verdict"

    $stateFallbackAnalysis = New-SoakAnalysis -Events $events.ToArray() -SourceSummary $null -SourceRunState $runState `
        -RunStateArtifact "run.state.json"
    Assert-SelfTest ($stateFallbackAnalysis.completion_reason -eq "synthetic_interruption" -and
        $stateFallbackAnalysis.completion_metadata_source -eq "run_state" -and
        $stateFallbackAnalysis.run_state -eq "interrupted" -and $stateFallbackAnalysis.interruption_reason -eq "synthetic_interruption") "interrupted run state supplies completion reason without becoming duration_completed"
    Assert-SelfTest ($stateFallbackAnalysis.started_at -eq "2026-07-17T00:00:00.0000000+00:00" -and
        $stateFallbackAnalysis.ended_at -eq "2026-07-17T00:00:30.0000000+00:00" -and
        $stateFallbackAnalysis.observed_seconds -eq 30) "run state supplies end metadata and observed seconds"
    Assert-SelfTest ($stateFallbackAnalysis.dimensions.schedule.verdict -eq "not_observed" -and
        $stateFallbackAnalysis.verdict -eq "insufficient_evidence" -and
        $stateFallbackAnalysis.source_run_state.supplied -and $stateFallbackAnalysis.source_run_state.used_for_completion_metadata -and
        $stateFallbackAnalysis.artifacts.run_state_json -eq "run.state.json") "run state is surfaced but never substitutes for schedule evidence"

    $distribution = Get-NearestRankDistribution -Values (1..100)
    Assert-SelfTest ($distribution.p50 -eq 50 -and $distribution.p95 -eq 95 -and $distribution.p99 -eq 99) "nearest-rank percentile definition"

    $invalidRttSeries = Get-SeriesSummary -Key "ping:A->B" -Events @(
        [pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:10Z"; source_id = "A"; target_id = "B"; ok = $true },
        [pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:11Z"; source_id = "A"; target_id = "B"; ok = $true; api_rtt_ms = $null },
        [pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:12Z"; source_id = "A"; target_id = "B"; ok = $true; api_rtt_ms = [double]::PositiveInfinity },
        [pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:13Z"; source_id = "A"; target_id = "B"; ok = $true; api_rtt_ms = -1 }
    )
    Assert-SelfTest ($invalidRttSeries.successes -eq 0 -and $invalidRttSeries.failures -eq 4 -and $invalidRttSeries.api_rtt_ms.count -eq 0) "missing, null, non-finite, and negative ping RTT are failures"

    $invalidSchedule = Get-ScheduleAnalysis -SourceSummary ([pscustomobject]@{
            schedule = [pscustomobject]@{ missed_status_slots = -1; missed_ping_slots = $null; missed_ssh_slots = 0 }
        }) -CompletionReason "duration_completed" -Events @()
    Assert-SelfTest ($invalidSchedule.verdict -eq "not_observed" -and $invalidSchedule.source -eq "invalid_source_summary" -and
        $null -eq $invalidSchedule.missed_slots -and $invalidSchedule.invalid_counter_fields.Count -eq 2) "schedule counters must be nonnegative integers"

    $mixedTimestampEvents = @(
        [pscustomobject]@{ event = "ping"; timestamp = "2026-07-17T00:00:20Z"; source_id = "A"; target_id = "B"; ok = $false; error = "legacy" },
        [pscustomobject]@{
            event = "ping"; timestamp = "2026-07-17T00:00:21Z"; started_at = "2026-07-17T00:00:20.900Z"
            completed_at = "2026-07-17T00:00:21Z"; source_id = "B"; target_id = "A"; ok = $false; error = "exact"
        }
    )
    $mixedTimestampAnalysis = Get-PingTimestampAnalysis -Events $mixedTimestampEvents
    $mixedFailures = Get-FailureAnalysis -Events $mixedTimestampEvents -PingTimestampAnalysis $mixedTimestampAnalysis
    Assert-SelfTest ($mixedTimestampAnalysis.schema -eq "mixed" -and
        $mixedFailures.events[0].timestamp_precision -eq "legacy_event_timestamp_only" -and
        $mixedFailures.events[1].timestamp_precision -eq "per_probe_start_and_completion") "mixed timestamp precision is classified per event"

    $endpointGapEvents = @($events.ToArray()) + @([pscustomobject]@{
            event = "status"; timestamp = "2026-07-17T00:01:01Z"; node_id = "B"; sample_index = 4
            ok = $false; observed_ms = 9; error = "final endpoint gap"
        })
    $endpointGapTopology = Get-TopologyAnalysis -Events $endpointGapEvents -ExpectedStartedAt $expectedStartedAt -ExpectedEdges $expectedEdges -CompletionReason "duration_completed"
    Assert-SelfTest ($endpointGapTopology.verdict -eq "not_observed" -and
        -not $endpointGapTopology.final_synchronized_status_set_observed -and
        -not $endpointGapTopology.final_synchronized_status_successful) "a stale last success cannot satisfy final synchronized topology evidence"

    $brokenStatus = [pscustomobject]@{
        started_at = "A-start"
        neighbors = @("B")
        desired_bootstrap_peers = [pscustomobject]@{}
        routes = @([pscustomobject]@{ destination = "B"; next_hop = "B"; hop_count = 1; path = @("A", "B") })
        stable_shortcuts = @([pscustomobject]@{ attempt_id = "A-B"; direct_peer_id = "B"; connection_type = "direct"; remote_addr = "192.0.2.1:1"; path_id = "birthdaypunch/direct"; path_role = "protected_direct" })
    }
    $brokenEvents = @($events.ToArray())
    foreach ($nodeID in @("A", "B", "C")) {
        $status = if ($nodeID -eq "A") { $brokenStatus } else { $statuses[$nodeID] }
        $brokenEvents += [pscustomobject]@{
            event = "status"; timestamp = "2026-07-17T00:00:59Z"; node_id = $nodeID; sample_index = 4
            ok = $true; observed_ms = 1; status = $status
            topology_health = [pscustomobject]@{ complete_direct_triangle_locally = ($nodeID -ne "A") }
        }
    }
    $brokenTopology = Get-TopologyAnalysis -Events $brokenEvents -ExpectedStartedAt $expectedStartedAt -ExpectedEdges $expectedEdges -CompletionReason "duration_completed"
    Assert-SelfTest ($brokenTopology.verdict -eq "fail" -and -not $brokenTopology.final_sampled_complete_direct_triangle -and
        @($brokenTopology.nodes | Where-Object { $_.node_id -eq "A" -and -not $_.last_successful_status_complete_direct_triangle }).Count -eq 1) "final broken triangle is explicit"

    $badManifestStatus = $statuses.A | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    $badManifestStatus.stable_shortcuts[0].attempt_id = "wrong-attempt"
    $badManifest = Get-LocalTopologyAssessment -NodeID "A" -Status $badManifestStatus -ExpectedEdges $expectedEdges
    Assert-SelfTest (-not $badManifest.complete -and -not $badManifest.edge_manifest_matches) "attempt manifest mismatch cannot pass legacy topology analysis"

    $badMetadataStatus = $statuses.A | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    $badMetadataStatus.stable_shortcuts[0].dependencies = @("bootstrap")
    $badMetadataStatus.infrastructure_coordinator_started = $true
    $badMetadata = Get-LocalTopologyAssessment -NodeID "A" -Status $badMetadataStatus -ExpectedEdges $expectedEdges
    Assert-SelfTest (-not $badMetadata.complete -and -not $badMetadata.direct_metadata_valid -and
        -not $badMetadata.infrastructure_coordinator_stopped) "dependencies and infrastructure coordinator state are validated"

    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("winkyou-soak-selftest-" + [guid]::NewGuid().ToString("N") + ".jsonl")
    $writerStream = $null
    $writer = $null
    try {
        $writerStream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $writer = New-Object System.IO.StreamWriter($writerStream, (New-Object System.Text.UTF8Encoding($false)))
        $writer.AutoFlush = $true
        $writer.WriteLine('{"event":"run_start"}')
        $writer.Write('{"event":"partial"')
        $writer.Flush()
        $activeRead = @(Read-JsonLines -Path $tempPath)
        Assert-SelfTest ($activeRead.Count -eq 1 -and $activeRead[0].event -eq "run_start") "active writer can be read and only an unterminated tail is ignored"
        $writer.WriteLine("")
        $writer.Flush()
        $terminatedInvalidRejected = $false
        try {
            [void](Read-JsonLines -Path $tempPath)
        } catch {
            $terminatedInvalidRejected = $true
        }
        Assert-SelfTest $terminatedInvalidRejected "terminated invalid JSON is rejected"
    } finally {
        if ($null -ne $writer) { $writer.Dispose() }
        if ($null -ne $writerStream) { $writerStream.Dispose() }
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
    }

    $malformedTailPath = Join-Path ([System.IO.Path]::GetTempPath()) ("winkyou-soak-selftest-malformed-" + [guid]::NewGuid().ToString("N") + ".jsonl")
    try {
        [System.IO.File]::WriteAllText($malformedTailPath, '{"event": }', (New-Object System.Text.UTF8Encoding($false)))
        $malformedTailRejected = $false
        try {
            [void](Read-JsonLines -Path $malformedTailPath)
        } catch {
            $malformedTailRejected = $true
        }
        Assert-SelfTest $malformedTailRejected "unterminated malformed JSON is not mistaken for an incomplete writer tail"
    } finally {
        if (Test-Path -LiteralPath $malformedTailPath) { Remove-Item -LiteralPath $malformedTailPath -Force }
    }

    return [pscustomobject][ordered]@{
        ok = $true
        tests = 26
        analysis_kind = $analysis.analysis_kind
    }
}

if ($SelfTest) {
    Invoke-SelfTest | ConvertTo-Json -Depth 4
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RunDirectory) -and [string]::IsNullOrWhiteSpace($EventsPath)) {
    throw "provide -RunDirectory or -EventsPath"
}
if (-not [string]::IsNullOrWhiteSpace($RunDirectory)) {
    $RunDirectory = [System.IO.Path]::GetFullPath($RunDirectory)
    if (-not (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        throw "run directory not found: $RunDirectory"
    }
    if ([string]::IsNullOrWhiteSpace($EventsPath)) {
        $EventsPath = Join-Path $RunDirectory "events.jsonl"
    }
    if ([string]::IsNullOrWhiteSpace($SummaryPath)) {
        $candidateSummary = Join-Path $RunDirectory "summary.json"
        if (Test-Path -LiteralPath $candidateSummary -PathType Leaf) {
            $SummaryPath = $candidateSummary
        }
    }
    if ([string]::IsNullOrWhiteSpace($RunStatePath)) {
        $candidateRunState = Join-Path $RunDirectory "run.state.json"
        if (Test-Path -LiteralPath $candidateRunState -PathType Leaf) {
            $RunStatePath = $candidateRunState
        }
    }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $RunDirectory "analysis.json"
    }
}

$EventsPath = [System.IO.Path]::GetFullPath($EventsPath)
if (-not (Test-Path -LiteralPath $EventsPath -PathType Leaf)) {
    throw "events file not found: $EventsPath"
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Split-Path -Parent $EventsPath) "analysis.json"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "refusing to overwrite existing analysis (use -Force): $OutputPath"
}

$sourceSummary = $null
if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
    $SummaryPath = [System.IO.Path]::GetFullPath($SummaryPath)
    if (-not (Test-Path -LiteralPath $SummaryPath -PathType Leaf)) {
        throw "summary file not found: $SummaryPath"
    }
    $sourceSummary = Get-Content -Raw -LiteralPath $SummaryPath | ConvertFrom-Json
}
$sourceRunState = $null
if (-not [string]::IsNullOrWhiteSpace($RunStatePath)) {
    $RunStatePath = [System.IO.Path]::GetFullPath($RunStatePath)
    if (-not (Test-Path -LiteralPath $RunStatePath -PathType Leaf)) {
        throw "run state file not found: $RunStatePath"
    }
    $sourceRunState = Get-Content -Raw -LiteralPath $RunStatePath | ConvertFrom-Json
}
$events = Read-JsonLines -Path $EventsPath
$analysis = New-SoakAnalysis -Events $events -SourceSummary $sourceSummary -SourceRunState $sourceRunState `
    -EventsArtifact $EventsPath -SummaryArtifact $SummaryPath -RunStateArtifact $RunStatePath

$eventRunStart = @($events | Where-Object { [string](Get-PropertyValue $_ "event" "") -eq "run_start" } | Select-Object -First 1)
if ($null -ne $sourceSummary -and $eventRunStart.Count -gt 0) {
    $eventRunID = [string](Get-PropertyValue $eventRunStart[0] "run_id" "")
    $summaryRunID = [string](Get-PropertyValue $sourceSummary "run_id" "")
    if (-not [string]::IsNullOrWhiteSpace($eventRunID) -and -not [string]::IsNullOrWhiteSpace($summaryRunID) -and $eventRunID -ne $summaryRunID) {
        throw "events and summary run_id mismatch: $eventRunID != $summaryRunID"
    }
}
if ($null -ne $sourceRunState -and $eventRunStart.Count -gt 0) {
    $eventRunID = [string](Get-PropertyValue $eventRunStart[0] "run_id" "")
    $stateRunID = [string](Get-PropertyValue $sourceRunState "run_id" "")
    if (-not [string]::IsNullOrWhiteSpace($eventRunID) -and -not [string]::IsNullOrWhiteSpace($stateRunID) -and $eventRunID -ne $stateRunID) {
        throw "events and run state run_id mismatch: $eventRunID != $stateRunID"
    }
}
if ($null -ne $sourceSummary -and $null -ne $sourceRunState) {
    $summaryRunID = [string](Get-PropertyValue $sourceSummary "run_id" "")
    $stateRunID = [string](Get-PropertyValue $sourceRunState "run_id" "")
    if (-not [string]::IsNullOrWhiteSpace($summaryRunID) -and -not [string]::IsNullOrWhiteSpace($stateRunID) -and $summaryRunID -ne $stateRunID) {
        throw "summary and run state run_id mismatch: $summaryRunID != $stateRunID"
    }
}

$outputParent = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    [void][System.IO.Directory]::CreateDirectory($outputParent)
}
Write-JsonFile -Path $OutputPath -Value $analysis

[pscustomobject][ordered]@{
    written = $true
    analysis_json = $OutputPath
    run_id = $analysis.run_id
    completion_reason = $analysis.completion_reason
    verdict = $analysis.verdict
    clean_soak = $analysis.clean_soak
    failed_probe_events = $analysis.failure_summary.failed_probe_events
} | ConvertTo-Json -Depth 4
