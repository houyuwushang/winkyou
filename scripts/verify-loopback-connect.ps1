[CmdletBinding()]
param(
    [string]$GoCommand = "go"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# Harness-only budget: per-group maxima from the two first runs in issue #165.
# ceil(92990ms * 1.25 / 10000ms) * 10s = 120s; no product deadline changes.
# See docs/FLAKE-165-LOOPBACK-PROOF-BUDGET.md for samples and limitations.
$loopbackPreFinishMeasuredMs = 26700
$loopbackSlowFinishMeasuredMs = 42200
$loopbackTwoProcessesMeasuredMs = 8860
$loopbackCrashAfterNoiseMeasuredMs = 890
$loopbackCrashBeforePromoteMeasuredMs = 1300
$loopbackAbsenceMeasuredMs = 13040
$loopbackObservedTotalMs = $loopbackPreFinishMeasuredMs + $loopbackSlowFinishMeasuredMs + $loopbackTwoProcessesMeasuredMs + $loopbackCrashAfterNoiseMeasuredMs + $loopbackCrashBeforePromoteMeasuredMs + $loopbackAbsenceMeasuredMs
$loopbackProofTimeoutSeconds = [int]([Math]::Ceiling($loopbackObservedTotalMs * 1.25 / 10000) * 10)

function Invoke-ProofStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host "==> $Name"
    & $GoCommand @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repositoryRoot
try {
    & $GoCommand version
    if ($LASTEXITCODE -ne 0) {
        throw "Go toolchain is unavailable"
    }

    Invoke-ProofStep -Name "stdio framing, method, and loopback handler contracts" -Arguments @(
        "test",
        "./internal/stdiojsonrpc",
        "./internal/solverstdio",
        "./internal/v2/loopbackcarrier",
        "-count=1",
        "-timeout=60s"
    )

    Invoke-ProofStep -Name "real loopback UDP, subprocess, crash, and peer-absence witnesses" -Arguments @(
        "test",
        "./internal/governor",
        "-run",
        "^TestLoopbackCarrier",
        "-count=1",
        "-timeout=${loopbackProofTimeoutSeconds}s",
        "-v"
    )

    Invoke-ProofStep -Name "network capability and exact-consumer architecture gates" -Arguments @(
        "test",
        "./internal/architecture",
        "-run",
        "^(TestProductionNetworkCapabilityInventory|TestPairingAdmissionGateHasOnlyReviewedCarrierConsumer|TestLoopbackCarrierApprovalIsExactAndBidirectional)$",
        "-count=1"
    )

    Write-Host "LOOPBACK_CONNECT_PROOF: PASS"
}
finally {
    Pop-Location
}
