[CmdletBinding()]
param(
    [string]$GoCommand = "go"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

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
        "-timeout=90s",
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
