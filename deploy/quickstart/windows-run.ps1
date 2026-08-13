param(
    [Parameter(Mandatory = $true)]
    [string]$HostAddress,
    [Parameter(Mandatory = $true)]
    [string]$CoordinatorCAFile,
    [Parameter(Mandatory = $true)]
    [string]$CoordinatorAuthKey,
    [string]$ConfigOut = "$env:TEMP\\wink-windows-client.yaml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$template = Join-Path $repoRoot "deploy\\quickstart\\windows-client.yaml"
$binary = Join-Path $repoRoot "bin\\wink.exe"

$content = Get-Content $template -Raw
$content = $content.Replace("<HOST>", $HostAddress)
$content = $content.Replace("<COORDINATOR_CA_FILE>", $CoordinatorCAFile)
$content = $content.Replace("<COORDINATOR_AUTH_KEY>", $CoordinatorAuthKey)
[System.IO.File]::WriteAllText($ConfigOut, $content, [System.Text.UTF8Encoding]::new($false))

Write-Host "Using config: $ConfigOut"
& $binary --config $ConfigOut up
