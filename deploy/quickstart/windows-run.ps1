param(
    [Parameter(Mandatory = $true)]
    [string]$HostAddress,
    [string]$ConfigOut = "$env:TEMP\\wink-windows-client.yaml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$template = Join-Path $repoRoot "deploy\\quickstart\\windows-client.yaml"
$binary = Join-Path $repoRoot "bin\\wink.exe"

$content = (Get-Content $template -Raw).Replace("<HOST>", $HostAddress)
[System.IO.File]::WriteAllText($ConfigOut, $content, [System.Text.UTF8Encoding]::new($false))

Write-Host "Using config: $ConfigOut"
& $binary --config $ConfigOut up
