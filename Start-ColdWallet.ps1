[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 19580,
    [string]$Executable,
    [string]$Config,
    [string]$ChainId,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Executable) {
    $Executable = Join-Path $PSScriptRoot 'target/release/hashstash-cold.exe'
    if (-not (Test-Path -LiteralPath $Executable)) { $Executable = Join-Path $PSScriptRoot 'bin/hashstash-cold.exe' }
}
$signerPath = [IO.Path]::GetFullPath($Executable)
if (-not (Test-Path -LiteralPath $signerPath -PathType Leaf)) { throw 'Cold signer executable was not found.' }
if ($Config -and $ChainId) { throw 'Use either -Config or -ChainId.' }
if (-not $Config -and -not $ChainId) {
    $latestPath = Join-Path $PSScriptRoot 'data/testnet-latest.json'
    if (Test-Path -LiteralPath $latestPath) {
        $manifestPath = [string](Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json).manifest
        if (Test-Path -LiteralPath $manifestPath) {
            $candidateConfig = [string](Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).config
            if (Test-Path -LiteralPath $candidateConfig) { $Config = $candidateConfig }
        }
    }
}
$signerArguments = @('--port', $Port.ToString())
if ($Config) { $signerArguments += @('--config', (Resolve-Path -LiteralPath $Config).Path) }
if ($ChainId) {
    if ($ChainId -notmatch '^[0-9a-fA-F]{64}$') { throw 'Chain ID must contain 64 hexadecimal characters.' }
    $signerArguments += @('--chain-id', $ChainId)
}
$quotedArguments = @($signerArguments | ForEach-Object {
    if ($_.Contains('"')) { throw 'Signer argument contains an unsupported quote character.' }
    '"' + $_ + '"'
}) -join ' '
$signerListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
try {
    $signerListener.Server.ExclusiveAddressUse = $true
    $signerListener.Start()
} finally { $signerListener.Stop() }
$signerProcess = Start-Process -FilePath $signerPath -ArgumentList $quotedArguments -WindowStyle Hidden -PassThru
$signerUrl = "http://127.0.0.1:$Port/"
$signerReady = $false
$signerDeadline = [DateTime]::UtcNow.AddSeconds(15)
while ([DateTime]::UtcNow -lt $signerDeadline) {
    if ($signerProcess.HasExited) { throw 'Cold signer exited during startup.' }
    try {
        $signerSession = Invoke-RestMethod -Uri ($signerUrl + 'api/session') -TimeoutSec 1
        if ($signerSession.format -eq 'hashstash-cold-v1') { $signerReady = $true; break }
    } catch { }
    Start-Sleep -Milliseconds 100
}
if (-not $signerReady) { throw "Signer did not become ready. Process ID: $($signerProcess.Id)" }
Write-Host "Cold signer: $signerUrl"
Write-Host "Process ID: $($signerProcess.Id). Lock the wallet when finished; stop this process to close the signer."
if (-not $NoBrowser) { Start-Process $signerUrl }
