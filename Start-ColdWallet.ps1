[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 19580,
    [string]$Executable,
    [string]$Config,
    [string]$ChainId,
    [switch]$NoBrowser,
    # Registry key, under HKEY_CURRENT_USER, listing the programs Windows Error
    # Reporting leaves alone. Tests name another key.
    [string]$CrashReportKey = 'Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows Error Reporting can save a crash dump of a failing signer, holding
# any key it has loaded. Exclude the signer's file name for this account, as
# WerAddExcludedApplication would: a DWORD value of 1 named after the file.
# Other values under the key are left as they are.
function Register-CrashReportExclusion([string]$Name, [string]$SubKey) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($SubKey)
    try {
        if ($key.GetValueNames() -contains $Name -and $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$key.GetValue($Name) -eq 1) { return 'found' }
        $key.SetValue($Name, 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        return 'added'
    } finally { $key.Dispose() }
}
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
$signerName = [IO.Path]::GetFileName($signerPath)
try {
    $crashReports = Register-CrashReportExclusion $signerName $CrashReportKey
    Write-Host "Crash reports: Windows Error Reporting excludes $signerName for this account (DWORD $signerName = 1 under HKCU\$CrashReportKey, $crashReports)."
} catch {
    Write-Warning "Windows Error Reporting could not exclude $signerName ($($_.Exception.Message)); a crash dump of the signer may hold its key."
}
# Loopback is shared by every local account, so the signer never serves its
# session token. Choose it here and pass it through this process's environment,
# which other accounts cannot read, then only in the launch URL's fragment.
$tokenBytes = [byte[]]::new(32)
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
$signerToken = -join ($tokenBytes | ForEach-Object { $_.ToString('x2') })
$env:HASHSTASH_COLD_TOKEN = $signerToken
try {
    $signerProcess = Start-Process -FilePath $signerPath -ArgumentList $quotedArguments -WindowStyle Hidden -PassThru
} finally { Remove-Item Env:\HASHSTASH_COLD_TOKEN -ErrorAction SilentlyContinue }
$signerUrl = "http://127.0.0.1:$Port/"
$launchUrl = $signerUrl + '#token=' + $signerToken
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
Write-Host "Cold signer: $launchUrl"
Write-Host "Open that full address; the page needs its #token part. Process ID: $($signerProcess.Id). An open wallet locks after 5 minutes without use; lock it when finished and stop this process to close the signer."
if (-not $NoBrowser) { Start-Process $launchUrl }
