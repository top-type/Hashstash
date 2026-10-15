[CmdletBinding()]
param([string]$RecordPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $RecordPath) {
    $latestPath = Join-Path $PSScriptRoot 'data/watch-latest.json'
    if (-not (Test-Path -LiteralPath $latestPath)) { throw 'No saved watch node. Supply -RecordPath.' }
    $RecordPath = [string](Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json).record
}
$record = Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
if ($record.schema_version -ne 1) { throw 'Unsupported watch-node record.' }
$candidate = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
if ($null -eq $candidate) { Write-Host 'Watch node is already stopped.'; return }
if (-not [String]::Equals([IO.Path]::GetFullPath($candidate.Path), [string]$record.executable, [StringComparison]::OrdinalIgnoreCase) -or
    $candidate.StartTime.ToUniversalTime().Ticks.ToString() -ne [string]$record.start_time_ticks) {
    throw 'The recorded process identity no longer matches. No process was stopped.'
}
Stop-Process -InputObject $candidate
if (-not $candidate.WaitForExit(10000)) { throw 'Watch node did not exit within ten seconds.' }
Write-Host ('Watch node stopped. Data remains in ' + $record.directory)
