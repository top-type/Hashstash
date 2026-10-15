[CmdletBinding()]
param(
    [string]$DataRoot = (Join-Path $PSScriptRoot 'data'),
    [string]$ManifestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ManifestPath) {
    $latestPath = Join-Path ([IO.Path]::GetFullPath($DataRoot)) 'testnet-latest.json'
    if (-not (Test-Path -LiteralPath $latestPath)) { throw 'There is no saved testnet. Supply -ManifestPath to select one.' }
    $pointer = Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json
    $ManifestPath = [string]$pointer.manifest
}
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or @($manifest.nodes).Count -ne 3) { throw 'Unsupported testnet manifest.' }
$expectedExecutable = [IO.Path]::GetFullPath([string]$manifest.executable)
foreach ($nodeRecord in $manifest.nodes) {
    if ([int]$nodeRecord.pid -le 0) { continue }
    $candidate = Get-Process -Id ([int]$nodeRecord.pid) -ErrorAction SilentlyContinue
    if ($null -eq $candidate) {
        Write-Host "$($nodeRecord.name) is already stopped."
        continue
    }
    try {
        $actualExecutable = [IO.Path]::GetFullPath($candidate.Path)
        $actualStart = $candidate.StartTime.ToUniversalTime().Ticks.ToString()
        $matchesExecutable = [String]::Equals($actualExecutable, $expectedExecutable, [StringComparison]::OrdinalIgnoreCase)
        $matchesRecord = [String]::Equals($actualExecutable, [string]$nodeRecord.executable, [StringComparison]::OrdinalIgnoreCase)
        if (-not $matchesExecutable -or -not $matchesRecord -or $actualStart -ne [string]$nodeRecord.start_time_ticks) {
            Write-Warning "PID $($nodeRecord.pid) no longer matches $($nodeRecord.name)'s recorded executable and start time. It was not stopped."
            continue
        }
        Stop-Process -Id $candidate.Id -ErrorAction Stop
        if (-not $candidate.WaitForExit(10000)) { throw 'The node did not exit within ten seconds.' }
        Write-Host "Stopped $($nodeRecord.name) (PID $($nodeRecord.pid))."
    } catch {
        Write-Warning "Could not verify or stop $($nodeRecord.name): $($_.Exception.Message)"
    }
}
Write-Host ('Wallets, configuration, and chain data remain in ' + $manifest.directory)
