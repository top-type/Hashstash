[CmdletBinding()]
param([Parameter(Mandatory)][string]$ManifestPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.format -ne 'hashstash-rental-test-v1' -or @($manifest.nodes).Count -ne 2) { throw 'Unsupported rental test manifest.' }
function Save-RecordedJson([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 32) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temporary, $Path, [NullString]::Value)
}
function Stop-RecordedProcess($Record, [string]$ExpectedExecutable, [string]$Name) {
    if ([int]$Record.pid -le 0) { return 'already_stopped' }
    $candidate = Get-Process -Id ([int]$Record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { return 'already_stopped' }
    $actual = [IO.Path]::GetFullPath($candidate.Path)
    if (-not [String]::Equals($actual, $ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase) -or
        -not [String]::Equals($actual, [IO.Path]::GetFullPath([string]$Record.executable), [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartTime.ToUniversalTime().Ticks.ToString() -ne [string]$Record.start_time_ticks) {
        throw "PID $($Record.pid) does not match its recorded executable and start time; it was not stopped."
    }
    Stop-Process -Id $candidate.Id
    if (-not $candidate.WaitForExit(10000)) { throw "$Name did not stop within ten seconds." }
    Write-Host "Stopped $Name (PID $($Record.pid))."
    return 'stopped'
}

# A relay is owned only by this manifest's adjacent record and exact process
# identity. Stop it before stopping the two nodes it exposes.
$relayPath = Join-Path (Split-Path -Parent $ManifestPath) 'relay.json'
if (Test-Path -LiteralPath $relayPath -PathType Leaf) {
    $relay = Get-Content -LiteralPath $relayPath -Raw | ConvertFrom-Json
    $destination = "127.0.0.1:$($manifest.nodes[0].stratum_port)"
    if ([string]$relay.destination -ne $destination) { throw 'Relay destination does not match this rental network; no process was stopped.' }
    $result = Stop-RecordedProcess $relay ([IO.Path]::GetFullPath([string]$relay.executable)) 'relay'
    $relay | Add-Member -NotePropertyName state -NotePropertyValue 'stopped' -Force
    $relay | Add-Member -NotePropertyName stopped_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $relay | Add-Member -NotePropertyName stop_result -NotePropertyValue $result -Force
    Save-RecordedJson $relayPath $relay
}
$expected = [IO.Path]::GetFullPath([string]$manifest.executable)
foreach ($record in $manifest.nodes) {
    [void](Stop-RecordedProcess $record $expected ([string]$record.name))
}
$manifest.state = 'stopped'
$manifest.stopped_utc = [DateTime]::UtcNow.ToString('o')
Save-RecordedJson $ManifestPath $manifest
Write-Host "Configuration, mining key, chain data, and evidence retained in $($manifest.directory)."
