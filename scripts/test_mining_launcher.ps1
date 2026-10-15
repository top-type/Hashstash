[CmdletBinding()]
param(
    [string]$Executable,
    [ValidateRange(1024,65513)][int]$BasePort = 24580,
    [string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent (Split-Path -Parent $repository)
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash.exe' }
if (-not $Report) { $Report = Join-Path $repository 'work/mining-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$fixture = Join-Path $workspace ('work/mining-launcher-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$start = Join-Path $repository 'Start-Testnet.ps1'
$stop = Join-Path $repository 'Stop-Testnet.ps1'
$manifestPath = $null
$checks = [Collections.Generic.List[string]]::new()
$timer = [Diagnostics.Stopwatch]::StartNew()
$userPointer = Join-Path $repository 'data/testnet-latest.json'
$pointerBefore = if (Test-Path -LiteralPath $userPointer) { (Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash } else { $null }
$result = [ordered]@{ passed = $false; checks = $checks; directory = $fixture; node_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant(); processes_stopped = $false }

function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw $Description }
    $checks.Add($Description)
    Write-Host ('PASS: ' + $Description)
}
function Reject([scriptblock]$Action, [string]$Pattern) {
    $message = $null
    try { & $Action } catch { $message = $_.Exception.Message }
    Check ($null -ne $message -and $message -match $Pattern) ('Rejected mining setup: ' + $Pattern)
}
function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 32) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
function Load-Manifest {
    $script:manifestPath = [string](Get-Content -LiteralPath (Join-Path $fixture 'testnet-latest.json') -Raw | ConvertFrom-Json).manifest
    return Get-Content -LiteralPath $script:manifestPath -Raw | ConvertFrom-Json
}
function Statuses($Manifest) {
    return @($Manifest.nodes | ForEach-Object {
        (Invoke-RestMethod -Uri "http://127.0.0.1:$($_.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 5).result
    })
}
function Files($Manifest) {
    return (@(@($Manifest.config) + @($Manifest.nodes.key_file) | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash }) -join ',')
}
function Stratum-Profile([string]$Address, [int]$Port, [string]$Password, [bool]$Authorize, [int]$RpcPort = 0) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($Address, $Port)
        $stream = $client.GetStream(); $stream.ReadTimeout = 5000; $stream.WriteTimeout = 5000
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false)); $writer.AutoFlush = $true
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false))
        $writer.WriteLine('{"id":1,"method":"mining.subscribe","params":["launcher-test"]}')
        $subscribed = $reader.ReadLine() | ConvertFrom-Json
        if ($null -eq $subscribed.result) { throw 'Mining subscription failed' }
        $writer.WriteLine((@{id=2;method='mining.authorize';params=@('launcher.worker',$Password)} | ConvertTo-Json -Compress))
        $authorized = $reader.ReadLine() | ConvertFrom-Json
        if (-not $Authorize) {
            if ($authorized.result -eq $true) { throw 'Incorrect mining password was accepted' }
            return $null
        }
        if ($authorized.result -ne $true) { throw 'Correct mining password was rejected' }
        $difficulty = $reader.ReadLine() | ConvertFrom-Json
        if ($difficulty.method -ne 'mining.set_difficulty') { throw 'Missing share difficulty notification' }
        $job = $reader.ReadLine() | ConvertFrom-Json
        if ($job.method -ne 'mining.notify') { throw 'Missing mining job notification' }
        $assigned = [double]$difficulty.params[0]
        # Decode the actual job target independently. Network work caps a
        # configured reporting floor so ordinary miners report every block.
        $bits = [Convert]::ToUInt32([string]$job.params[6], 16)
        $target = [double]($bits -band 0x7fffff) * [Math]::Pow(256, ($bits -shr 24) - 3)
        $networkDifficulty = (65535.0 * [Math]::Pow(256, 26)) / $target
        $metadata = (Invoke-RestMethod -Uri "http://127.0.0.1:$RpcPort/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"mining","params":{}}' -TimeoutSec 5).result
        return @{ assigned = $assigned; network = $networkDifficulty; metadata = $metadata }
    } finally { $client.Dispose() }
}
function Check-Stratum([string]$Address, [int]$Port, [string]$Password, [int]$RpcPort, [double]$Configured, [string]$Description) {
    $profile = Stratum-Profile $Address $Port $Password $true $RpcPort
    $expected = [Math]::Min($Configured, $profile.network)
    Check ($profile.assigned -gt 0 -and $profile.assigned -le $expected -and [Math]::Abs($profile.assigned / $expected - 1) -lt 1e-12) $Description
    $workers = @($profile.metadata.workers | Where-Object { $_.worker -eq 'launcher.worker' })
    Check ($profile.metadata.stratum.share_difficulty -eq $Configured -and $workers.Count -eq 1 -and $workers[0].share_difficulty -eq $profile.assigned -and $profile.assigned -lt $Configured) 'Configured reporting floor remains separate from the capped worker difficulty'
}

try {
    Reject { & $start -Fresh -DataRoot $fixture -Executable $Executable -BasePort $BasePort -StratumBindIPAddress 'not-an-ip' -NoBrowser } 'must be an IP address'
    Reject { & $start -Fresh -DataRoot $fixture -Executable $Executable -BasePort $BasePort -ShareDifficulty 0 -NoBrowser } 'ShareDifficulty must'
    Reject { & $start -Fresh -DataRoot $fixture -Executable $Executable -BasePort $BasePort -StratumAdvertise '0.0.0.0:18482' -NoBrowser } 'reachable HOST:PORT'
    Check (-not (Test-Path -LiteralPath (Join-Path $fixture 'testnet-latest.json'))) 'Invalid mining options create no network or latest pointer'
    $passwordFile = Join-Path $fixture 'public test password.txt'
    [IO.File]::WriteAllText($passwordFile, 'launcher-test-password', [Text.UTF8Encoding]::new($false))
    $advertised = '127.0.0.2:' + ($BasePort + 2)
    & $start -Fresh -DataRoot $fixture -Executable $Executable -BasePort $BasePort -StratumBindIPAddress '127.0.0.2' -ShareDifficulty 1024 -StratumAdvertise $advertised -StratumPasswordFile $passwordFile -NoBrowser
    $manifest = Load-Manifest
    $networkConfig = Get-Content -LiteralPath $manifest.config -Raw | ConvertFrom-Json
    Check ($networkConfig.protocol_version -eq 28) 'Mining launcher uses the current protocol v28 preset'
    $identity = $manifest.chain_id; $files = Files $manifest
    Check ($manifest.mining.bind_ip -eq '127.0.0.2' -and $manifest.mining.share_difficulty -eq 1024 -and $manifest.mining.advertise -eq $advertised -and $manifest.mining.password_file -eq $passwordFile) 'Fresh network saves explicit mining connection settings'
    Check-Stratum '127.0.0.2' ($BasePort + 2) 'launcher-test-password' $BasePort 1024 'Node 1 binds the selected interface and caps work at its network difficulty'
    Check-Stratum '127.0.0.1' ($BasePort + 12) 'anything' ($BasePort + 10) 65536 'Node 2 retains its loopback listener and caps its default reporting difficulty'
    [void](Stratum-Profile '127.0.0.2' ($BasePort + 2) 'wrong' $false)
    Check $true 'Password-file setting reaches the mining server and rejects another password'
    $manifestBefore = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    Reject { & $start -ManifestPath $manifestPath -DataRoot $fixture -Executable $Executable -ShareDifficulty 2048 -NoBrowser } 'Stop the saved testnet'
    Check ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq $manifestBefore -and (Files $manifest) -eq $files) 'Rejected live change preserves the manifest, genesis and mining keys'
    & $stop -ManifestPath $manifestPath
    & $start -ManifestPath $manifestPath -DataRoot $fixture -Executable $Executable -NoBrowser
    $manifest = Load-Manifest
    Check-Stratum '127.0.0.2' ($BasePort + 2) 'launcher-test-password' $BasePort 1024 'Restart restores mining settings and capped work without repeating arguments'
    Check (@(Statuses $manifest | Where-Object { $_.chain_id -ne $identity -or $_.height -ne 0 -or $_.issued -ne '0' }).Count -eq 0 -and (Files $manifest) -eq $files) 'Mining-setting restart keeps all three original genesis states and mining keys'
    & $stop -ManifestPath $manifestPath
    & $start -ManifestPath $manifestPath -DataRoot $fixture -Executable $Executable -ShareDifficulty 2048 -NoBrowser
    $manifest = Load-Manifest
    Check ($manifest.mining.share_difficulty -eq 2048) 'Stopped network saves a mining-only setting change'
    Check-Stratum '127.0.0.2' ($BasePort + 2) 'launcher-test-password' $BasePort 2048 'Changed reporting floor still preserves network-valid work'
    & $stop -ManifestPath $manifestPath
    $manifest.PSObject.Properties.Remove('mining'); Write-Json $manifestPath $manifest
    $manifestBefore = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    Reject { & $start -ManifestPath $manifestPath -DataRoot $fixture -Executable $Executable -NoBrowser } 'mining settings are missing'
    Check ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq $manifestBefore -and (Files $manifest) -eq $files) 'Missing mining settings are rejected without changing the manifest, network identity or mining keys'
    $result.passed = $true
} finally {
    if ($manifestPath) { & $stop -ManifestPath $manifestPath }
    $result.processes_stopped = $true
    if ($manifestPath) {
        $saved = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        foreach ($node in $saved.nodes) {
            $process = Get-Process -Id ([int]$node.pid) -ErrorAction SilentlyContinue
            if ($process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$node.start_time_ticks) { $result.processes_stopped = $false }
        }
    }
    $pointerAfter = if (Test-Path -LiteralPath $userPointer) { (Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash } else { $null }
    $result.user_pointer_preserved = $pointerBefore -eq $pointerAfter
    $result.elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
    Write-Json $Report $result
}
if (-not $result.processes_stopped -or -not $result.user_pointer_preserved) { throw 'Process or user-pointer preservation failed' }
Write-Host ('Saved ' + $Report)
