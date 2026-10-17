[CmdletBinding()]
param(
    [string]$Executable,
    [ValidateRange(1024,65513)][int]$BasePort = 21880,
    [string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent (Split-Path -Parent $repository)
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash.exe' }
if (-not $Report) { $Report = Join-Path $repository 'work/fresh-wallet-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$fixture = Join-Path $workspace ('work/fresh-wallet-launcher-' + [Guid]::NewGuid().ToString('N'))
$emptyRoot = Join-Path $fixture 'empty'
$seedRoot = Join-Path $fixture 'seeded'
$start = Join-Path $repository 'Start-Testnet.ps1'
$stop = Join-Path $repository 'Stop-Testnet.ps1'
$manifests = [Collections.Generic.List[string]]::new()
$checks = [Collections.Generic.List[string]]::new()
$timer = [Diagnostics.Stopwatch]::StartNew()
$reportValue = [ordered]@{passed=$false; node_sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant(); directory=$fixture; checks=$checks; processes_stopped=$false}
$userPointer = Join-Path $repository 'data/testnet-latest.json'
$pointerBefore = if (Test-Path -LiteralPath $userPointer) {(Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash} else {$null}

function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) {throw $Description}
    $checks.Add($Description)
    Write-Host ('PASS: ' + $Description)
}
function Sessions($Manifest) {
    return @($Manifest.nodes | ForEach-Object {Invoke-RestMethod -Uri "http://127.0.0.1:$($_.rpc_port)/api/session" -TimeoutSec 5})
}
function Call-Node($Record, [string]$Method, $Parameters=@{}) {
    $result = Invoke-RestMethod -Uri "http://127.0.0.1:$($Record.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body (@{jsonrpc='2.0';id=1;method=$Method;params=$Parameters}|ConvertTo-Json -Depth 10) -TimeoutSec 10
    if ($result.PSObject.Properties.Name -contains 'error') {throw ($result.error|ConvertTo-Json -Compress)}
    return $result.result
}
function Load-Manifest([string]$Root) {
    $path = [string](Get-Content -LiteralPath (Join-Path $Root 'testnet-latest.json') -Raw|ConvertFrom-Json).manifest
    if (-not $manifests.Contains($path)) {$manifests.Add($path)}
    return Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
}

try {
    & $start -Fresh -DataRoot $emptyRoot -BasePort $BasePort -Executable $Executable -NoBrowser
    $empty = Load-Manifest $emptyRoot
    $emptyPath = $manifests[0]
    $initial = @(Sessions $empty)
    Check ($empty.seed_wallets -eq $false -and @($initial|Where-Object {$_.wallet_mode -ne 'none' -or $_.wallets.Count -ne 0 -or $null -ne $_.public_key -or $null -ne $_.wallet_id}).Count -eq 0) 'Default fresh launcher starts all three nodes with no saved or selected account'
    $genesis = @( $empty.nodes|ForEach-Object {Call-Node $_ 'status'} )
    Check (@($genesis|Where-Object {$_.height -ne 0 -or $_.issued -ne '0' -or $_.mempool -ne 0}).Count -eq 0) 'Default fresh chain has no blocks, issued HASH, or pending transactions'
    & $stop -ManifestPath $emptyPath
    & $start -ManifestPath $emptyPath -DataRoot $emptyRoot -Executable $Executable -NoBrowser
    $empty = Load-Manifest $emptyRoot
    $restarted = @(Sessions $empty)
    Check (@($restarted|Where-Object {$_.wallet_mode -ne 'none' -or $_.wallets.Count -ne 0}).Count -eq 0) 'Restart preserves empty wallet managers without loading mining-key backups'
    $node = $empty.nodes[0]
    $origin = "http://127.0.0.1:$($node.rpc_port)"
    $created = Invoke-RestMethod -Uri ($origin+'/api/wallet/manage') -Method Post -ContentType 'application/json' -Headers @{'Origin'=$origin;'X-Hashstash-Token'=(Get-Content -LiteralPath ([IO.Path]::ChangeExtension([string]$node.data_file, 'session-token')) -Raw)} -Body (@{action='create';name='First wallet';revision=$restarted[0].wallet_revision}|ConvertTo-Json) -TimeoutSec 5
    Check ($created.wallets.Count -eq 1 -and $created.wallet_mode -eq 'hot') 'First explicit wallet creation adds exactly one hot account'
    [void](Call-Node $node 'mine' @{count=1;recipient=$created.public_key})
    $minedStatus = Call-Node $node 'status'
    $selected = (Sessions $empty)[0]
    Check ($minedStatus.issued -eq '0' -and $selected.miner -eq $node.public_key -and $selected.public_key -eq $created.public_key) 'An easy production block issues zero atoms; wallet selection leaves the configured mining recipient unchanged'
    & $stop -ManifestPath $emptyPath
    & $start -ManifestPath $emptyPath -DataRoot $emptyRoot -Executable $Executable -NoBrowser
    $empty = Load-Manifest $emptyRoot
    $saved = @(Sessions $empty)
    Check ($saved[0].wallet_id -eq $created.wallet_id -and $saved[0].wallets.Count -eq 1 -and $saved[1].wallets.Count -eq 0 -and $saved[2].wallets.Count -eq 0) 'Saved explicit wallet selection survives restart without populating the other nodes'
    & $stop -ManifestPath $emptyPath

    & $start -Fresh -SeedWallets -DataRoot $seedRoot -BasePort $BasePort -Executable $Executable -NoBrowser
    $seeded = Load-Manifest $seedRoot
    $seedPath = $manifests[1]
    $hot = @(Sessions $seeded)
    $correct = $seeded.seed_wallets -eq $true
    for ($index=0;$index -lt 3;$index++) {$correct=$correct -and $hot[$index].wallet_mode -eq 'hot' -and $hot[$index].wallets.Count -eq 1 -and $hot[$index].public_key -eq $seeded.nodes[$index].public_key}
    Check $correct 'Explicit SeedWallets initializes exactly one mining wallet on each test node'
    & $stop -ManifestPath $seedPath
    & $start -ManifestPath $seedPath -DataRoot $seedRoot -Executable $Executable -NoBrowser
    $seeded = Load-Manifest $seedRoot
    $hot = @(Sessions $seeded)
    Check ($seeded.seed_wallets -eq $true -and @($hot|Where-Object {$_.wallet_mode -ne 'hot' -or $_.wallets.Count -ne 1}).Count -eq 0) 'Manifest persists the seeding choice when restarting without the command-line switch'
    & $stop -ManifestPath $seedPath
    $savedMining = $seeded.mining
    $seeded.PSObject.Properties.Remove('mining')
    [IO.File]::WriteAllText($seedPath,($seeded|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $start -ManifestPath $seedPath -DataRoot $seedRoot -Executable $Executable -NoBrowser } catch { $rejected = $_.Exception.Message -like '*mining settings*' }
    Check $rejected 'Missing mining settings are rejected before starting nodes'
    $seeded | Add-Member -NotePropertyName mining -NotePropertyValue $savedMining
    $seeded.PSObject.Properties.Remove('seed_wallets')
    [IO.File]::WriteAllText($seedPath,($seeded|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $start -ManifestPath $seedPath -DataRoot $seedRoot -Executable $Executable -NoBrowser } catch { $rejected = $_.Exception.Message -like '*seeding setting*' }
    Check $rejected 'Missing wallet-seeding intent is rejected before starting nodes'
    $reportValue.passed=$true
} finally {
    foreach ($path in $manifests) {& $stop -ManifestPath $path}
    $allStopped=$true
    foreach ($path in $manifests) {
        $manifest=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        foreach ($record in $manifest.nodes) {
            $candidate=Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
            if ($candidate -and $candidate.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$record.start_time_ticks) {$allStopped=$false}
        }
    }
    $reportValue.processes_stopped=$allStopped
    $pointerAfter=if (Test-Path -LiteralPath $userPointer) {(Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash} else {$null}
    $reportValue.user_pointer_preserved=$pointerBefore -eq $pointerAfter
    $timer.Stop()
    $reportValue.elapsed_seconds=[Math]::Round($timer.Elapsed.TotalSeconds,3)
    [IO.File]::WriteAllText($Report,($reportValue|ConvertTo-Json -Depth 16)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
if (-not $reportValue.processes_stopped -or -not $reportValue.user_pointer_preserved) {throw 'Process or user pointer preservation failed'}
Write-Host ('Saved ' + $Report)
