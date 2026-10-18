[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [ValidateRange(1024,65533)][int]$BasePort = 21780,
    [string]$Executable,
    [string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent (Split-Path -Parent $repository)
$fixture = Join-Path $workspace 'work/wallet-manager-launcher-test'
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
foreach ($script in @('Start-WatchOnly.ps1','Stop-WatchOnly.ps1')) {
    Copy-Item -LiteralPath (Join-Path $repository $script) -Destination (Join-Path $fixture $script) -Force
}
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash.exe' }
if (-not $Report) { $Report = Join-Path $repository 'work/wallet-manager-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$Config = (Resolve-Path -LiteralPath $Config).Path
$vector = (Get-Content -LiteralPath (Join-Path $repository 'tests/data/passphrase-v1.json') -Raw | ConvertFrom-Json).vectors[0]
$publicKey = [string]$vector.public_key
$directory = Join-Path $fixture ('data-' + [Guid]::NewGuid().ToString('N'))
$recordPath = Join-Path $directory 'watch-node.json'
$userPointer = Join-Path $repository 'data/watch-latest.json'
$pointerBefore = if (Test-Path -LiteralPath $userPointer) { (Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash } else { $null }
$timer = [Diagnostics.Stopwatch]::StartNew()
$checks = [Collections.Generic.List[string]]::new()
$result = [ordered]@{ passed=$false; node_sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant(); config=$Config; fixture=$directory; checks=$checks; owned_process_stopped=$false }

function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw $Description }
    $checks.Add($Description)
    Write-Host ('PASS: ' + $Description)
}

try {
    $network = & $Executable network --config $Config | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Could not read test network identity.' }
    $address = [string](& $Executable address --public-key $publicKey --config $Config)
    if ($LASTEXITCODE -ne 0) { throw 'Could not encode test account address.' }
    $descriptor = [ordered]@{format='hashstash-watch-v2';address=$address;public_key=$publicKey;chain_id=[string]$network.chain_id}
    $watchFile = $directory + '.watch.json'
    [IO.File]::WriteAllText($watchFile, ($descriptor | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $first = & (Join-Path $fixture 'Start-WatchOnly.ps1') -WatchFile $watchFile -Config $Config -Executable $Executable -DataDirectory $directory -BasePort $BasePort -NoBrowser -PassThru
    # Server wallets are listed only to a caller presenting the node's session token.
    $session = Invoke-RestMethod -Uri ($first.url + 'api/session') -Headers @{'X-Hashstash-Token'=(Get-Content -LiteralPath (Join-Path $directory 'chain.session-token') -Raw)} -TimeoutSec 5
    Check ($session.wallet_mode -eq 'watch' -and $session.public_key -eq $publicKey -and $session.miner -eq $publicKey -and $session.address -eq $address) 'Fresh copied launcher imports a v2 descriptor with the correct address, watch account, and miner'
    $alias = & (Join-Path $fixture 'Start-WatchOnly.ps1') -Address $address -Config $Config -Executable $Executable -DataDirectory $directory -BasePort $BasePort -NoBrowser -PassThru
    Check ([int]$alias.pid -eq [int]$first.pid) 'Address alias resolves to the same existing watch account and process'
    $invalidFile = $directory + '.invalid-watch.json'
    $invalidDirectory = $directory + '-rejected'
    $last = if ($descriptor.chain_id.EndsWith('0')) { '1' } else { '0' }
    $descriptor.chain_id = $descriptor.chain_id.Substring(0,63) + $last
    [IO.File]::WriteAllText($invalidFile, ($descriptor | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & (Join-Path $fixture 'Start-WatchOnly.ps1') -WatchFile $invalidFile -Config $Config -Executable $Executable -DataDirectory $invalidDirectory -BasePort $BasePort -NoBrowser -PassThru | Out-Null }
    catch { $rejected = $_.Exception.Message -like '*different network*' }
    Check ($rejected -and -not (Test-Path -LiteralPath $invalidDirectory)) 'V2 full chain ID mismatch rejects before creating node data even when the address fingerprint matches'
    $descriptor.chain_id = [string]$network.chain_id
    $descriptor.public_key = [string](Get-Content -LiteralPath (Join-Path $repository 'tests/data/passphrase-v1.json') -Raw | ConvertFrom-Json).vectors[1].public_key
    [IO.File]::WriteAllText($invalidFile, ($descriptor | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & (Join-Path $fixture 'Start-WatchOnly.ps1') -WatchFile $invalidFile -Config $Config -Executable $Executable -DataDirectory $invalidDirectory -BasePort $BasePort -NoBrowser -PassThru | Out-Null }
    catch { $rejected = $_.Exception.Message -like '*does not match its address*' }
    Check ($rejected -and -not (Test-Path -LiteralPath $invalidDirectory)) 'V2 public key mismatch rejects before creating node data'
    $manifestFile = $directory + '.manifest.json'
    $manifest = [ordered]@{schema_version=1; config=$Config; chain_id=(([string]$network.chain_id).Substring(0,63) + $last); nodes=@(1,2,3 | ForEach-Object { [ordered]@{p2p_port=($BasePort + 20 + $_)} })}
    [IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & (Join-Path $fixture 'Start-WatchOnly.ps1') -PublicKey $publicKey -ManifestPath $manifestFile -Executable $Executable -DataDirectory $invalidDirectory -BasePort $BasePort -NoBrowser -PassThru | Out-Null }
    catch { $rejected = $_.Exception.Message -like '*manifest chain identity*' }
    Check ($rejected -and -not (Test-Path -LiteralPath $invalidDirectory)) 'Manifest chain ID mismatch is reported before launch instead of as a readiness timeout'
    [IO.File]::WriteAllText($invalidFile, (@{format='hashstash-watch-v1';public_key=$publicKey} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $legacy = & (Join-Path $fixture 'Start-WatchOnly.ps1') -WatchFile $invalidFile -Config $Config -Executable $Executable -DataDirectory $directory -BasePort $BasePort -NoBrowser -PassThru
    Check ([int]$legacy.pid -eq [int]$first.pid) 'Legacy v1 watch descriptor remains compatible with the same account'
    $created = Invoke-RestMethod -Uri ($first.url + 'api/wallet/manage') -Method Post -ContentType 'application/json' -Headers @{'Origin'=$first.url.TrimEnd('/');'X-Hashstash-Token'=(Get-Content -LiteralPath (Join-Path $directory 'chain.session-token') -Raw)} -Body (@{action='create';name='Launcher persistence test';revision=$session.wallet_revision} | ConvertTo-Json) -TimeoutSec 5
    Check ($created.wallet_mode -eq 'hot' -and $created.public_key -ne $publicKey) 'Runtime creation selects a different hot wallet on the same node'
    $selected = [string]$created.public_key
    $selectedId = [string]$created.wallet_id
    $oldProcess = [int]$first.pid
    & (Join-Path $fixture 'Stop-WatchOnly.ps1') -RecordPath $recordPath
    Check ($null -eq (Get-Process -Id $oldProcess -ErrorAction SilentlyContinue)) 'First owned node process stops before restart'
    $second = & (Join-Path $fixture 'Start-WatchOnly.ps1') -PublicKey $publicKey -Config $Config -Executable $Executable -DataDirectory $directory -BasePort $BasePort -NoBrowser -PassThru
    $restored = Invoke-RestMethod -Uri ($second.url + 'api/session') -Headers @{'X-Hashstash-Token'=(Get-Content -LiteralPath (Join-Path $directory 'chain.session-token') -Raw)} -TimeoutSec 5
    Check ($restored.wallet_mode -eq 'hot' -and $restored.wallet_enabled -and $restored.public_key -eq $selected -and $restored.wallet_id -eq $selectedId) 'Restart with the original watch argument preserves the saved hot selection and passes readiness'
    Check ($restored.miner -eq $publicKey -and $second.public_key -eq $publicKey) 'Saved wallet selection does not change the mining recipient or launcher identity'
    $again = & (Join-Path $fixture 'Start-WatchOnly.ps1') -PublicKey $publicKey -Config $Config -Executable $Executable -DataDirectory $directory -BasePort $BasePort -NoBrowser -PassThru
    Check ([int]$again.pid -eq [int]$second.pid) 'Repeated launcher call reuses the ready hot-selected process'
    $result.initial_public_key = $publicKey
    $result.initial_address = $address
    $result.chain_id = [string]$network.chain_id
    $result.saved_hot_public_key = $selected
    $result.wallet_id = $selectedId
    $result.passed = $true
} finally {
    if (Test-Path -LiteralPath $recordPath) {
        & (Join-Path $fixture 'Stop-WatchOnly.ps1') -RecordPath $recordPath
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        $result.owned_process_stopped = $null -eq (Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue)
    }
    $pointerAfter = if (Test-Path -LiteralPath $userPointer) { (Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash } else { $null }
    $result.user_pointer_preserved = $pointerAfter -eq $pointerBefore
    $timer.Stop()
    $result.elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds,3)
    [IO.File]::WriteAllText($Report, ($result | ConvertTo-Json -Depth 12) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
if (-not $result.owned_process_stopped -or -not $result.user_pointer_preserved) { throw 'Final process or pointer preservation check failed.' }
Write-Host ('Saved ' + $Report)
