[CmdletBinding(DefaultParameterSetName = 'PublicKey')]
param(
    [Parameter(Mandatory, ParameterSetName = 'PublicKey')][Alias('Address')][string]$PublicKey,
    [Parameter(Mandatory, ParameterSetName = 'WatchFile')][string]$WatchFile,
    [string]$Config,
    [string]$ManifestPath,
    [string[]]$Peer = @(),
    [string]$DataDirectory,
    [ValidateRange(1024, 65533)][int]$BasePort = 20080,
    [string]$Executable,
    [switch]$NoBrowser,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This launcher is for Windows. Use hashstash run --watch-key on other systems.' }

function Save-WatchJson([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}
function Quote-WatchArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'A process argument contains an unsupported quote character.' }
    return '"' + $Value + '"'
}
function Find-WatchProcess($Record) {
    $candidate = Get-Process -Id ([int]$Record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { return $null }
    try {
        if ([String]::Equals([IO.Path]::GetFullPath($candidate.Path), [string]$Record.executable, [StringComparison]::OrdinalIgnoreCase) -and
            $candidate.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$Record.start_time_ticks) { return $candidate }
    } catch { }
    return $null
}

$descriptor = $null
if ($WatchFile) {
    if ((Get-Item -LiteralPath $WatchFile).Length -gt 4096) { throw 'Watch descriptor is too large.' }
    $descriptor = Get-Content -LiteralPath $WatchFile -Raw | ConvertFrom-Json
    if ($descriptor.format -eq 'hashstash-watch-v1') { $PublicKey = [string]$descriptor.public_key }
    elseif ($descriptor.format -eq 'hashstash-watch-v2') { $PublicKey = [string]$descriptor.address }
    else { throw 'Unsupported watch descriptor format.' }
}
$PublicKey = $PublicKey.Trim()
if ($Config -and $ManifestPath) { throw 'Use either -Config or -ManifestPath.' }
$expectedChain = ''
if (-not $Config) {
    if (-not $ManifestPath) {
        $latestTestnet = Join-Path $PSScriptRoot 'data/testnet-latest.json'
        if (-not (Test-Path -LiteralPath $latestTestnet)) { throw 'Start a testnet first, or supply -Config and -Peer.' }
        $ManifestPath = [string](Get-Content -LiteralPath $latestTestnet -Raw | ConvertFrom-Json).manifest
    }
    $network = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ($network.schema_version -ne 1 -or @($network.nodes).Count -ne 3) { throw 'Unsupported testnet manifest.' }
    $Config = [string]$network.config
    $expectedChain = [string]$network.chain_id
    if (-not $PSBoundParameters.ContainsKey('Peer')) {
        $Peer = @($network.nodes | ForEach-Object { '127.0.0.1:' + $_.p2p_port })
    }
}
$Config = (Resolve-Path -LiteralPath $Config).Path
if (-not $Executable) {
    $Executable = Join-Path $PSScriptRoot 'target/release/hashstash.exe'
    if (-not (Test-Path -LiteralPath $Executable)) { $Executable = Join-Path $PSScriptRoot 'bin/hashstash.exe' }
}
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$networkDescriptor = & $Executable network --config $Config | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Could not read the network identity.' }
if ($expectedChain -and $networkDescriptor.chain_id -cne $expectedChain) { throw 'The testnet manifest chain identity does not match its configuration.' }
if ($null -ne $descriptor -and $descriptor.format -eq 'hashstash-watch-v2' -and $descriptor.chain_id -cne $networkDescriptor.chain_id) { throw 'The watch address belongs to a different network.' }
if ($PublicKey -cmatch '^[0-9a-fA-F]{64}$' -and ($null -eq $descriptor -or $descriptor.format -eq 'hashstash-watch-v1')) {
    $PublicKey = $PublicKey.ToLowerInvariant()
} else {
    $PublicKey = [string](& $Executable decode-address --address $PublicKey --config $Config)
    if ($LASTEXITCODE -ne 0) { throw 'Invalid address or wrong network.' }
    if ($null -ne $descriptor -and $descriptor.format -eq 'hashstash-watch-v2' -and $descriptor.public_key -cne $PublicKey) { throw 'Watch descriptor public key does not match its address.' }
}
$watchedAddress = [string](& $Executable address --public-key $PublicKey --config $Config)
if ($LASTEXITCODE -ne 0) { throw 'Invalid account public key.' }
if (-not $DataDirectory) {
    $configId = (Get-FileHash -LiteralPath $Config -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0, 16)
    $DataDirectory = Join-Path $PSScriptRoot ('data/watch/' + $configId + '/' + $PublicKey)
}
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
$recordPath = Join-Path $DataDirectory 'watch-node.json'
$latestPath = Join-Path $PSScriptRoot 'data/watch-latest.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $latestPath) -Force | Out-Null
$launchLock = $null
$started = $null
$record = $null
try {
    try { $launchLock = [IO.File]::Open((Join-Path $DataDirectory 'launch.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'Another watch-only launcher is using this data directory.' }
    if (Test-Path -LiteralPath $recordPath) {
        $saved = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        if ($saved.schema_version -ne 1 -or $saved.public_key -ne $PublicKey) { throw 'This data directory belongs to a different watched account.' }
        if ($null -ne (Find-WatchProcess $saved)) {
            if ($saved.config -ne $Config -or $saved.executable -ne $Executable -or [int]$saved.base_port -ne $BasePort -or (@($saved.peers) -join ',') -ne ($Peer -join ',')) {
                throw 'The watch node is already running with different settings. Stop it with Stop-WatchOnly.ps1 before changing them.'
            }
            $record = $saved
        }
    }
    if ($null -eq $record) {
        foreach ($port in $BasePort, ($BasePort + 1), ($BasePort + 2)) {
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port)
            try { $listener.Server.ExclusiveAddressUse = $true; $listener.Start() }
            catch { throw "Port $port is in use. Choose another -BasePort. No existing process was stopped." }
            finally { $listener.Stop() }
        }
        $arguments = @('run', '--config', $Config, '--data', (Join-Path $DataDirectory 'chain.sqlite'), '--miner', $PublicKey, '--watch-key', $PublicKey,
            '--rpc', "127.0.0.1:$BasePort", '--p2p', ('127.0.0.1:' + ($BasePort + 1)), '--stratum', ('127.0.0.1:' + ($BasePort + 2)))
        foreach ($endpoint in $Peer) { $arguments += @('--peer', $endpoint) }
        $started = Start-Process -FilePath $Executable -ArgumentList (($arguments | ForEach-Object { Quote-WatchArgument $_ }) -join ' ') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $DataDirectory 'stdout.log') -RedirectStandardError (Join-Path $DataDirectory 'stderr.log')
        $record = [PSCustomObject]@{
            schema_version = 1; pid = $started.Id; executable = $Executable
            start_time_ticks = $started.StartTime.ToUniversalTime().Ticks.ToString()
            public_key = $PublicKey; config = $Config; peers = @($Peer); base_port = $BasePort
            directory = $DataDirectory; url = "http://127.0.0.1:$BasePort/"; chain_id = ''
        }
        Save-WatchJson $recordPath $record
    }
    $ready = $false
    $servedChain = ''
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -eq (Find-WatchProcess $record)) { throw "Watch node exited. Read $DataDirectory\stderr.log." }
        # Only startup request failures are retried; the identity check below is not swallowed.
        try {
            $session = Invoke-RestMethod -Uri ($record.url + 'api/session') -TimeoutSec 2
            $status = Invoke-RestMethod -Uri ($record.url + 'rpc') -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 2
            # The saved manager selection may have changed through the Wallet page.
            if ($session.miner -eq $PublicKey -and $session.wallet_id -and $status.result.chain_id) {
                $servedChain = [string]$status.result.chain_id
                $ready = $true
                break
            }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { throw "Watch node did not become ready. Read $DataDirectory\stderr.log." }
    if ($servedChain -cne $networkDescriptor.chain_id) { throw 'Watch node returned a different chain identity.' }
    $record.chain_id = $servedChain
    Save-WatchJson $recordPath $record
    Save-WatchJson $latestPath ([PSCustomObject]@{ record = $recordPath })
    Write-Host ('Wallet: ' + $record.url)
    Write-Host ('Account address: ' + $watchedAddress)
    Write-Host ('Mining recipient: ' + $PublicKey)
    Write-Host ('Data: ' + $DataDirectory)
    if (-not $NoBrowser) { Start-Process $record.url | Out-Null }
    if ($PassThru) { $record }
} catch {
    if ($null -ne $started -and -not $started.HasExited) { $started.Kill(); $started.WaitForExit(10000) | Out-Null }
    throw
} finally {
    if ($null -ne $launchLock) { $launchLock.Dispose() }
}
