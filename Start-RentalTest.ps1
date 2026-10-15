[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$ExpectedHashrate = '100T',
    [ValidateRange(1024,65523)][int]$BasePort = 20280,
    [double]$ShareDifficulty = 65536,
    [string]$StratumAdvertise = '',
    [string]$StratumPasswordFile = '',
    [switch]$GeneratePassword,
    [string]$Executable
)

# Always creates a separate network. All listeners stay on loopback; an external
# forwarder, if wanted, is configured separately. This script never mines.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This launcher requires Windows.' }
if ($GeneratePassword -and $StratumPasswordFile) { throw 'Choose GeneratePassword or StratumPasswordFile, not both.' }
if (-not $Executable) {
    $Executable = Join-Path $PSScriptRoot 'target/release/hashstash.exe'
    if (-not (Test-Path -LiteralPath $Executable)) { $Executable = Join-Path $PSScriptRoot 'bin/hashstash.exe' }
}
$Executable = (Resolve-Path -LiteralPath $Executable).Path
if ([double]::IsNaN($ShareDifficulty) -or [double]::IsInfinity($ShareDifficulty) -or $ShareDifficulty -lt 1e-12 -or $ShareDifficulty -gt 1e18) { throw 'ShareDifficulty must be finite and between 1e-12 and 1e18.' }
if ($StratumPasswordFile) { $StratumPasswordFile = (Resolve-Path -LiteralPath $StratumPasswordFile).Path }
if ($StratumAdvertise -and ($StratumAdvertise.Length -gt 320 -or $StratumAdvertise -notmatch '^(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})$' -or [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535)) { throw 'StratumAdvertise must be HOST:PORT.' }

function Save-Manifest([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 32) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}
function Quote-Argument([string]$Value) {
    if ($Value.Contains('"')) { throw 'A process argument contains a quote character.' }
    return '"' + $Value + '"'
}
function Status([int]$Port) {
    $reply = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 3
    if (-not $reply.result) { throw 'Node did not return a status result.' }
    return $reply.result
}

# Refuse occupied ports without interacting with their owners.
foreach ($offset in 0,1,2,10,11,12) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $BasePort + $offset)
    try { $listener.Server.ExclusiveAddressUse = $true; $listener.Start() }
    catch { throw "Port $($BasePort + $offset) is occupied. Choose another -BasePort; no process was stopped." }
    finally { $listener.Stop() }
}

$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workRoot = Join-Path $workspace 'work'
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$suffix = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$directory = Join-Path $workRoot ('rental-test-' + $suffix)
New-Item -ItemType Directory -Path $directory | Out-Null
$configPath = Join-Path $directory 'network.json'
$keyPath = Join-Path $directory 'miner.key'
$manifestPath = Join-Path $directory 'manifest.json'
$started = @()
$manifest = $null
try {
    if ($GeneratePassword) {
        $passwordBytes = New-Object byte[] 32
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $random.GetBytes($passwordBytes) } finally { $random.Dispose() }
        $StratumPasswordFile = Join-Path $directory 'stratum-password.txt'
        [IO.File]::WriteAllText($StratumPasswordFile, ([BitConverter]::ToString($passwordBytes).Replace('-','').ToLowerInvariant()), [Text.UTF8Encoding]::new($false))
    }
    & $Executable init --preset slow --hashrate $ExpectedHashrate --config $configPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Initial hashrate calibration failed.' }
    $configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($configuration.test_work) { throw 'Rental mining requires production issuance. Supply a normal build without test-fixtures.' }
    $configuration.network = 'hashstash-rental-' + $suffix
    # The initial work estimate seeds timestamp DAA; it is not an easing floor.
    Save-Manifest $configPath $configuration
    $identity = & $Executable network --config $configPath | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Calibrated configuration validation failed.' }
    & $Executable keygen --out $keyPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the rental mining key.' }
    $publicKey = [string](& $Executable public-key --key $keyPath)
    if ($LASTEXITCODE -ne 0 -or $publicKey -notmatch '^[0-9a-fA-F]{64}$') { throw 'Could not read the mining public key.' }
    $nodes = @()
    foreach ($index in 0,1) {
        $nodeDirectory = Join-Path $directory ('node-' + ($index + 1))
        New-Item -ItemType Directory -Path $nodeDirectory | Out-Null
        $nodes += [PSCustomObject]@{
            name = if ($index -eq 0) { 'primary' } else { 'observer' }
            pid = 0; start_time_ticks = ''; start_time_utc = ''; executable = $Executable
            rpc_port = $BasePort + 10 * $index; p2p_port = $BasePort + 10 * $index + 1; stratum_port = $BasePort + 10 * $index + 2
            directory = $nodeDirectory; data_file = (Join-Path $nodeDirectory 'chain.sqlite')
            stdout_file = (Join-Path $nodeDirectory 'stdout.log'); stderr_file = (Join-Path $nodeDirectory 'stderr.log')
        }
    }
    $manifest = [PSCustomObject]@{
        format = 'hashstash-rental-test-v1'; state = 'starting'; directory = $directory; config = $configPath
        executable = $Executable; executable_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
        created_utc = [DateTime]::UtcNow.ToString('o'); stopped_utc = ''; chain_id = [string]$identity.chain_id
        expected_hashrate = $ExpectedHashrate; calibration_seconds = 15; initial_bits = $configuration.initial_bits
        public_key = $publicKey; key_file = $keyPath; wallets_seeded = $false; software_mining = $false
        mining = [PSCustomObject]@{ bind_ip = '127.0.0.1'; local_url = "stratum+tcp://127.0.0.1:$($BasePort + 2)"; advertise = $StratumAdvertise; share_difficulty = $ShareDifficulty; password_required = [bool]$StratumPasswordFile; password_file = $StratumPasswordFile }
        nodes = $nodes
    }
    Save-Manifest $manifestPath $manifest
    foreach ($index in 0,1) {
        $record = $nodes[$index]
        $peer = $nodes[1 - $index]
        $arguments = @('run', '--config', (Quote-Argument $configPath), '--data', (Quote-Argument $record.data_file), '--miner', $publicKey,
            '--rpc', "127.0.0.1:$($record.rpc_port)", '--p2p', "127.0.0.1:$($record.p2p_port)", '--stratum', "127.0.0.1:$($record.stratum_port)",
            '--peer', "127.0.0.1:$($peer.p2p_port)", '--stratum-share-difficulty', $ShareDifficulty.ToString('R',[Globalization.CultureInfo]::InvariantCulture))
        if ($index -eq 0) {
            if ($StratumAdvertise) { $arguments += @('--stratum-advertise', (Quote-Argument $StratumAdvertise)) }
            if ($StratumPasswordFile) { $arguments += @('--stratum-password-file', (Quote-Argument $StratumPasswordFile)) }
        }
        # Deliberately omit wallet-key/watch-key: both wallet managers begin empty.
        $child = Start-Process -FilePath $Executable -ArgumentList ($arguments -join ' ') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $record.stdout_file -RedirectStandardError $record.stderr_file -PassThru
        $started += $child
        $record.pid = $child.Id
        $record.start_time_ticks = $child.StartTime.ToUniversalTime().Ticks.ToString()
        $record.start_time_utc = $child.StartTime.ToUniversalTime().ToString('o')
        Save-Manifest $manifestPath $manifest
    }
    foreach ($record in $nodes) {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $ready = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            $child = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
            if ($null -eq $child) { throw "$($record.name) exited; inspect its stderr.log." }
            if (-not [String]::Equals([IO.Path]::GetFullPath($child.Path), $Executable, [StringComparison]::OrdinalIgnoreCase) -or $child.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.start_time_ticks) { throw 'A launched process no longer matches its recorded executable and start time.' }
            try { $status = Status $record.rpc_port; $ready = $true; break } catch { Start-Sleep -Milliseconds 150 }
        }
        if (-not $ready) { throw "$($record.name) did not become ready." }
        if ($status.chain_id -ne $manifest.chain_id -or $status.height -ne 0 -or $status.issued -ne '0') { throw 'Fresh network identity or empty-chain check failed.' }
    }
    $manifest.state = 'running'
    Save-Manifest $manifestPath $manifest
    Write-Host "Isolated rental test ready; no blocks mined. All listeners are loopback-only."
    Write-Host "Local Stratum: $($manifest.mining.local_url)"
    Write-Host "Stop: .\Stop-RentalTest.ps1 -ManifestPath `"$manifestPath`""
    Write-Output $manifestPath
} catch {
    foreach ($child in $started) {
        try { if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(10000) } } catch { }
    }
    if ($null -ne $manifest) { $manifest.state = 'failed'; $manifest.stopped_utc = [DateTime]::UtcNow.ToString('o'); Save-Manifest $manifestPath $manifest }
    throw
}
