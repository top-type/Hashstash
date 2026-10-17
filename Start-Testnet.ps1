[CmdletBinding()]
param(
    [switch]$Fresh,
    [string]$DataRoot = (Join-Path $PSScriptRoot 'data'),
    [string]$ManifestPath,
    [ValidateRange(1024, 65513)][int]$BasePort = 19480,
    [ValidateRange(0, 100)][int]$InitialBlocks = 0,
    [switch]$SeedWallets,
    [string]$Executable,
    [switch]$NoBrowser,
    # Mining connection settings apply to node 1. Other nodes remain loopback-only.
    [string]$StratumBindIPAddress = '127.0.0.1',
    [double]$ShareDifficulty = 65536,
    [string]$StratumAdvertise = '',
    [string]$StratumPasswordFile = '',
    [ValidateNotNullOrEmpty()][string]$Config = (Join-Path $PSScriptRoot 'config/testnet.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Save-JsonAtomic([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 32) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}

function Get-RecordedProcess($Node, [string]$ExpectedExecutable) {
    if ([int]$Node.pid -le 0) { return $null }
    $candidate = Get-Process -Id ([int]$Node.pid) -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { return $null }
    try {
        $actualPath = [IO.Path]::GetFullPath($candidate.Path)
        $actualStart = $candidate.StartTime.ToUniversalTime().Ticks.ToString()
        if (-not [String]::Equals($actualPath, $ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        if ($actualStart -ne [string]$Node.start_time_ticks) { return $null }
        return $candidate
    } catch { return $null }
}

function Get-LaunchedProcessPath([Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) { throw 'A node exited during startup. Read its stderr.log.' }
        $snapshot = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
        if ($null -ne $snapshot -and -not [String]::IsNullOrEmpty($snapshot.Path)) { return [IO.Path]::GetFullPath($snapshot.Path) }
        Start-Sleep -Milliseconds 20
    }
    throw 'Could not verify a newly launched node executable.'
}

function Assert-PortFree([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
    } catch {
        throw "Port $Port is already in use. No existing process was stopped. Choose another -BasePort with -Fresh, or stop the corresponding saved testnet first."
    } finally { $listener.Stop() }
}

function Quote-ProcessArgument([string]$Value) {
    # All file arguments are absolute file paths, so none end in a separator.
    if ($Value.Contains('"')) { throw 'A process argument contains an unsupported quote character.' }
    return '"' + $Value + '"'
}

function Get-StratumEndpoint([string]$Address, [int]$Port) {
    $ip = [Net.IPAddress]::Parse($Address)
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { return ('[{0}]:{1}' -f $ip, $Port) }
    return ('{0}:{1}' -f $ip, $Port)
}

function Assert-MiningSettings($Settings) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse([string]$Settings.bind_ip, [ref]$parsed)) { throw 'StratumBindIPAddress must be an IP address.' }
    $difficulty = [double]$Settings.share_difficulty
    if ([double]::IsNaN($difficulty) -or [double]::IsInfinity($difficulty) -or $difficulty -lt 1e-12 -or $difficulty -gt 1e18) { throw 'ShareDifficulty must be a finite number from 1e-12 to 1e18.' }
    if ($Settings.advertise) {
        $endpoint = [string]$Settings.advertise
        if ($endpoint.Length -gt 320 -or $endpoint -notmatch '^(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})$' -or [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535 -or $endpoint -match '^(?:0\.0\.0\.0|\[::\]):') { throw 'StratumAdvertise must be a reachable HOST:PORT, without a URL prefix or wildcard address.' }
    }
    if ($Settings.password_file -and -not (Test-Path -LiteralPath ([string]$Settings.password_file) -PathType Leaf)) { throw 'StratumPasswordFile does not exist.' }
    # The node refuses a non-loopback Stratum listener without a password; fail before creating a network.
    if (-not [Net.IPAddress]::IsLoopback($parsed) -and -not $Settings.password_file) { throw 'A non-loopback StratumBindIPAddress requires StratumPasswordFile.' }
}

function Wait-NodeReady($Node, [string]$ExpectedExecutable) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -eq (Get-RecordedProcess $Node $ExpectedExecutable)) {
            throw "$($Node.name) exited before becoming ready. Read $($Node.stderr_file)."
        }
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:$($Node.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 2
            if ($null -ne $response.result -and $response.result.chain_id) { return $response.result }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    throw "$($Node.name) did not become ready. Read $($Node.stderr_file)."
}

function Wait-TestnetConvergence($Nodes, [string]$ExpectedExecutable, [int]$TimeoutSeconds = 40) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $tips = @()
        foreach ($nodeRecord in $Nodes) {
            if ($null -eq (Get-RecordedProcess $nodeRecord $ExpectedExecutable)) { throw "$($nodeRecord.name) stopped while waiting for peer synchronization." }
            try {
                $response = Invoke-RestMethod -Uri "http://127.0.0.1:$($nodeRecord.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 2
                if ($response.result.tip) { $tips += [string]$response.result.tip }
            } catch { }
        }
        if ($tips.Count -eq @($Nodes).Count -and @($tips | Select-Object -Unique).Count -eq 1) { return $true }
        Start-Sleep -Milliseconds 200
    }
    Write-Warning 'Nodes are ready but currently have different tips. They remain running; equal-work forks can require another block to resolve.'
    return $false
}

if ($Fresh -and $ManifestPath) { throw '-Fresh and -ManifestPath cannot be used together.' }
if ($env:OS -ne 'Windows_NT') { throw 'This launcher is for Windows. Run the node CLI directly on other systems.' }
$resolvedDataRoot = [IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Path $resolvedDataRoot -Force | Out-Null
$latestPath = Join-Path $resolvedDataRoot 'testnet-latest.json'
$launchLock = $null
$startedHere = @()
$startedProcesses = @()
$manifest = $null
try {
    try { $launchLock = [IO.File]::Open((Join-Path $resolvedDataRoot 'testnet-launch.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'Another testnet launcher is already using this data directory.' }

    if (-not $Fresh -and -not $ManifestPath -and (Test-Path -LiteralPath $latestPath)) {
        $pointer = Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json
        $ManifestPath = [string]$pointer.manifest
    }
    $isNewNetwork = $Fresh -or -not $ManifestPath
    $miningSettings = [PSCustomObject]@{ bind_ip = '127.0.0.1'; share_difficulty = [double]65536; advertise = ''; password_file = '' }
    if (-not $isNewNetwork) {
        if ($PSBoundParameters.ContainsKey('Config')) { throw 'A saved testnet retains its configuration. Omit -Config to resume it, or use -Fresh for a separate network.' }
        $ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
        if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "The saved manifest is missing: $ManifestPath. Use -Fresh to create a separate network." }
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        if ($manifest.schema_version -ne 1 -or @($manifest.nodes).Count -ne 3) { throw 'Unsupported testnet manifest.' }
        if ($PSBoundParameters.ContainsKey('BasePort') -and $BasePort -ne [int]$manifest.base_port) { throw 'A saved testnet retains its ports. Omit -BasePort to restart it, or use -Fresh for a new network.' }
        $BasePort = [int]$manifest.base_port
        if ($manifest.PSObject.Properties.Name -notcontains 'seed_wallets' -or $manifest.seed_wallets -isnot [bool]) { throw 'The saved wallet-seeding setting is missing or invalid.' }
        $savedSeeding = [bool]$manifest.seed_wallets
        if ($PSBoundParameters.ContainsKey('SeedWallets') -and [bool]$SeedWallets -ne $savedSeeding) {
            throw 'A saved testnet retains its wallet-seeding choice. Use Wallet in the app to import a key, or use -Fresh for a new network.'
        }
        if (-not $Executable) { $Executable = [string]$manifest.executable }
        if ($manifest.PSObject.Properties.Name -notcontains 'mining' -or $null -eq $manifest.mining) { throw 'The saved mining settings are missing.' }
        foreach ($settingName in @('bind_ip', 'share_difficulty', 'advertise', 'password_file')) {
            if ($manifest.mining.PSObject.Properties.Name -notcontains $settingName) { throw "The saved mining setting is missing: $settingName" }
        }
        $miningSettings = [PSCustomObject]@{
            bind_ip = [string]$manifest.mining.bind_ip
            share_difficulty = [double]$manifest.mining.share_difficulty
            advertise = [string]$manifest.mining.advertise
            password_file = [string]$manifest.mining.password_file
        }
    }
    $savedMining = $miningSettings | ConvertTo-Json -Compress
    if ($PSBoundParameters.ContainsKey('StratumBindIPAddress')) { $miningSettings.bind_ip = $StratumBindIPAddress }
    if ($PSBoundParameters.ContainsKey('ShareDifficulty')) { $miningSettings.share_difficulty = $ShareDifficulty }
    if ($PSBoundParameters.ContainsKey('StratumAdvertise')) { $miningSettings.advertise = $StratumAdvertise }
    if ($PSBoundParameters.ContainsKey('StratumPasswordFile')) {
        $miningSettings.password_file = if ($StratumPasswordFile) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($StratumPasswordFile) } else { '' }
    }
    Assert-MiningSettings $miningSettings
    if (-not $isNewNetwork -and $savedMining -ne ($miningSettings | ConvertTo-Json -Compress)) {
        foreach ($nodeRecord in $manifest.nodes) {
            if ($null -ne (Get-RecordedProcess $nodeRecord ([string]$manifest.executable))) { throw 'Stop the saved testnet before changing its mining connection settings.' }
        }
    }
    if (-not $Executable) {
        $Executable = Join-Path $PSScriptRoot 'target/release/hashstash.exe'
        if (-not (Test-Path -LiteralPath $Executable)) { $Executable = Join-Path $PSScriptRoot 'bin/hashstash.exe' }
    }
    $Executable = [IO.Path]::GetFullPath($Executable)
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Build the node with cargo build --release --locked, or supply -Executable with its path.' }

    if ($isNewNetwork) {
        $templatePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Config)
        if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) { throw "The genesis configuration template is missing: $templatePath" }
        # Validate before creating any network directory, keys, or databases.
        # The node remains the authority for valid configuration and arithmetic bounds.
        try {
            $configuration = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
            & $Executable network --config $templatePath | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'The node rejected this configuration.' }
        } catch { throw "Invalid genesis configuration template: $($_.Exception.Message)" }
        for ($index = 0; $index -lt 3; $index++) {
            foreach ($offset in 0, 1, 2) { Assert-PortFree ($BasePort + 10 * $index + $offset) }
        }
        $suffix = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $networkDirectory = Join-Path $resolvedDataRoot ('testnet-' + $suffix)
        New-Item -ItemType Directory -Path $networkDirectory | Out-Null
        $networkPath = Join-Path $networkDirectory 'network.json'
        if ($configuration.test_work) { Write-Warning 'Accelerated test issuance: this fixture network is not a production network.' }
        $configuration.network = 'hashstash-local-' + $suffix
        $configuration.genesis_time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1
        Save-JsonAtomic $networkPath $configuration
        $records = @()
        for ($index = 0; $index -lt 3; $index++) {
            $nodeName = 'node-' + ($index + 1)
            $nodeDirectory = Join-Path $networkDirectory $nodeName
            New-Item -ItemType Directory -Path $nodeDirectory | Out-Null
            $keyPath = Join-Path $nodeDirectory 'miner.key'
            & $Executable keygen --out $keyPath | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not create $nodeName's mining key." }
            $publicKey = [string](& $Executable public-key --key $keyPath)
            if ($LASTEXITCODE -ne 0 -or $publicKey -notmatch '^[0-9a-fA-F]{64}$') { throw "Could not read $nodeName's public key." }
            $records += [PSCustomObject]@{
                name = $nodeName; pid = 0; rpc_port = $BasePort + 10 * $index
                p2p_port = $BasePort + 10 * $index + 1; stratum_port = $BasePort + 10 * $index + 2
                public_key = $publicKey; key_file = $keyPath; data_file = (Join-Path $nodeDirectory 'chain.sqlite')
                directory = $nodeDirectory; executable = $Executable; start_time_utc = ''; start_time_ticks = ''
                stdout_file = (Join-Path $nodeDirectory 'stdout.log'); stderr_file = (Join-Path $nodeDirectory 'stderr.log')
            }
        }
        $manifest = [PSCustomObject]@{
            schema_version = 1; directory = $networkDirectory; config = $networkPath; executable = $Executable
            base_port = $BasePort; created_utc = [DateTime]::UtcNow.ToString('o'); chain_id = ''; nodes = $records
            seed_wallets = [bool]$SeedWallets; test_work = [bool]$configuration.test_work
            mining = $miningSettings
        }
        $ManifestPath = Join-Path $networkDirectory 'manifest.json'
        Save-JsonAtomic $ManifestPath $manifest
        Save-JsonAtomic $latestPath ([PSCustomObject]@{ manifest = $ManifestPath })
    } else {
        if (-not (Test-Path -LiteralPath $manifest.config -PathType Leaf)) { throw 'The saved network configuration is missing; its identity must not be replaced.' }
        foreach ($nodeRecord in $manifest.nodes) {
            if (-not (Test-Path -LiteralPath $nodeRecord.key_file -PathType Leaf)) { throw "$($nodeRecord.name)'s mining-key backup is missing; existing keys are never replaced." }
            $storedPublicKey = [string](& $Executable public-key --key $nodeRecord.key_file)
            if ($LASTEXITCODE -ne 0 -or $storedPublicKey -ne [string]$nodeRecord.public_key) { throw "$($nodeRecord.name)'s key file does not match its saved mining recipient." }
            $running = Get-RecordedProcess $nodeRecord ([string]$manifest.executable)
            if ($null -ne $running) {
                if (-not [String]::Equals($Executable, [string]$manifest.executable, [StringComparison]::OrdinalIgnoreCase)) { throw 'Stop the saved testnet before changing its executable.' }
            } else {
                foreach ($port in $nodeRecord.rpc_port, $nodeRecord.p2p_port, $nodeRecord.stratum_port) { Assert-PortFree ([int]$port) }
            }
        }
    }

    $manifest | Add-Member -NotePropertyName mining -NotePropertyValue $miningSettings -Force
    $seedOnLaunch = if ($isNewNetwork) { [bool]$SeedWallets } else { $savedSeeding }
    foreach ($nodeRecord in $manifest.nodes) {
        if ($null -ne (Get-RecordedProcess $nodeRecord ([string]$manifest.executable))) { continue }
        $stratumAddress = if ($nodeRecord.name -eq $manifest.nodes[0].name) { $miningSettings.bind_ip } else { '127.0.0.1' }
        $arguments = @(
            'run', '--config', (Quote-ProcessArgument ([string]$manifest.config)),
            '--data', (Quote-ProcessArgument ([string]$nodeRecord.data_file)),
            '--miner', [string]$nodeRecord.public_key,
            '--rpc', "127.0.0.1:$($nodeRecord.rpc_port)",
            '--p2p', "127.0.0.1:$($nodeRecord.p2p_port)",
            '--stratum', (Get-StratumEndpoint $stratumAddress ([int]$nodeRecord.stratum_port))
        )
        if ($nodeRecord.name -eq $manifest.nodes[0].name) {
            $arguments += @('--stratum-share-difficulty', ([double]$miningSettings.share_difficulty).ToString('R', [Globalization.CultureInfo]::InvariantCulture))
            if ($miningSettings.advertise) { $arguments += @('--stratum-advertise', (Quote-ProcessArgument ([string]$miningSettings.advertise))) }
            if ($miningSettings.password_file) { $arguments += @('--stratum-password-file', (Quote-ProcessArgument ([string]$miningSettings.password_file))) }
        }
        if ($seedOnLaunch) { $arguments += @('--wallet-key', (Quote-ProcessArgument ([string]$nodeRecord.key_file))) }
        foreach ($peerRecord in $manifest.nodes) {
            if ($peerRecord.name -ne $nodeRecord.name) { $arguments += @('--peer', "127.0.0.1:$($peerRecord.p2p_port)") }
        }
        $nodeProcess = Start-Process -FilePath $Executable -ArgumentList ($arguments -join ' ') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $nodeRecord.stdout_file -RedirectStandardError $nodeRecord.stderr_file -PassThru
        $startedProcesses += $nodeProcess
        $Executable = Get-LaunchedProcessPath $nodeProcess
        $nodeRecord.pid = $nodeProcess.Id
        $nodeRecord.executable = $Executable
        $nodeRecord.start_time_utc = $nodeProcess.StartTime.ToUniversalTime().ToString('o')
        $nodeRecord.start_time_ticks = $nodeProcess.StartTime.ToUniversalTime().Ticks.ToString()
        $startedHere += $nodeRecord
        $manifest.executable = $Executable
        Save-JsonAtomic $ManifestPath $manifest
    }
    foreach ($nodeRecord in $manifest.nodes) {
        $status = Wait-NodeReady $nodeRecord $Executable
        if ($manifest.chain_id -and $manifest.chain_id -ne [string]$status.chain_id) { throw 'A node returned a different chain identity from the saved testnet.' }
        $manifest.chain_id = [string]$status.chain_id
    }
    Save-JsonAtomic $ManifestPath $manifest
    # Process readiness does not require fork choice to have selected one common tip.
    # In particular, startup mining may be what resolves an honest equal-work fork.
    if ($InitialBlocks -eq 0) { [void](Wait-TestnetConvergence $manifest.nodes $Executable 3) }
    if ($InitialBlocks -gt 0) {
        foreach ($nodeRecord in $manifest.nodes) {
            & $Executable mine --url "http://127.0.0.1:$($nodeRecord.rpc_port)/rpc" --count $InitialBlocks
            if ($LASTEXITCODE -ne 0) { throw "Initial test mining failed for $($nodeRecord.name)." }
            [void](Wait-TestnetConvergence $manifest.nodes $Executable)
        }
        [void](Wait-TestnetConvergence $manifest.nodes $Executable)
    }
    Write-Host ('Testnet directory: ' + $manifest.directory)
    Write-Host ('Manifest: ' + $ManifestPath)
    foreach ($nodeRecord in $manifest.nodes) {
        Write-Host ('{0}: http://127.0.0.1:{1}/  PID {2}  mining recipient {3}' -f $nodeRecord.name, $nodeRecord.rpc_port, $nodeRecord.pid, $nodeRecord.public_key)
    }
    Write-Host ('Restart this network: .\Start-Testnet.ps1 -ManifestPath "{0}"' -f $ManifestPath)
    Write-Host ('Stop this network: .\Stop-Testnet.ps1 -ManifestPath "{0}"' -f $ManifestPath)
    Write-Host 'Open Wallet to create or import a private key, or add a watch-only account.'
    Write-Host 'Use -Fresh to create a separate network with new mining keys and databases. Saved networks are preserved.'
    if (-not $NoBrowser) {
        try { Start-Process "http://127.0.0.1:$($manifest.nodes[0].rpc_port)/" }
        catch { Write-Warning 'The nodes are running. Open one of the dashboard URLs above in your browser.' }
    }
} catch {
    foreach ($launchedProcess in $startedProcesses) {
        try {
            if (-not $launchedProcess.HasExited) {
                $launchedProcess.Kill()
                [void]$launchedProcess.WaitForExit(3000)
            }
        } catch { }
    }
    throw
} finally {
    if ($null -ne $launchLock) { $launchLock.Dispose() }
}
