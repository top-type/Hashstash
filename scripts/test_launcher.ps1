[CmdletBinding()]
param(
    [string]$Executable = (Join-Path (Split-Path $PSScriptRoot -Parent) 'target/release/hashstash.exe'),
    [string]$DataRoot = (Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'work/audit-fixes-launcher'),
    [ValidateRange(1024, 65513)][int]$BasePort = 20680,
    [string]$ReportPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work/launcher-fix-test-report.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$testDirectory = [IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
$testExecutable = Join-Path $testDirectory ('hashstash-launcher-' + [Guid]::NewGuid().ToString('N') + '.exe')
Copy-Item -LiteralPath ([IO.Path]::GetFullPath($Executable)) -Destination $testExecutable
$launcher = Join-Path $repository 'Start-Testnet.ps1'
$stopper = Join-Path $repository 'Stop-Testnet.ps1'
$manifestPath = $null
$isolatedProcesses = @()
$startedAt = [DateTime]::UtcNow
$checks = [Collections.Generic.List[object]]::new()
$passed = $false
$failure = $null

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Call-Node($Record, [string]$Method, $Parameters = @{}) {
    $body = @{ jsonrpc = '2.0'; id = 1; method = $Method; params = $Parameters } | ConvertTo-Json -Compress -Depth 12
    $reply = Invoke-RestMethod -Uri "http://127.0.0.1:$($Record.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 5
    if ($reply.PSObject.Properties.Name -contains 'error') { throw ($reply.error | ConvertTo-Json -Compress) }
    return $reply.result
}

function Read-Statuses($Records) {
    return @($Records | ForEach-Object { Call-Node $_ 'status' })
}

function Wait-Statuses($Records, [bool]$Converge) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $states = @(Read-Statuses $Records)
            if ($states.Count -eq 3 -and (-not $Converge -or @($states.tip | Select-Object -Unique).Count -eq 1)) { return $states }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    throw 'The isolated test nodes did not reach the expected readiness/convergence state.'
}

function Stop-Isolated {
    foreach ($process in $script:isolatedProcesses) {
        if (-not $process.HasExited) {
            $process.Kill()
            Assert-True ($process.WaitForExit(10000)) 'An isolated node did not exit.'
        }
        $process.Dispose()
    }
    $script:isolatedProcesses = @()
}

function Make-EqualWorkForks($Manifest, [string]$Label) {
    foreach ($record in $Manifest.nodes) {
        $arguments = @(
            'run', '--config', ('"' + $Manifest.config + '"'),
            '--data', ('"' + $record.data_file + '"'), '--miner', $record.public_key,
            '--rpc', "127.0.0.1:$($record.rpc_port)",
            '--p2p', "127.0.0.1:$($record.p2p_port)",
            '--stratum', "127.0.0.1:$($record.stratum_port)"
        )
        $process = Start-Process -FilePath $testExecutable -ArgumentList ($arguments -join ' ') -WorkingDirectory $repository -WindowStyle Hidden -RedirectStandardOutput (Join-Path $record.directory "$Label.stdout.log") -RedirectStandardError (Join-Path $record.directory "$Label.stderr.log") -PassThru
        $script:isolatedProcesses += $process
    }
    [void](Wait-Statuses $Manifest.nodes $false)
    foreach ($record in $Manifest.nodes) { [void](Call-Node $record 'mine' @{ count = 1 }) }
    $states = @(Read-Statuses $Manifest.nodes)
    Assert-True (@($states.tip | Select-Object -Unique).Count -eq 3) 'Isolated miners did not create three distinct forks.'
    Assert-True (@($states.height | Select-Object -Unique).Count -eq 1) 'Isolated forks have different heights.'
    $blocks = @($Manifest.nodes | ForEach-Object { Call-Node $_ 'getblock' })
    Assert-True (@($blocks.header.bits | Select-Object -Unique).Count -eq 1) 'Isolated forks have different proof-of-work targets.'
    Assert-True (@($blocks | ForEach-Object { ($_.header.previous -join ',') } | Select-Object -Unique).Count -eq 1) 'Isolated forks do not share the same parent.'
    Stop-Isolated
    return $states
}

try {
    & $launcher -Fresh -DataRoot $testDirectory -BasePort $BasePort -Executable $testExecutable -NoBrowser
    $pointer = Get-Content -LiteralPath (Join-Path $testDirectory 'testnet-latest.json') -Raw | ConvertFrom-Json
    $manifestPath = [string]$pointer.manifest
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $identity = [string]$manifest.chain_id
    $publicKeys = @($manifest.nodes.public_key)
    $initial = @(Wait-Statuses $manifest.nodes $true)
    Assert-True (@($initial.height | Select-Object -Unique).Count -eq 1 -and $initial[0].height -eq 0) 'Fresh launcher network was not at genesis.'
    & $stopper -ManifestPath $manifestPath

    $forks = @(Make-EqualWorkForks $manifest 'ordinary-fork')
    $restartAt = [DateTime]::UtcNow
    & $launcher -ManifestPath $manifestPath -DataRoot $testDirectory -Executable $testExecutable -NoBrowser
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $ready = @(Read-Statuses $manifest.nodes)
    Assert-True (@($ready.tip | Select-Object -Unique).Count -eq 3) 'Restart unexpectedly changed equal-work fork choice.'
    Assert-True ((($ready.tip | Sort-Object) -join ',') -eq (($forks.tip | Sort-Object) -join ',')) 'Restart failed to preserve saved competing tips.'
    foreach ($record in $manifest.nodes) { Assert-True ($null -ne (Get-Process -Id $record.pid -ErrorAction SilentlyContinue)) 'Launcher terminated an otherwise ready node.' }
    $checks.Add(@{ name = 'equal_work_restart_keeps_ready_nodes_running'; passed = $true; height = $ready[0].height; distinct_tips = 3; seconds = [Math]::Round(([DateTime]::UtcNow - $restartAt).TotalSeconds, 3) })
    [void](Call-Node $manifest.nodes[0] 'mine' @{ count = 1 })
    $resolved = @(Wait-Statuses $manifest.nodes $true)
    Assert-True (@($resolved.state_root | Select-Object -Unique).Count -eq 1) 'Fork resolution has inconsistent state commitments.'
    $checks.Add(@{ name = 'additional_work_resolves_restarted_forks'; passed = $true; height = $resolved[0].height; tip = $resolved[0].tip; state_root = $resolved[0].state_root })
    & $stopper -ManifestPath $manifestPath

    $forks = @(Make-EqualWorkForks $manifest 'initial-blocks-fork')
    & $launcher -ManifestPath $manifestPath -DataRoot $testDirectory -Executable $testExecutable -InitialBlocks 1 -NoBrowser
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $initialized = @(Wait-Statuses $manifest.nodes $true)
    Assert-True ($initialized[0].height -eq ($forks[0].height + 3)) 'InitialBlocks did not mine one block per node after restart.'
    Assert-True (@($initialized.state_root | Select-Object -Unique).Count -eq 1) 'InitialBlocks fork resolution has inconsistent state commitments.'
    Assert-True ($manifest.chain_id -eq $identity) 'Launcher replaced the existing network identity.'
    Assert-True ((($manifest.nodes.public_key) -join ',') -eq ($publicKeys -join ',')) 'Launcher replaced an existing wallet identity.'
    $checks.Add(@{ name = 'initial_blocks_run_before_requiring_tip_convergence'; passed = $true; initial_fork_height = $forks[0].height; final_height = $initialized[0].height; tip = $initialized[0].tip; identity_preserved = $true; wallets_preserved = $true })
    $passed = $true
} catch {
    $failure = $_.Exception.Message
    throw
} finally {
    Stop-Isolated
    if ($manifestPath) { & $stopper -ManifestPath $manifestPath }
    $launcherNodesStopped = $true
    if ($manifestPath) {
        $saved = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        foreach ($record in $saved.nodes) {
            $candidate = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
            if ($candidate -and $candidate.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$record.start_time_ticks -and $candidate.Path -eq $testExecutable) { $launcherNodesStopped = $false }
        }
    }
    $report = @{
        passed = $passed; started_utc = $startedAt.ToString('o'); finished_utc = [DateTime]::UtcNow.ToString('o')
        duration_seconds = [Math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
        executable_sha256 = (Get-FileHash -LiteralPath $testExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
        manifest = $manifestPath; base_port = $BasePort; isolated_processes_stopped = ($isolatedProcesses.Count -eq 0); launcher_nodes_stopped = $launcherNodesStopped
        checks = @($checks.ToArray()); error = $failure
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ReportPath))) | Out-Null
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($ReportPath), ($report | ConvertTo-Json -Depth 16) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

Write-Host "Launcher regression passed. Report: $ReportPath"
