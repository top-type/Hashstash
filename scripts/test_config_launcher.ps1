[CmdletBinding()]
param(
    [string]$Executable,
    [string]$Config,
    [ValidateRange(1024,65513)][int]$BasePort = 23180,
    [string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent (Split-Path -Parent $repository)
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash.exe' }
if (-not $Config) { $Config = Join-Path $repository 'config/slow-testnet.json' }
if (-not $Report) { $Report = Join-Path $repository 'work/config-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$Config = (Resolve-Path -LiteralPath $Config).Path
$fixture = Join-Path $workspace ('work/config-launcher-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$start = Join-Path $repository 'Start-Testnet.ps1'
$stop = Join-Path $repository 'Stop-Testnet.ps1'
$manifests = [Collections.Generic.List[string]]::new()
$checks = [Collections.Generic.List[string]]::new()
$timer = [Diagnostics.Stopwatch]::StartNew()
$reportValue = [ordered]@{passed=$false;node_sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant();template=$Config;directory=$fixture;checks=$checks;processes_stopped=$false}
$userPointer = Join-Path $repository 'data/testnet-latest.json'
$pointerBefore = if (Test-Path -LiteralPath $userPointer) {(Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash} else {$null}

function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) {throw $Description}
    $checks.Add($Description)
    Write-Host ('PASS: ' + $Description)
}
function Expect-Rejection([scriptblock]$Action, [string]$Pattern) {
    $message = $null
    try {& $Action} catch {$message = $_.Exception.Message}
    Check ($null -ne $message -and $message -match $Pattern) ('Rejected launch: ' + $Pattern)
}
function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 32),[Text.UTF8Encoding]::new($false))
}
function Load-Manifest([string]$Root) {
    $path = [string](Get-Content -LiteralPath (Join-Path $Root 'testnet-latest.json') -Raw|ConvertFrom-Json).manifest
    if (-not $manifests.Contains($path)) {$manifests.Add($path)}
    return Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
}
function Genesis-Parameters([string]$Path) {
    $value = Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
    $value.PSObject.Properties.Remove('network')
    $value.PSObject.Properties.Remove('genesis_time')
    return $value|ConvertTo-Json -Depth 32 -Compress
}
function Sessions($Manifest) {
    # Server wallets are listed only to a caller presenting the node's session token.
    return @($Manifest.nodes|ForEach-Object {Invoke-RestMethod -Uri "http://127.0.0.1:$($_.rpc_port)/api/session" -Headers @{'X-Hashstash-Token'=(Get-Content -LiteralPath ([IO.Path]::ChangeExtension([string]$_.data_file, 'session-token')) -Raw)} -TimeoutSec 5})
}
function Statuses($Manifest) {
    return @($Manifest.nodes|ForEach-Object {
        $result = Invoke-RestMethod -Uri "http://127.0.0.1:$($_.rpc_port)/rpc" -Method Post -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -TimeoutSec 5
        $result.result
    })
}
function Saved-Files($Manifest) {
    return @(@($Manifest.config) + @($Manifest.nodes.key_file)|ForEach-Object {(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}) -join ','
}

try {
    $invalidRoot = Join-Path $fixture 'invalid'
    $missing = Join-Path $fixture 'missing.json'
    Expect-Rejection {& $start -Fresh -DataRoot $invalidRoot -BasePort $BasePort -Executable $Executable -Config $missing -NoBrowser} 'configuration template is missing'
    $badJson = Join-Path $fixture 'malformed.json'
    [IO.File]::WriteAllText($badJson,'{"broken":',[Text.UTF8Encoding]::new($false))
    Expect-Rejection {& $start -Fresh -DataRoot $invalidRoot -BasePort $BasePort -Executable $Executable -Config $badJson -NoBrowser} 'Invalid genesis configuration template'
    $invalid = Get-Content -LiteralPath $Config -Raw|ConvertFrom-Json
    $invalid.initial.interval = 0
    $badBounds = Join-Path $fixture 'invalid-bounds.json'; Write-Json $badBounds $invalid
    Expect-Rejection {& $start -Fresh -DataRoot $invalidRoot -BasePort $BasePort -Executable $Executable -Config $badBounds -NoBrowser} 'Invalid genesis configuration template'
    Check (@(Get-ChildItem -LiteralPath $invalidRoot -Directory).Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $invalidRoot 'testnet-latest.json'))) 'Rejected templates create no network directories, keys, databases, or saved pointer'

    $defaultRoot = Join-Path $fixture 'default'
    & $start -Fresh -DataRoot $defaultRoot -BasePort $BasePort -Executable $Executable -NoBrowser
    $default = Load-Manifest $defaultRoot; $defaultPath = $manifests[0]
    Check ((Genesis-Parameters $default.config) -eq (Genesis-Parameters (Join-Path $repository 'config/testnet.json'))) 'Omitting Config retains the existing default genesis parameters'
    Check (-not $default.seed_wallets -and @(Sessions $default|Where-Object {$_.wallet_mode -ne 'none' -or $_.wallets.Count -ne 0}).Count -eq 0) 'Default launcher still starts three empty wallet managers'
    & $stop -ManifestPath $defaultPath

    $customRoot = Join-Path $fixture 'custom'
    $template = Join-Path $fixture 'custom template.json'
    Copy-Item -LiteralPath $Config -Destination $template
    $templateBefore = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
    # No -Fresh is necessary when a data directory has no saved network.
    Push-Location -LiteralPath $fixture
    try {& $start -DataRoot $customRoot -BasePort $BasePort -Executable $Executable -Config 'custom template.json' -SeedWallets -NoBrowser}
    finally {Pop-Location}
    $custom = Load-Manifest $customRoot; $customPath = $manifests[1]
    $status = @(Statuses $custom); $sessions = @(Sessions $custom)
    Check ((Genesis-Parameters $custom.config) -eq (Genesis-Parameters $template)) 'A relative custom template path with spaces resolves against the caller and supplies the new genesis'
    Check ((Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash -eq $templateBefore) 'Launching never rewrites the source template'
    Check (@($status|Where-Object {$_.chain_id -ne $custom.chain_id -or $_.height -ne 0 -or $_.issued -ne '0'}).Count -eq 0) 'All three custom nodes start on one empty genesis'
    $expectedSettings = (Get-Content -LiteralPath $template -Raw|ConvertFrom-Json).initial
    $settingsMatch = $true
    foreach ($nodeStatus in $status) {
        foreach ($property in $expectedSettings.PSObject.Properties) {
            $settingsMatch = $settingsMatch -and $nodeStatus.settings.PSObject.Properties.Name.Contains($property.Name) -and [string]$nodeStatus.settings.($property.Name) -eq [string]$property.Value
        }
    }
    Check $settingsMatch 'Node status exposes the selected genesis timing and settings'
    $seeded = $custom.seed_wallets
    for ($index=0;$index -lt 3;$index++) {$seeded=$seeded -and $sessions[$index].wallet_mode -eq 'hot' -and $sessions[$index].public_key -eq $custom.nodes[$index].public_key}
    Check $seeded 'Custom genesis preserves explicit mining-wallet seeding'
    $identity = $custom.chain_id; $savedFiles = Saved-Files $custom; $manifestHash = (Get-FileHash -LiteralPath $customPath -Algorithm SHA256).Hash
    $selectedWallets = @($sessions.wallet_id) -join ','
    Expect-Rejection {& $start -ManifestPath $customPath -DataRoot $customRoot -Executable $Executable -Config $custom.config -NoBrowser} 'saved testnet retains its configuration'
    Expect-Rejection {& $start -DataRoot $customRoot -Executable $Executable -Config $template -NoBrowser} 'saved testnet retains its configuration'
    Check ((Get-FileHash -LiteralPath $customPath -Algorithm SHA256).Hash -eq $manifestHash -and (Saved-Files $custom) -eq $savedFiles) 'Rejected overrides preserve the manifest, configuration, and mining keys'
    Check (@(Statuses $custom|Where-Object {$_.chain_id -ne $identity}).Count -eq 0) 'Rejected overrides do not interrupt the running network'
    & $stop -ManifestPath $customPath
    # Make the original template unavailable: resume must use the saved copy.
    Rename-Item -LiteralPath $template -NewName 'template no longer available.json'
    & $start -ManifestPath $customPath -DataRoot $customRoot -Executable $Executable -NoBrowser
    $custom = Load-Manifest $customRoot
    Check ($custom.chain_id -eq $identity -and (Saved-Files $custom) -eq $savedFiles) 'Restart uses the saved genesis and preserves every mining key'
    Check ((@(Sessions $custom).wallet_id -join ',') -eq $selectedWallets) 'Restart preserves all three selected wallets'
    & $stop -ManifestPath $customPath
    & $start -DataRoot $customRoot -Executable $Executable -NoBrowser
    $custom = Load-Manifest $customRoot
    Check ($custom.chain_id -eq $identity -and (Saved-Files $custom) -eq $savedFiles) 'Latest-pointer resume also uses the saved genesis without the template'
    $reportValue.passed = $true
} finally {
    foreach ($path in $manifests) {& $stop -ManifestPath $path}
    $allStopped = $true
    foreach ($path in $manifests) {
        $saved = Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        foreach ($record in $saved.nodes) {
            $candidate = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
            if ($candidate -and $candidate.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$record.start_time_ticks) {$allStopped=$false}
        }
    }
    $reportValue.processes_stopped = $allStopped
    $pointerAfter = if (Test-Path -LiteralPath $userPointer) {(Get-FileHash -LiteralPath $userPointer -Algorithm SHA256).Hash} else {$null}
    $reportValue.user_pointer_preserved = $pointerBefore -eq $pointerAfter
    $timer.Stop(); $reportValue.elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds,3)
    [IO.File]::WriteAllText($Report,($reportValue|ConvertTo-Json -Depth 16)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
if (-not $reportValue.processes_stopped -or -not $reportValue.user_pointer_preserved) {throw 'Process or user pointer preservation failed'}
Write-Host ('Saved ' + $Report)
