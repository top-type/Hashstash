param(
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'data'),
    [int]$RpcPort = 18480,
    [int]$PeerPort = 18481,
    [int]$MiningPort = 18482,
    [switch]$SeedWallets
)
$ErrorActionPreference = 'Stop'
$hashstashExe = Join-Path $PSScriptRoot 'target/release/hashstash.exe'
if (-not (Test-Path -LiteralPath $hashstashExe)) {
    $hashstashExe = Join-Path $PSScriptRoot 'bin/hashstash.exe'
}
if (-not (Test-Path -LiteralPath $hashstashExe)) {
    throw 'Build the node with cargo build --release --locked first.'
}
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
$networkFile = Join-Path $DataDirectory 'network.json'
$keyFile = Join-Path $DataDirectory 'miner.key'
$databaseFile = Join-Path $DataDirectory 'chain.sqlite'
if (-not (Test-Path -LiteralPath $networkFile)) {
    & $hashstashExe init --config $networkFile
    if ($LASTEXITCODE -ne 0) { throw 'Network configuration could not be created.' }
}
if (-not (Test-Path -LiteralPath $keyFile)) {
    & $hashstashExe keygen --out $keyFile
    if ($LASTEXITCODE -ne 0) { throw 'Miner key could not be created.' }
}
$minerPublicKey = & $hashstashExe public-key --key $keyFile
if ($LASTEXITCODE -ne 0) { throw 'Miner key could not be read.' }
Write-Host 'Starting your local Hashstash development network. Stop with Ctrl+C.'
Write-Host ("Browser wallet: http://127.0.0.1:$RpcPort/")
Write-Host ('In a second terminal: & "{0}" mine --url http://127.0.0.1:{1}/rpc --count 12' -f $hashstashExe,$RpcPort)
$arguments = @('run', '--config', $networkFile, '--data', $databaseFile, '--miner', $minerPublicKey,
    '--rpc', "127.0.0.1:$RpcPort", '--p2p', "127.0.0.1:$PeerPort", '--stratum', "127.0.0.1:$MiningPort")
if ($SeedWallets) { $arguments += @('--wallet-key', $keyFile) }
Write-Host ('Mining recipient: ' + $minerPublicKey)
& $hashstashExe @arguments
if ($LASTEXITCODE -ne 0) { throw 'Hashstash exited with an error.' }

