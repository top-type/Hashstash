# Read-only regression check: validate presets and reject invalid configuration.
# This never invokes the launcher, starts services, creates keys or submits work.
[CmdletBinding()]
param([string]$Executable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash.exe' }
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'Start-RentalTest.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Rental launcher has parse errors.' }
$source = $ast.Extent.Text
$validation = $source.IndexOf('& $Executable network --config $configPath')
$keyCreation = $source.IndexOf('& $Executable keygen')
if ($validation -lt 0 -or $validation -ge $keyCreation) { throw 'The rental configuration must be validated before keys or services are created.' }
$identities = @()
foreach ($preset in 'devnet.json', 'testnet.json', 'slow-testnet.json') {
    $path = Join-Path $repository ('config/' + $preset)
    $identity = & $Executable network --config $path | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $identity.chain_id -notmatch '^[0-9a-f]{64}$') { throw "Invalid preset: $preset" }
    $identities += $identity.chain_id
}
if (@($identities | Select-Object -Unique).Count -ne 3) { throw 'Distinct presets must have distinct identities.' }
$temporary = [IO.Path]::GetTempFileName()
try {
    $configuration = Get-Content -LiteralPath (Join-Path $repository 'config/devnet.json') -Raw | ConvertFrom-Json
    $configuration.initial.interval = 0
    [IO.File]::WriteAllText($temporary, ($configuration | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    $diagnostic = & $Executable network --config $temporary 2>&1
    if ($LASTEXITCODE -eq 0) { throw 'Invalid arithmetic configuration was accepted.' }
} finally { Remove-Item -LiteralPath $temporary }
Write-Output 'Rental configuration validation passes all presets and rejects invalid arithmetic. No services started.'
