# Read-only regression check. Execute only the launcher's protocol guard;
# never invoke the launcher, a node, a miner, a rental, or a process stop.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'Start-RentalTest.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Rental launcher has parse errors.' }
$guards = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text -match '^if \(\$configuration\.protocol_version '
}, $true))
if ($guards.Count -ne 1) { throw 'Expected exactly one rental protocol guard.' }
$guard = [ScriptBlock]::Create($guards[0].Extent.Text)
$currentVersion = $null
foreach ($preset in 'devnet.json', 'testnet.json', 'slow-testnet.json') {
    $configuration = Get-Content -LiteralPath (Join-Path $repository ('config/' + $preset)) -Raw | ConvertFrom-Json
    if ($null -eq $currentVersion) { $currentVersion = [int]$configuration.protocol_version }
    elseif ($configuration.protocol_version -ne $currentVersion) { throw 'Current presets disagree on protocol version.' }
    & $guard
}
foreach ($version in @(0, ($currentVersion - 1), ($currentVersion + 1)) | Select-Object -Unique) {
    $configuration = [PSCustomObject]@{ protocol_version = $version }
    $rejected = $false
    try { & $guard } catch { $rejected = $true }
    if (-not $rejected) { throw "Rental guard accepted unsupported protocol $version." }
}
Write-Output 'Rental protocol guard matches all current presets; historical and unknown protocols rejected. No services started.'
