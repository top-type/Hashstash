[CmdletBinding()]
param([ValidateRange(1024,65473)][int]$BasePort = 28280, [string]$Directory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$auditRoot = if ($Directory) { [IO.Path]::GetFullPath($Directory) } else { Join-Path $repository 'work/wallet-launcher-audit' }
$auditDirectory = Join-Path $auditRoot ('run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $auditDirectory -Force | Out-Null
$executable = Join-Path $repository 'target/release/hashstash.exe'
$index = 0
foreach ($name in @('test_wallet_launcher', 'test_fresh_wallet_launcher')) {
    # Preserve the maintained suite's assertions; only relocate its fixtures.
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot ($name + '.ps1')) -Raw
    $source = $source.Replace('$repository = Split-Path -Parent $PSScriptRoot', ('$repository = ' + "'" + $repository.Replace("'", "''") + "'"))
    $fixture = Join-Path $auditDirectory ($name + '-' + [Guid]::NewGuid().ToString('N'))
    $replacement = '$fixture = ' + "'" + $fixture.Replace("'", "''") + "'"
    $source = [regex]::Replace($source, '(?m)^\$fixture = .*$', [System.Text.RegularExpressions.MatchEvaluator]{param($match) $replacement})
    $copy = Join-Path $auditDirectory ($name + '.isolated.ps1')
    [IO.File]::WriteAllText($copy, $source, [Text.UTF8Encoding]::new($false))
    $parameters = @{Executable=$executable; BasePort=($BasePort + $index * 40); Report=(Join-Path $auditDirectory ($name.Substring(5) + '.json'))}
    if ($name -eq 'test_wallet_launcher') { $parameters.Config = Join-Path $repository 'config/devnet.json' }
    & $copy @parameters
    $index++
}
