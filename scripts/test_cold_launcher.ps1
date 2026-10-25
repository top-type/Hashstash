[CmdletBinding()]
param(
    [string]$Executable,
    [ValidateRange(1024,65535)][int]$Port = 21980,
    [string]$Report,
    # Check only the launcher's crash-report exclusion, which needs no signer.
    [switch]$RegistryOnly
)
# Start-ColdWallet.ps1 token hand-off: the launcher chooses the session token,
# passes it only through the signer's environment and prints it only in the
# launch URL's fragment; the signer never serves it and requires it for every
# POST. Uses a public fixture chain ID and stops only the signer it started:
# any process of the selected executable that was not running before the
# launch, even when the launcher fails after starting it.
# The launcher's Windows Error Reporting exclusion is checked under a test key
# of this account, removed afterwards, never the real ExcludedApplications key.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $repository 'Start-ColdWallet.ps1'
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash-cold.exe' }
if (-not $Report) { $Report = Join-Path $repository 'work/cold-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$checks = [Collections.Generic.List[string]]::new()
$result = [ordered]@{ passed=$false; signer_sha256=$null; port=$Port; checks=$checks; owned_processes=0; owned_process_stopped=$false; test_key_removed=$false }
$signer = $null
$running = $null
$client = $null
$testRoot = 'Software\Hashstash-launcher-test-' + [Guid]::NewGuid().ToString('N')
$testKey = $testRoot + '\ExcludedApplications'
Add-Type -AssemblyName System.Net.Http

function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw $Description }
    $checks.Add($Description)
    Write-Host ('PASS: ' + $Description)
}
function Post-Status([string]$Origin, [string]$Path, [string]$Token) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $Origin + $Path)
    [void]$request.Headers.TryAddWithoutValidation('Origin', $Origin)
    if ($Token) { [void]$request.Headers.TryAddWithoutValidation('X-Hashstash-Cold-Token', $Token) }
    $request.Content = [Net.Http.StringContent]::new('{}', [Text.Encoding]::UTF8, 'application/json')
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    try { return [int]$response.StatusCode } finally { $response.Dispose(); $request.Dispose() }
}

function Get-Signer {
    $name = [IO.Path]::GetFileNameWithoutExtension($Executable)
    @(Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq $Executable } catch { $false } })
}
function Test-Exclusion([string]$Name) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey)
    if (-not $key) { return $false }
    try { return ($key.GetValueNames() -contains $Name) -and $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$key.GetValue($Name) -eq 1 }
    finally { $key.Dispose() }
}

try {
    # The launcher's own registration function, taken from its source.
    $syntax = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$null, [ref]$null)
    $definition = $syntax.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Register-CrashReportExclusion' }, $true)
    if (-not $definition) { throw 'The launcher defines no crash-report exclusion.' }
    . ([ScriptBlock]::Create($definition.Extent.Text))
    $existing = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
    try {
        $existing.SetValue('other-program.exe', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $existing.SetValue('hashstash-cold.exe', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally { $existing.Dispose() }
    Check ((Register-CrashReportExclusion 'hashstash-cold.exe' $testKey) -eq 'added' -and (Test-Exclusion 'hashstash-cold.exe')) 'A disabled exclusion is set to DWORD 1'
    Check ((Register-CrashReportExclusion 'hashstash-cold.exe' $testKey) -eq 'found') 'An existing exclusion is reported, not rewritten'
    Check (Test-Exclusion 'other-program.exe') 'Other excluded programs are kept'
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRoot)
    Check ((Register-CrashReportExclusion 'hashstash-cold.exe' $testKey) -eq 'added' -and (Test-Exclusion 'hashstash-cold.exe')) 'A missing key is created with the exclusion'
    if ($RegistryOnly) { $result.passed = $true; return }

    # The launcher's readiness check, taken from its source. Another program
    # can bind the port after the launcher's free-port check; its listener is
    # refused even before it answers, so the token address is never opened.
    $readiness = $syntax.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Wait-SignerReady' }, $true)
    if (-not $readiness) { throw 'The launcher has no readiness check that confirms the listener belongs to the signer.' }
    . ([ScriptBlock]::Create($readiness.Extent.Text))
    $impostor = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $impostor.Start()
    try {
        $impostorPort = ([Net.IPEndPoint]$impostor.LocalEndpoint).Port
        $refusal = { param($Process, [int]$Seconds) try { Wait-SignerReady $Process $impostorPort ([TimeSpan]::FromSeconds($Seconds)); 'ready' } catch { $_.Exception.Message } }
        # A started signer that has not bound the port yet, while this
        # process holds it.
        $starting = [pscustomobject]@{ Id = [int]::MaxValue; HasExited = $false }
        Check ((& $refusal $starting 10) -like "Another program (process ID $PID) is listening on port $impostorPort*") 'A listener another process owns is refused, never taken for the signer'
        # The listener's owner is the signer only if it also answers as one.
        $owner = [pscustomobject]@{ Id = $PID; HasExited = $false }
        Check ((& $refusal $owner 3) -like 'Signer did not become ready*') 'A listener that does not answer as the signer is never ready'
        $exited = [pscustomobject]@{ Id = [int]::MaxValue; HasExited = $true }
        Check ((& $refusal $exited 10) -eq 'Cold signer exited during startup.') 'A signer that exited is reported, whoever holds the port'
    } finally { $impostor.Stop() }

    $Executable = (Resolve-Path -LiteralPath $Executable).Path
    $result.signer_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
    $client = [Net.Http.HttpClient]::new()
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRoot)
    $running = @(Get-Signer | ForEach-Object { $_.Id })
    $output = @(& $launcher -Executable $Executable -ChainId ('27' * 32) -Port $Port -NoBrowser -CrashReportKey $testKey 6>&1 | ForEach-Object { [string]$_ })
    $signerName = [IO.Path]::GetFileName($Executable)
    Check ((Test-Exclusion $signerName) -and @($output | Where-Object { $_ -like "Crash reports: Windows Error Reporting excludes $signerName for this account*added*" }).Count -eq 1) 'The launcher excludes the signer from Windows Error Reporting and says so'
    $launch = @($output | Where-Object { $_ -like 'Cold signer: *' })
    Check ($launch.Count -eq 1) 'The launcher prints one launch address'
    if ($launch[0] -notmatch '^Cold signer: (http://127\.0\.0\.1:(\d+))/#token=([0-9a-f]{64})$') { throw "Unexpected launch address: $($launch[0])" }
    $origin = $Matches[1]
    $token = $Matches[3]
    Check ([int]$Matches[2] -eq $Port) 'The launch address names the requested loopback port and a 64-hex token only in its fragment'
    $notice = @($output | Where-Object { $_ -match 'Process ID: (\d+)\.' })
    if ($notice.Count -ne 1) { throw 'The launcher did not report the signer process.' }
    $signer = Get-Process -Id ([int]$Matches[1])
    Check ($signer.Path -eq $Executable -and $running -notcontains $signer.Id) 'The reported process is a new instance of the selected signer executable'
    $commandLine = [string](Get-CimInstance Win32_Process -Filter "ProcessId=$($signer.Id)").CommandLine
    Check (-not $commandLine.Contains($token)) 'The token never appears on the signer command line'
    Check ($null -eq $env:HASHSTASH_COLD_TOKEN) 'The launcher leaves no token in its own environment'
    $session = Invoke-RestMethod -Uri ($origin + '/api/session') -TimeoutSec 5
    Check ($session.format -eq 'hashstash-cold-v1' -and -not ($session | ConvertTo-Json -Depth 10 -Compress).Contains($token)) 'The session endpoint answers without serving the token'
    $named = @($session.PSObject.Properties.Name | Where-Object { @('chain_id', 'public_key', 'address', 'watch') -contains $_ })
    Check ($named.Count -eq 0) 'Without the token the session endpoint names no network or account'
    $status = Invoke-RestMethod -Uri ($origin + '/api/status') -Method Post -ContentType 'application/json' -Body '{}' -Headers @{ Origin = $origin; 'X-Hashstash-Cold-Token' = $token } -TimeoutSec 5
    Check ($status.chain_id -eq ('27' * 32)) 'The launch token reads the selected network'
    Check ((Post-Status $origin '/api/lock' $null) -eq 403) 'A POST without the token is refused'
    Check ((Post-Status $origin '/api/lock' ('0' * 64)) -eq 403) 'A POST with another token is refused'
    Check ((Post-Status $origin '/api/lock' $token) -eq 200) 'The launch token authorizes the signer'
    $result.passed = $true
} finally {
    if ($client) { $client.Dispose() }
    # The launcher can start the signer and then fail, before the signer it
    # reports is known here; stop whatever this launch started.
    if ($null -ne $running) {
        $owned = @(Get-Signer | Where-Object { $running -notcontains $_.Id })
        $result.owned_processes = $owned.Count
        $stopped = $true
        foreach ($process in $owned) {
            Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
            $stopped = $process.WaitForExit(10000) -and $stopped
        }
        $result.owned_process_stopped = $stopped
    }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRoot, $false)
    $result.test_key_removed = $null -eq [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testRoot)
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding utf8
}
