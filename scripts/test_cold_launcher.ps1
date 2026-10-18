[CmdletBinding()]
param(
    [string]$Executable,
    [ValidateRange(1024,65535)][int]$Port = 21980,
    [string]$Report
)
# Start-ColdWallet.ps1 token hand-off: the launcher chooses the session token,
# passes it only through the signer's environment and prints it only in the
# launch URL's fragment; the signer never serves it and requires it for every
# POST. Uses a public fixture chain ID and stops only the signer it started.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $repository 'target/release/hashstash-cold.exe' }
if (-not $Report) { $Report = Join-Path $repository 'work/cold-launcher-report.json' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Report))) | Out-Null
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$checks = [Collections.Generic.List[string]]::new()
$result = [ordered]@{ passed=$false; signer_sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant(); port=$Port; checks=$checks; owned_process_stopped=$false }
$signer = $null
Add-Type -AssemblyName System.Net.Http
$client = [Net.Http.HttpClient]::new()

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

try {
    $launcher = Join-Path $repository 'Start-ColdWallet.ps1'
    $output = @(& $launcher -Executable $Executable -ChainId ('27' * 32) -Port $Port -NoBrowser 6>&1 | ForEach-Object { [string]$_ })
    $launch = @($output | Where-Object { $_ -like 'Cold signer: *' })
    Check ($launch.Count -eq 1) 'The launcher prints one launch address'
    if ($launch[0] -notmatch '^Cold signer: (http://127\.0\.0\.1:(\d+))/#token=([0-9a-f]{64})$') { throw "Unexpected launch address: $($launch[0])" }
    $origin = $Matches[1]
    $token = $Matches[3]
    Check ([int]$Matches[2] -eq $Port) 'The launch address names the requested loopback port and a 64-hex token only in its fragment'
    $notice = @($output | Where-Object { $_ -match 'Process ID: (\d+)\.' })
    if ($notice.Count -ne 1) { throw 'The launcher did not report the signer process.' }
    $signer = Get-Process -Id ([int]$Matches[1])
    Check ($signer.Path -eq $Executable) 'The reported process is the selected signer executable'
    $commandLine = [string](Get-CimInstance Win32_Process -Filter "ProcessId=$($signer.Id)").CommandLine
    Check (-not $commandLine.Contains($token)) 'The token never appears on the signer command line'
    Check ($null -eq $env:HASHSTASH_COLD_TOKEN) 'The launcher leaves no token in its own environment'
    $session = Invoke-RestMethod -Uri ($origin + '/api/session') -TimeoutSec 5
    Check ($session.format -eq 'hashstash-cold-v1' -and -not ($session | ConvertTo-Json -Depth 10 -Compress).Contains($token)) 'The session endpoint answers without serving the token'
    Check ((Post-Status $origin '/api/lock' $null) -eq 403) 'A POST without the token is refused'
    Check ((Post-Status $origin '/api/lock' ('0' * 64)) -eq 403) 'A POST with another token is refused'
    Check ((Post-Status $origin '/api/lock' $token) -eq 200) 'The launch token authorizes the signer'
    $result.passed = $true
} finally {
    $client.Dispose()
    if ($signer) {
        Stop-Process -Id $signer.Id -ErrorAction SilentlyContinue
        $result.owned_process_stopped = $signer.WaitForExit(10000)
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding utf8
}
