# Runs one command for a CI step, mirrors its output, and exits with its code.
# When the command fails, each failing Rust test (its name and the first lines
# of its panic) and each compiler error becomes a GitHub annotation. Anyone can
# read annotations through the API, even where a job's log needs a sign-in.
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
)
$log = Join-Path ([IO.Path]::GetTempPath()) ('ci-annotate-' + [Guid]::NewGuid().ToString('N') + '.log')
$writer = [IO.StreamWriter]::new($log)
try {
    & $Command @Arguments 2>&1 | ForEach-Object {
        $line = "$_"
        Write-Output $line
        $writer.WriteLine($line)
    }
    $code = $LASTEXITCODE
} finally {
    $writer.Dispose()
}
if ($code -ne 0) {
    function Escape([string]$text, [bool]$property) {
        $text = $text.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        if ($property) { $text = $text.Replace(':', '%3A').Replace(',', '%2C') }
        return $text
    }
    $lines = [IO.File]::ReadAllLines($log)
    $found = 0
    for ($i = 0; $i -lt $lines.Count -and $found -lt 10; $i++) {
        $title = $null
        if ($lines[$i] -match '^---- (.+) stdout ----$') { $title = $Matches[1] }
        elseif ($lines[$i] -match '^error(\[E\d+\])?: ') { $title = 'compile error' }
        if (-not $title) { continue }
        $body = @($lines[$i..([Math]::Min($i + 12, $lines.Count - 1))] | Where-Object { $_ -and $_ -notmatch '^note: run with' })
        $message = ($body | Select-Object -First 10) -join "`n"
        if ($message.Length -gt 1500) { $message = $message.Substring(0, 1500) }
        Write-Output ('::error title=' + (Escape $title $true) + '::' + (Escape $message $false))
        $found++
    }
    if ($found -eq 0) {
        $tail = ($lines | Select-Object -Last 15) -join "`n"
        Write-Output ('::error title=' + (Escape "$Command failed ($code)" $true) + '::' + (Escape $tail $false))
    }
}
Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
exit $code
