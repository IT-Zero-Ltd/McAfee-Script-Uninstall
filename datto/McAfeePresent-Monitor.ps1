# IT Zero - McAfee consumer present (Datto RMM component monitor)
#
# Create a component with Category: Monitors, Script type: PowerShell, paste this script, and attach
# mcafee_detect.ps1 from the repository's main branch. Optional component variable:
#   GraceHours  (default 72)  how long consumer McAfee may remain after it was first seen before alerting
#
# Behaviour:
#   - No McAfee, managed McAfee/Trellix (out of scope), or removal waiting for a restart -> OK, no alert.
#   - Consumer McAfee present for less than GraceHours since this monitor first saw it -> OK ("pending"),
#     giving the scheduled removal job time to run.
#   - Consumer McAfee still present after GraceHours -> ALERT, with the detection output and the last
#     lines of the removal log as diagnostics.
#   - Detection script missing, modified, or failing -> ALERT.
#
# The "first seen" time is kept in HKLM\SOFTWARE\ITZero\McAfeeRemoval (writable by SYSTEM/admins only)
# and cleared once the device is clean.
#
# When mcafee_detect.ps1 changes in the repository, update $ExpectedSha256 and re-attach the file.

param(
    [string]$PowerShellPath,   # for testing only; normally left empty
    [string]$StateFile,        # for testing only; normally the registry is used
    [string]$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log'
)

$ExpectedSha256 = 'E7959BFC90B2195BE478BBB24D7735D6E5E776A1721BBDA22BEB444D3CD97B1F'
$ScriptName     = 'mcafee_detect.ps1'
$StateKey       = 'HKLM:\SOFTWARE\ITZero\McAfeeRemoval'
$GraceHours     = 72
if ($env:GraceHours -and ($env:GraceHours -as [int]) -gt 0) { $GraceHours = [int]$env:GraceHours }

function Write-MonitorResult {
    param([string]$Status, [int]$ExitCode, [string]$Diagnostic)
    # Datto requires a single-line result between these markers, "STATUS=" with no space after "=".
    $line = ($Status -replace '[\r\n]+', ' ').Trim()
    Write-Output '<-Start Result->'
    Write-Output ("STATUS=" + $line)
    Write-Output '<-End Result->'
    if ($ExitCode -ne 0 -and $Diagnostic) {
        Write-Output '<-Start Diagnostic->'
        Write-Output $Diagnostic
        Write-Output '<-End Diagnostic->'
    }
    exit $ExitCode
}

function Find-AttachedFile {
    param([string]$Name)
    foreach ($folder in @($PSScriptRoot, (Get-Location).Path)) {
        if ($folder) {
            $candidate = Join-Path $folder $Name
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    return $null
}

function Get-WindowsPowerShell64 {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        return (Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe')
    }
    return (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-FirstSeenUtc {
    try {
        if ($StateFile) {
            if (Test-Path -LiteralPath $StateFile) { $raw = (Get-Content -LiteralPath $StateFile -Raw).Trim() } else { return $null }
        }
        else {
            $raw = (Get-ItemProperty -Path $StateKey -Name FirstDetectedUtc -ErrorAction Stop).FirstDetectedUtc
        }
        if (-not $raw) { return $null }
        return [datetime]::Parse($raw, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    catch { return $null }
}

function Set-FirstSeenUtc {
    param([datetime]$Utc)
    $value = $Utc.ToString('o')
    try {
        if ($StateFile) { Set-Content -LiteralPath $StateFile -Value $value }
        else {
            if (-not (Test-Path $StateKey)) { New-Item -Path $StateKey -Force | Out-Null }
            Set-ItemProperty -Path $StateKey -Name FirstDetectedUtc -Value $value
        }
    }
    catch {}
}

function Clear-FirstSeen {
    try {
        if ($StateFile) { if (Test-Path -LiteralPath $StateFile) { Remove-Item -LiteralPath $StateFile -Force } }
        elseif (Test-Path $StateKey) { Remove-ItemProperty -Path $StateKey -Name FirstDetectedUtc -ErrorAction SilentlyContinue }
    }
    catch {}
}

function Get-LogTail {
    param([int]$Lines = 15)
    if (Test-Path -LiteralPath $LogPath) {
        return ((Get-Content -LiteralPath $LogPath -Tail $Lines -ErrorAction SilentlyContinue) -join "`n")
    }
    return "(no removal log at $LogPath - has the removal job run on this device?)"
}

# --- run detection -----------------------------------------------------------------------------
$script = Find-AttachedFile -Name $ScriptName
if (-not $script) {
    Write-MonitorResult -Status "Monitor misconfigured: $ScriptName is not attached to the component" -ExitCode 1 -Diagnostic 'Attach mcafee_detect.ps1 from the repository main branch.'
}
$actual = (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash
if ($actual -ne $ExpectedSha256) {
    Write-MonitorResult -Status "Monitor misconfigured: attached $ScriptName does not match the tested version" -ExitCode 1 -Diagnostic ("Expected SHA256 {0}, got {1}." -f $ExpectedSha256, $actual)
}

if (-not $PowerShellPath) { $PowerShellPath = Get-WindowsPowerShell64 }
$output = (& $PowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script 2>&1 | Out-String).Trim()
$code = $LASTEXITCODE

# --- interpret -----------------------------------------------------------------------------------
if ($code -eq 0) {
    Clear-FirstSeen
    if ($output -match 'out of scope') {
        $reason = ''
        if ($output -match 'Managed McAfee/Trellix detected \(([^)]*)\)') { $reason = ' (' + $Matches[1] + ')' }
        Write-MonitorResult -Status ("OK - managed McAfee/Trellix present, out of scope" + $reason) -ExitCode 0
    }
    if ($output -match 'Reboot required/pending') {
        Write-MonitorResult -Status 'OK - McAfee removal waiting for a restart' -ExitCode 0
    }
    Write-MonitorResult -Status 'OK - no consumer McAfee detected' -ExitCode 0
}

if ($code -ne 1) {
    Write-MonitorResult -Status ("Detection script failed (exit code {0})" -f $code) -ExitCode 1 -Diagnostic $output
}

# exit code 1: consumer McAfee present
$now = [datetime]::UtcNow
$firstSeen = Get-FirstSeenUtc
if (-not $firstSeen -or $firstSeen -gt $now.AddMinutes(5)) {
    $firstSeen = $now
    Set-FirstSeenUtc -Utc $firstSeen
}
$hours = [math]::Floor(($now - $firstSeen).TotalHours)
$firstSeenText = $firstSeen.ToString('yyyy-MM-dd HH:mm') + ' UTC'

if (($now - $firstSeen).TotalHours -lt $GraceHours) {
    Write-MonitorResult -Status ("OK - consumer McAfee present, removal pending (first seen {0}, alert after {1}h)" -f $firstSeenText, $GraceHours) -ExitCode 0
}

$diag = "Detection output:`n" + $output + "`n`nLast lines of removal log (" + $LogPath + "):`n" + (Get-LogTail)
Write-MonitorResult -Status ("Consumer McAfee still present after {0}h (first seen {1}) - check removal job and RemoveMcAfee.log" -f $hours, $firstSeenText) -ExitCode 1 -Diagnostic $diag
