<#
.SYNOPSIS
  Verifies the McAfee removal scripts' safety behaviour on a real Windows test VM.

.DESCRIPTION
  Run ONCE, elevated, on a DISPOSABLE Windows 10/11 test VM (snapshot it first).
  Do not run on a production device or a device you care about.

  For each scenario the script sets up the situation an attacker or a messy device
  would create, runs the real mcafee_detect.ps1 / mcafee_remediate.ps1 as SYSTEM
  under Windows PowerShell 5.1 (as Intune does), and checks the result.

  Scenarios
    1  Fresh run creates C:\ProgramData\ITZero-McAfeeRemoval owned by SYSTEM,
       protected ACL with exactly SYSTEM + Administrators Full Control.
    2  A real standard user cannot create a file in that folder.
    3  Folder pre-created by a standard user with a planted post-reboot script:
       rebuilt clean and SYSTEM-owned.
    4  User-owned junction planted inside the folder: junction removed, target untouched.
    5  Working folder itself replaced by a user-owned junction: junction removed,
       real folder created, target untouched.
    6  Legacy C:\ProgramData\Debloat post-reboot script + startup task from the old
       version: file removed, task unregistered.
    7  Detection ignores a future-dated reboot marker owned by a standard user.
    8  Detection treats a future-dated marker owned by SYSTEM/Administrators as invalid.
    9  Managed McAfee (fake "McAfee Agent" uninstall entry): detection says out of
       scope; remediation makes no changes.
   10  (Only with -IncludeFullRun) Registry-only consumer McAfee entry: remediation
       downloads the payloads from the pinned GitHub commit, verifies SHA256, runs the
       McAfee cleanup tool and removes the orphaned entry. Needs internet access and
       takes several minutes.

  The script creates a temporary local standard user (random password) for
  scenarios 2-5 and 7, a temporary scheduled task to run things as SYSTEM, and
  temporary registry entries. Everything is removed at the end (use -KeepArtifacts
  to leave the working folder and logs for inspection).

.PARAMETER RepoPath
  Folder containing mcafee_detect.ps1 and mcafee_remediate.ps1. Defaults to the
  parent of this script's folder (the repository root).

.PARAMETER IncludeFullRun
  Also run scenario 10 (downloads ~30 MB and runs McAfee's cleanup tool).

.PARAMETER Force
  Skip the "is this a disposable test VM?" confirmation.

.EXAMPLE
  # From an elevated Windows PowerShell prompt in the repository folder:
  powershell.exe -ExecutionPolicy Bypass -File .\tests\Test-VMSafety.ps1
  powershell.exe -ExecutionPolicy Bypass -File .\tests\Test-VMSafety.ps1 -IncludeFullRun

.NOTES
  Exit code = number of failed checks (0 = all passed).
  A results file is written to C:\ProgramData\ITZero-VMTest\results.txt.
#>
[CmdletBinding()]
param(
    [string]$RepoPath = (Split-Path -Parent $PSScriptRoot),
    [switch]$IncludeFullRun,
    [switch]$Force,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# ---------------------------------------------------------------- constants
$WorkFolder      = 'C:\ProgramData\ITZero-McAfeeRemoval'
$LegacyFolder    = 'C:\ProgramData\Debloat'
$TestRoot        = 'C:\ProgramData\ITZero-VMTest'
$CanaryDir       = 'C:\ITZeroVMTestCanary'
$RemediationLog  = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log'
$SystemSid       = 'S-1-5-18'
$AdminsSid       = 'S-1-5-32-544'
$RunnerTaskName  = 'ITZero-VMTest-RunAsSystem'
$PostRebootTask  = 'McAfeeRemovalPostReboot'
$UninstallKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$FakeAgentKey    = Join-Path $UninstallKey 'ITZeroVMTest-McAfeeAgent'
$FakeConsumerKey = Join-Path $UninstallKey 'ITZeroVMTest-McAfeeLiveSafe'
$TestUserName    = 'itzvmtest' + (Get-Random -Minimum 1000 -Maximum 9999)

$DetectScript    = Join-Path $RepoPath 'mcafee_detect.ps1'
$RemediateScript = Join-Path $RepoPath 'mcafee_remediate.ps1'

$Results = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------- helpers
function Write-Step { param([string]$Text) Write-Host ''; Write-Host ('== ' + $Text) -ForegroundColor Cyan }

function Add-Result {
    param([string]$Scenario, [string]$Check, [bool]$Passed, [string]$Detail = '')
    $Results.Add([pscustomobject]@{ Scenario = $Scenario; Check = $Check; Result = $(if ($Passed) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
    $colour = 'Green'; if (-not $Passed) { $colour = 'Red' }
    $line = '  {0}  {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Check
    if ($Detail -and -not $Passed) { $line += "  [$Detail]" }
    Write-Host $line -ForegroundColor $colour
}

function Add-Skip {
    param([string]$Scenario, [string]$Check, [string]$Why)
    $Results.Add([pscustomobject]@{ Scenario = $Scenario; Check = $Check; Result = 'SKIP'; Detail = $Why })
    Write-Host ('  SKIP  {0}  [{1}]' -f $Check, $Why) -ForegroundColor Yellow
}

function Get-OwnerSid {
    param([string]$Path)
    try { return (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
}

function Test-IsReparsePoint {
    param([string]$Path)
    try { return [bool]((Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) }
    catch { return $false }
}

function Remove-PathNoFollow {
    # Removes a path without following junctions (used for test setup/cleanup only).
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        # Dangling junctions report as missing to Test-Path; try anyway.
        try { [System.IO.Directory]::Delete($Path, $false) } catch {}
        return
    }
    if (Test-IsReparsePoint -Path $Path) { [System.IO.Directory]::Delete($Path, $false); return }
    & cmd.exe /c "rd /s /q `"$Path`"" 2>$null | Out-Null
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

function Set-OwnerToTestUser {
    # Makes the test user the owner of a path (and give them Full Control), as if they had created it.
    param([string]$Path, [switch]$Recurse, [switch]$Link)
    $ownerArgs = @($Path, '/setowner', "$env:COMPUTERNAME\$TestUserName")
    if ($Recurse) { $ownerArgs += '/T' }
    if ($Link) { $ownerArgs += '/L' }
    $ownerArgs += '/C', '/Q'
    & icacls.exe @ownerArgs | Out-Null
    $isFolder = (Test-Path -LiteralPath $Path -PathType Container) -and -not $Link
    $perm = 'F'; if ($isFolder) { $perm = '(OI)(CI)F' }
    $grant = @($Path, '/grant', "$env:COMPUTERNAME\${TestUserName}:$perm")
    if ($Link) { $grant += '/L' }
    if ($Recurse -and $isFolder) { $grant += '/T' }
    $grant += '/C', '/Q'
    & icacls.exe @grant | Out-Null
}

function Invoke-AsSystem {
    # Runs a script as SYSTEM with Windows PowerShell 5.1 via a one-off scheduled task (like Intune's IME).
    # Returns @{ ExitCode; Output }.
    param([string]$ScriptPath, [int]$TimeoutSeconds = 300)

    $outFile = Join-Path $TestRoot ('out_{0}.txt' -f ([guid]::NewGuid().ToString('N')))
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $cmdArgs = '/c ""{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" > "{2}" 2>&1"' -f $ps, $ScriptPath, $outFile

    Unregister-ScheduledTask -TaskName $RunnerTaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action    = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmdArgs
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $RunnerTaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $RunnerTaskName

    # 267009 = task is running, 267011 = task has not run yet: keep waiting through both.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $state = (Get-ScheduledTask -TaskName $RunnerTaskName).State
        $exitCode = (Get-ScheduledTaskInfo -TaskName $RunnerTaskName).LastTaskResult
        if ((Get-Date) -gt $deadline) {
            Stop-ScheduledTask -TaskName $RunnerTaskName -ErrorAction SilentlyContinue
            Write-Warning ("{0} did not finish within {1} seconds." -f $ScriptPath, $TimeoutSeconds)
            $exitCode = -1
            break
        }
    } while (($state -eq 'Running') -or ($exitCode -eq 267009) -or ($exitCode -eq 267011))
    Unregister-ScheduledTask -TaskName $RunnerTaskName -Confirm:$false -ErrorAction SilentlyContinue

    $output = ''
    if (Test-Path -LiteralPath $outFile) { $output = Get-Content -LiteralPath $outFile -Raw; Remove-Item -LiteralPath $outFile -Force }
    if ($null -eq $output) { $output = '' }
    return @{ ExitCode = [int]$exitCode; Output = $output }
}

function Test-WorkFolderLockedDown {
    param([string]$Scenario)
    Add-Result $Scenario 'Working folder exists and is a real folder (not a link)' ((Test-Path -LiteralPath $WorkFolder) -and -not (Test-IsReparsePoint $WorkFolder))
    $owner = Get-OwnerSid $WorkFolder
    Add-Result $Scenario 'Working folder owned by SYSTEM' ($owner -eq $SystemSid) ("owner " + $owner)
    $acl = Get-Acl -LiteralPath $WorkFolder
    Add-Result $Scenario 'No inherited permissions (ACL protected)' ($acl.AreAccessRulesProtected)
    $rules = @($acl.Access)
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $onlyTwo = ($sids.Count -eq 2) -and ($sids -contains $SystemSid) -and ($sids -contains $AdminsSid)
    Add-Result $Scenario 'Access for SYSTEM and Administrators only' $onlyTwo ("found " + ($sids -join ', '))
    $allFull = @($rules | Where-Object { $_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl' }).Count -eq 0
    Add-Result $Scenario 'Both entries are Allow / Full Control' $allFull
}

function Test-UserCanWrite {
    # Tries to create a file as the real test user. Returns $true (wrote), $false (denied), or $null (could not run).
    param([string]$Folder, [pscredential]$Credential)
    $target = Join-Path $Folder 'user-write-test.txt'
    $probe = Join-Path $TestRoot 'probe.ps1'
    Set-Content -LiteralPath $probe -Encoding Ascii -Value @"
try { Set-Content -LiteralPath '$target' -Value 'x' -ErrorAction Stop; exit 10 } catch { exit 20 }
"@
    try {
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $probe) `
            -Credential $Credential -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -PassThru -Wait -ErrorAction Stop
        if ($p.ExitCode -eq 10) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue; return $true }
        if ($p.ExitCode -eq 20) { return $false }
        return $null
    }
    catch { return $null }
}

function Reset-State {
    Unregister-ScheduledTask -TaskName $PostRebootTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-PathNoFollow $WorkFolder
    Remove-PathNoFollow $CanaryDir
    foreach ($k in @($FakeAgentKey, $FakeConsumerKey)) { if (Test-Path $k) { Remove-Item $k -Recurse -Force } }
}

function New-Canary {
    New-Item -ItemType Directory -Path $CanaryDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $CanaryDir 'must-survive.txt') -Value 'canary'
}

# ---------------------------------------------------------------- preflight
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Run this from an elevated (Administrator) PowerShell prompt.'; exit 255 }
foreach ($f in @($DetectScript, $RemediateScript)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Error "Not found: $f (use -RepoPath)"; exit 255 }
}
$remediateText = Get-Content -LiteralPath $RemediateScript -Raw
if ($remediateText -notmatch 'ITZero-McAfeeRemoval' -or $remediateText -notmatch 'Get-ManagedMcAfeeIndicators') {
    Write-Error 'mcafee_remediate.ps1 is not the hardened version (expected PRs #1-#4). Check out the right branch.'; exit 255
}

$managedSigns = @()
foreach ($svc in @('masvc', 'macmnsvc')) { if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { $managedSigns += $svc } }
foreach ($p in @('C:\Program Files\McAfee', 'C:\Program Files (x86)\McAfee', 'C:\ProgramData\McAfee', 'C:\Program Files\Trellix')) { if (Test-Path $p) { $managedSigns += $p } }
if ($managedSigns.Count -gt 0) {
    Write-Error ("This VM has McAfee/Trellix installed ({0}). Use a clean VM: the tests expect no McAfee present." -f ($managedSigns -join ', ')); exit 255
}

if (-not $Force) {
    Write-Host 'This script changes system state (temporary local user, scheduled tasks, folders under C:\ProgramData, registry).' -ForegroundColor Yellow
    Write-Host 'Run it only on a DISPOSABLE TEST VM, ideally with a snapshot taken first.' -ForegroundColor Yellow
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Cancelled.'; exit 255 }
}

New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null
Write-Host ("Windows PowerShell used for SYSTEM runs: {0}" -f (& (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'))

# Temporary standard user
$testCred = $null
try {
    $chars = (48..57) + (65..90) + (97..122) + (33, 35, 37, 42, 43, 45, 61, 63)
    $plain = -join (1..24 | ForEach-Object { [char]($chars | Get-Random) }) + 'aA1!'
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    New-LocalUser -Name $TestUserName -Password $secure -Description 'Temporary user for ITZero McAfee VM tests' -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $TestUserName -ErrorAction SilentlyContinue
    $testCred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$TestUserName", $secure)
    Write-Host "Created temporary standard user $TestUserName"
}
catch {
    Write-Error "Could not create a temporary local user: $_"; exit 255
}

try {
    Reset-State

    # ------------------------------------------------------------ 1
    Write-Step '1  Fresh run locks down the working folder'
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '1' 'Remediation ran as SYSTEM and exited 0 (no McAfee present)' ($r.ExitCode -eq 0) ("exit " + $r.ExitCode)
    Test-WorkFolderLockedDown '1'

    # ------------------------------------------------------------ 2
    Write-Step '2  Standard user cannot write to the working folder'
    $canWrite = Test-UserCanWrite -Folder $WorkFolder -Credential $testCred
    if ($null -eq $canWrite) { Add-Skip '2' 'Standard user denied when creating a file' 'could not start a process as the test user (Secondary Logon service stopped?)' }
    else { Add-Result '2' 'Standard user denied when creating a file' (-not $canWrite) }
    # Control: an ordinary admin-created ProgramData subfolder (like the old C:\ProgramData\Debloat) IS writable
    # by standard users. If this fails, the test user cannot write anywhere and check 2 proves nothing.
    $canWriteControl = Test-UserCanWrite -Folder $TestRoot -Credential $testCred
    if ($null -ne $canWriteControl) {
        Add-Result '2' 'Control: same user CAN write to an ordinary ProgramData subfolder (as with the old Debloat folder)' ([bool]$canWriteControl)
    }

    # ------------------------------------------------------------ 3
    Write-Step '3  Folder pre-created by a standard user with a planted script'
    Reset-State
    New-Item -ItemType Directory -Path $WorkFolder | Out-Null
    $planted = Join-Path $WorkFolder 'mcafee_remediate_postreboot.ps1'
    Set-Content -LiteralPath $planted -Value '# planted by test'
    Set-OwnerToTestUser -Path $WorkFolder -Recurse
    Add-Result '3' 'Setup: folder now owned by the standard user' ((Get-OwnerSid $WorkFolder) -ne $SystemSid)
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '3' 'Planted script removed' (-not ((Test-Path -LiteralPath $planted) -and ((Get-Content -LiteralPath $planted -Raw) -match 'planted by test')))
    Test-WorkFolderLockedDown '3'

    # ------------------------------------------------------------ 4
    Write-Step '4  User-owned junction planted inside the folder'
    Reset-State; New-Canary
    $null = Invoke-AsSystem $RemediateScript          # create the locked-down folder
    $junction = Join-Path $WorkFolder 'mcafeeclean_extracted'
    New-Item -ItemType Junction -Path $junction -Target $CanaryDir | Out-Null
    Set-OwnerToTestUser -Path $junction -Link
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '4' 'Junction removed' (-not (Test-IsReparsePoint $junction))
    Add-Result '4' 'Junction target left untouched' (Test-Path -LiteralPath (Join-Path $CanaryDir 'must-survive.txt'))

    # ------------------------------------------------------------ 5
    Write-Step '5  Working folder itself replaced by a user-owned junction'
    Reset-State; New-Canary
    New-Item -ItemType Junction -Path $WorkFolder -Target $CanaryDir | Out-Null
    Set-OwnerToTestUser -Path $WorkFolder -Link
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '5' 'Junction target left untouched' (Test-Path -LiteralPath (Join-Path $CanaryDir 'must-survive.txt'))
    Add-Result '5' 'Target did not receive working files' (-not (Test-Path -LiteralPath (Join-Path $CanaryDir 'McAfeeRemoval.reboot.json')))
    Test-WorkFolderLockedDown '5'

    # ------------------------------------------------------------ 6
    Write-Step '6  Legacy Debloat files and startup task are retired'
    Reset-State
    $legacyCreatedFolder = -not (Test-Path -LiteralPath $LegacyFolder)
    New-Item -ItemType Directory -Path $LegacyFolder -Force | Out-Null
    $legacyScript = Join-Path $LegacyFolder 'mcafee_remediate_postreboot.ps1'
    Set-Content -LiteralPath $legacyScript -Value '# legacy staged script (test)'
    $legacyAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c powershell.exe -NoProfile -File "{0}" -PostReboot' -f $legacyScript)
    Register-ScheduledTask -TaskName $PostRebootTask -Action $legacyAction -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) -Force | Out-Null
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '6' 'Legacy post-reboot script removed from C:\ProgramData\Debloat' (-not (Test-Path -LiteralPath $legacyScript))
    Add-Result '6' 'Startup task pointing at the old location unregistered' ($null -eq (Get-ScheduledTask -TaskName $PostRebootTask -ErrorAction SilentlyContinue))
    if ($legacyCreatedFolder) { Remove-PathNoFollow $LegacyFolder }

    # ------------------------------------------------------------ 7 / 8
    Write-Step '7  Detection ignores a future-dated marker owned by a standard user'
    Reset-State
    $null = Invoke-AsSystem $RemediateScript          # locked-down folder
    $marker = Join-Path $WorkFolder 'McAfeeRemoval.reboot.json'
    Set-Content -LiteralPath $marker -Encoding Ascii -Value '{"CreatedUtc":"2099-01-01T00:00:00Z","Reason":"test","RebootCount":0}'
    Set-OwnerToTestUser -Path $marker
    $r = Invoke-AsSystem $DetectScript
    Add-Result '7' 'Detection reports it ignored the marker' ($r.Output -match 'Ignoring reboot marker') ($r.Output.Trim() -replace '\s+', ' ')
    Add-Result '7' 'Detection fell through to normal checks (No McAfee detected)' ($r.Output -match 'No McAfee detected')

    Write-Step '8  Detection treats a future-dated SYSTEM/Admin-owned marker as invalid'
    Remove-Item -LiteralPath $marker -Force
    Set-Content -LiteralPath $marker -Encoding Ascii -Value '{"CreatedUtc":"2099-01-01T00:00:00Z","Reason":"test","RebootCount":0}'
    # Files created by an elevated admin may be owned by that user rather than the group, depending on policy.
    & icacls.exe $marker /setowner '*S-1-5-32-544' /C /Q | Out-Null
    Add-Result '8' 'Setup: marker owned by Administrators' ((Get-OwnerSid $marker) -eq $AdminsSid)
    $r = Invoke-AsSystem $DetectScript
    Add-Result '8' 'Detection exits 1 instead of reporting "reboot pending"' ($r.ExitCode -eq 1) ("exit " + $r.ExitCode)
    Add-Result '8' 'Output mentions the invalid/old marker' ($r.Output -match 'invalid date')
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

    # ------------------------------------------------------------ 9
    Write-Step '9  Managed McAfee is out of scope'
    Reset-State
    New-Item -Path $FakeAgentKey -Force | Out-Null
    New-ItemProperty -Path $FakeAgentKey -Name DisplayName -Value 'McAfee Agent' -Force | Out-Null
    New-ItemProperty -Path $FakeAgentKey -Name Publisher -Value 'McAfee, LLC' -Force | Out-Null
    New-ItemProperty -Path $FakeAgentKey -Name UninstallString -Value 'C:\NonExistent\FrmInst.exe /forceuninstall' -Force | Out-Null
    $r = Invoke-AsSystem $DetectScript
    Add-Result '9' 'Detection exits 0 and says "out of scope"' (($r.ExitCode -eq 0) -and ($r.Output -match 'out of scope')) ($r.Output.Trim() -replace '\s+', ' ')
    $r = Invoke-AsSystem $RemediateScript
    Add-Result '9' 'Remediation exits 0' ($r.ExitCode -eq 0) ("exit " + $r.ExitCode)
    Add-Result '9' 'Fake McAfee Agent entry left in place' (Test-Path $FakeAgentKey)
    Add-Result '9' 'Remediation did not create its working folder (stopped before any change)' (-not (Test-Path -LiteralPath $WorkFolder))
    Remove-Item $FakeAgentKey -Recurse -Force

    # ------------------------------------------------------------ 10
    Write-Step '10 Full run: payload download, verification and orphan clean-up'
    if (-not $IncludeFullRun) {
        Add-Skip '10' 'Full remediation run' 'not requested (use -IncludeFullRun)'
    }
    else {
        Reset-State
        New-Item -Path $FakeConsumerKey -Force | Out-Null
        New-ItemProperty -Path $FakeConsumerKey -Name DisplayName -Value 'McAfee LiveSafe' -Force | Out-Null
        New-ItemProperty -Path $FakeConsumerKey -Name Publisher -Value 'McAfee, LLC' -Force | Out-Null
        New-ItemProperty -Path $FakeConsumerKey -Name UninstallString -Value '"C:\Program Files\McAfee\MSC\mcuihost.exe" /body:misp://MSCJsRes.dll::uninstall.html /id:uninstall' -Force | Out-Null
        $r = Invoke-AsSystem $DetectScript
        Add-Result '10' 'Detection flags the registry-only entry (exit 1)' ($r.ExitCode -eq 1) ("exit " + $r.ExitCode)
        $logStart = 0; if (Test-Path $RemediationLog) { $logStart = @(Get-Content $RemediationLog).Count }
        $r = Invoke-AsSystem $RemediateScript -TimeoutSeconds 3600
        $log = ''
        if (Test-Path $RemediationLog) { $log = (@(Get-Content $RemediationLog) | Select-Object -Skip $logStart) -join "`n" }
        Add-Result '10' 'Payloads downloaded from the pinned IT Zero commit and verified' (($log -match 'raw.githubusercontent.com/IT-Zero-Ltd/McAfee-Script-Uninstall/') -and ($log -match 'downloaded and verified mcafeeclean.zip') -and ($log -match 'downloaded and verified mccleanup.zip'))
        Add-Result '10' 'McAfee cleanup tool ran from the locked-down folder' ($log -match 'Running mcafeeclean => C:\\ProgramData\\ITZero-McAfeeRemoval\\')
        Add-Result '10' 'Orphaned LiveSafe entry removed (uninstaller missing)' (-not (Test-Path $FakeConsumerKey))
        Add-Result '10' 'Remediation exited 0' ($r.ExitCode -eq 0) ("exit " + $r.ExitCode)
        Add-Result '10' 'No shutdown was scheduled' (-not ($log -match 'Scheduling reboot'))
        $r = Invoke-AsSystem $DetectScript
        Add-Result '10' 'Detection now reports clean (exit 0)' ($r.ExitCode -eq 0) ("exit " + $r.ExitCode)
    }
}
finally {
    Write-Step 'Cleaning up'
    try { Unregister-ScheduledTask -TaskName $RunnerTaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $PostRebootTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    foreach ($k in @($FakeAgentKey, $FakeConsumerKey)) { try { if (Test-Path $k) { Remove-Item $k -Recurse -Force } } catch {} }
    try { Remove-PathNoFollow $CanaryDir } catch {}
    if (-not $KeepArtifacts) { try { Remove-PathNoFollow $WorkFolder } catch {} }
    try {
        Remove-LocalUser -Name $TestUserName -ErrorAction SilentlyContinue
        $userProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$TestUserName" }
        if ($userProfile) { $userProfile | Remove-CimInstance -ErrorAction SilentlyContinue }
        Write-Host "Removed temporary user $TestUserName"
    } catch {}
}

# ---------------------------------------------------------------- summary
$failed = @($Results | Where-Object { $_.Result -eq 'FAIL' }).Count
$passed = @($Results | Where-Object { $_.Result -eq 'PASS' }).Count
$skipped = @($Results | Where-Object { $_.Result -eq 'SKIP' }).Count
$summary = "{0} passed, {1} failed, {2} skipped" -f $passed, $failed, $skipped
$resultsFile = Join-Path $TestRoot 'results.txt'
$header = "ITZero McAfee removal VM safety test - {0} - {1} - {2}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm'), $summary
($header, '', ($Results | Format-Table -AutoSize -Wrap | Out-String -Width 220)) | Set-Content -LiteralPath $resultsFile
Write-Host ''
Write-Host $summary -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
Write-Host "Results saved to $resultsFile"
if ($KeepArtifacts) { Write-Host "Working folder kept for inspection: $WorkFolder" }
exit $failed
