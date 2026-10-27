# IT Zero - McAfee consumer removal (Datto RMM component)
#
# Paste this as the component script (Category: Scripts, Script type: PowerShell) and attach
# mcafee_remediate.ps1 from the repository's main branch to the component.
#
# What it does:
#   1. Finds the attached mcafee_remediate.ps1 and checks its SHA256 matches the tested version below.
#      A different or modified file is refused, so an accidental upload of the wrong version can't run.
#   2. Runs it in 64-bit Windows PowerShell (the script needs 64-bit to see all uninstall registry keys and
#      remove AppX packages), even if the Datto agent started this component as a 32-bit process.
#   3. Passes the script's output and exit code straight back to Datto (0 = clean / out of scope / waiting
#      for restart, 1 = McAfee still present or failure).
#
# Safe to run on every device on a schedule: on devices without consumer McAfee, or with managed
# McAfee/Trellix, the removal script exits within seconds without changing anything.
#
# When mcafee_remediate.ps1 changes in the repository, update $ExpectedSha256 and re-attach the file.

param(
    [string]$PowerShellPath   # for testing only; normally left empty
)

$ExpectedSha256 = 'DC8E89E23EE51C3EA093E35822A7ABA50A455B40397124E14C9C5D365E2ADFCF'
$ScriptName     = 'mcafee_remediate.ps1'

function Find-AttachedFile {
    param([string]$Name)
    # Datto places attached files in the component's working folder.
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
        # 32-bit process on 64-bit Windows: sysnative reaches the real 64-bit System32.
        return (Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe')
    }
    return (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

$script = Find-AttachedFile -Name $ScriptName
if (-not $script) {
    Write-Output "ERROR: $ScriptName is not attached to this component. Attach it from the repository's main branch."
    exit 1
}

$actual = (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash
if ($actual -ne $ExpectedSha256) {
    Write-Output ("ERROR: attached {0} does not match the tested version (expected SHA256 {1}, got {2}). Not running it." -f $ScriptName, $ExpectedSha256, $actual)
    exit 1
}

if (-not $PowerShellPath) { $PowerShellPath = Get-WindowsPowerShell64 }
Write-Output ("Running {0} (SHA256 verified) with {1}" -f $ScriptName, $PowerShellPath)

& $PowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script
$code = $LASTEXITCODE
Write-Output ("{0} finished with exit code {1}" -f $ScriptName, $code)
exit $code
