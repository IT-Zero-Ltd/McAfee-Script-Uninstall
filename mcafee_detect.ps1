[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

$fileThreshold = 10

Write-Host "=== McAfee Detection Script ==="

# Must match the secured working folder used by mcafee_remediate.ps1.
$workFolder = "C:\ProgramData\ITZero-McAfeeRemoval"
$rebootMarkerPath = Join-Path $workFolder "McAfeeRemoval.reboot.json"
$trustedOwnerSids = @('S-1-5-18', 'S-1-5-32-544')   # NT AUTHORITY\SYSTEM, BUILTIN\Administrators

function Test-TrustedPath {
    # True only if the item exists, is not a junction/link, and is owned by SYSTEM or Administrators.
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $false }
        $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        return ($trustedOwnerSids -contains $owner)
    }
    catch { return $false }
}

function Get-LastBootUtc {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os -and $os.LastBootUpTime) {
            return ([datetime]$os.LastBootUpTime).ToUniversalTime()
        }
    }
    catch {}
    return $null
}

function Get-RebootMarker {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    # Only honour a marker written by the remediation script. A marker a standard user could have planted
    # (e.g. with a future date) would otherwise hide McAfee from detection indefinitely.
    if (-not ((Test-TrustedPath -Path $workFolder) -and (Test-TrustedPath -Path $Path))) {
        Write-Host "Ignoring reboot marker that is not owned by SYSTEM/Administrators."
        return $null
    }

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction SilentlyContinue)
    }
    catch {
        return $null
    }
}

function Clear-RebootMarker {
    param([string]$Path)

    try {
        if (Test-TrustedPath -Path $Path) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    }
    catch {}
}

# If remediation scheduled a reboot, treat as temporarily compliant so HealthScripts does not mark the run as failed.
# Once the device actually reboots, remove the marker and resume normal detection.
$marker = Get-RebootMarker -Path $rebootMarkerPath
if ($marker -and $marker.CreatedUtc) {
    $markerUtc = $null
    try { $markerUtc = [datetime]::Parse($marker.CreatedUtc).ToUniversalTime() } catch {}

    $bootUtc = Get-LastBootUtc
    if ($bootUtc -and $markerUtc -and ($bootUtc -gt $markerUtc)) {
        Write-Host "Reboot marker exists, but device has rebooted since it was set. Clearing marker and continuing detection."
        Clear-RebootMarker -Path $rebootMarkerPath
    }
    else {
        # Safety: do not ignore forever if reboot never happens (or if the marker's date is in the future or unreadable).
        if ((-not $markerUtc) -or ($markerUtc -gt [datetime]::UtcNow.AddMinutes(5)) -or (([datetime]::UtcNow - $markerUtc).TotalHours -ge 48)) {
            Write-Host "Reboot marker is older than 48 hours or has an invalid date. Treating as non-compliant to re-trigger remediation."
            exit 1
        }

        Write-Host "Reboot required/pending (marker present). Treating as compliant until reboot occurs."
        exit 0
    }
}

$foundRegistry = $false
$totalFiles = 0
$directoryFileCounts = @{}

# Registry Check
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $mcAfeeMatches = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*McAfee*"
        }
        
        foreach ($match in $mcAfeeMatches) {
            Write-Host "Detected registry entry: $($match.DisplayName)"
            $foundRegistry = $true
        }
    }
}


# Directory Check (with detailed output)
$mcAfeeDirs = @(
    "C:\Program Files\McAfee",
    "C:\Program Files (x86)\McAfee",
    "C:\ProgramData\McAfee"
)
foreach ($dir in $mcAfeeDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
        $fileCount = $files.Count
        $directoryFileCounts[$dir] = $fileCount
        Write-Host "Directory found: $dir - File count: $fileCount"
        $totalFiles += $fileCount
    }
    else {
        Write-Host "Directory not found: $dir"
    }
}
Write-Host "Total leftover McAfee files: $totalFiles"

# Check for QcShm.exe process
$qcshmRunning = $null -ne (Get-Process -Name "QcShm" -ErrorAction SilentlyContinue)
if ($qcshmRunning) {
    Write-Host "QcShm.exe is running."
}
else {
    Write-Host "QcShm.exe is not running."
}

# Determine Final State
if ($foundRegistry -or ($totalFiles -gt $fileThreshold)) {
    Write-Host "McAfee appears to be still installed (registry traces found or file count exceeds threshold)."
    Write-Host "Exit Code 1"
    exit 1
}
elseif (($totalFiles -gt 0) -and ($totalFiles -le $fileThreshold)) {
    if ($qcshmRunning) {
        Write-Host "Residual McAfee files detected ($totalFiles files) and QcShm.exe is running."
        Write-Host "McAfee appears to be uninstalled, but a reboot is required to clear file locks."
        Write-Host "Exit Code 0"
        exit 0
    }
    else {
        Write-Host "Residual McAfee files detected ($totalFiles files), but no file-locking process found."
        Write-Host "McAfee appears to be uninstalled."
        Write-Host "Exit Code 0"
        exit 0
    }
}
else {
    Write-Host "No McAfee detected."
    Write-Host "Exit Code 0"
    exit 0
}
