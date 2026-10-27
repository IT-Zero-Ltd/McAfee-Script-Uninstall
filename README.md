McAfee Removal (Intune Proactive Remediation)
=============================================

This folder contains the detection and remediation scripts used to remove McAfee in device context (SYSTEM), including reboot orchestration for locked-file scenarios.

Files
-----

| File | Purpose |
|------|---------|
| `mcafee_detect.ps1` | Detection script for Intune Proactive Remediations. |
| `mcafee_remediate.ps1` | Remediation/uninstall script with cleanup + reboot handling. |

High-Level Behavior
-------------------

### Detection (`mcafee_detect.ps1`)

- **Scope:** consumer McAfee only. If managed McAfee/Trellix is present (McAfee/Trellix Agent, Endpoint Security, VirusScan Enterprise, encryption/DLP products, the `masvc`/`macmnsvc` agent services, or `Program Files\McAfee\Agent`, `Program Files\McAfee\Endpoint Security`, `Program Files\Trellix`), detection returns `0` with "out of scope" in its output and remediation makes no changes.
- Returns `1` when McAfee is still considered installed:
  - McAfee uninstall registry entries exist (each product subkey is checked), or
  - McAfee file count in known folders is above threshold (`> 10`).
- Returns `0` when compliant/removed.
- Supports reboot marker flow:
  - If `C:\ProgramData\ITZero-McAfeeRemoval\McAfeeRemoval.reboot.json` exists and reboot has not occurred yet, detection returns `0` (temporary compliant state).
  - If marker is older than 48 hours, detection returns `1` to re-trigger remediation.
  - If reboot happened after marker creation, marker is cleared and normal detection resumes.

### Remediation (`mcafee_remediate.ps1`)

- Runs cleanup in SYSTEM context and logs to:
  - `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log`
- Downloads cleanup payloads at runtime from this repository (pinned commit, SHA256-verified):
  - `mcafeeclean.zip`
  - `mccleanup.zip`
- Removes registry traces, AppX/provisioned package traces and known folders.
- Removes a McAfee uninstall registry entry only if its uninstaller succeeded (exit 0, 1605, 1614, 1641 or 3010) or the product is verifiably gone (uninstaller missing, or MSI product no longer registered). Entries for products that failed to uninstall are kept and logged, so detection keeps flagging the device.
- Exits without changes on devices with managed McAfee/Trellix (same check as detection).
- Uses a state model from `Get-McAfeeStatus`:
  - `0` = clean
  - `1` = installed/significant remnants
  - `2` = residual + lock scenario

Reboot/Retry Strategy
---------------------

When locked files or reboot-required conditions are detected:

1. Remediation **does not restart the device**. It sets Datto RMM's restart flag `C:\ProgramData\CentraStage\reboot.flag` (only if the Datto agent folder exists) and Datto prompts the user to restart. Without Datto, cleanup finishes after the next normal restart.
2. Remediation writes marker:
   - `C:\ProgramData\ITZero-McAfeeRemoval\McAfeeRemoval.reboot.json`
3. Remediation registers one-shot startup task:
   - Task name: `McAfeeRemovalPostReboot`
   - Staged script path: `C:\ProgramData\ITZero-McAfeeRemoval\mcafee_remediate_postreboot.ps1`
   - Runs with `-PostReboot`
   - Self-deletes after execution.
4. Remediation exits `0` so HealthScripts does not record a hard failure while waiting for reboot.

This is intentional to avoid repeated failed remediation runs caused by file locks that only clear after reboot.

Restart tracking (`C:\ProgramData\ITZero-McAfeeRemoval\McAfeeRemoval.restarts.json`) counts only restarts that actually happened without finishing the cleanup, so a user who postpones restarting is never treated as a failure. After 3 such restarts remediation exits `1` to surface the device. The count is reset once McAfee is clean.

Every external process (cleanup tool, uninstallers) has a time limit (cleanup tool 20 minutes, others 10 minutes). A process that exceeds it, e.g. an uninstaller showing hidden UI under SYSTEM, is stopped with its child processes and treated as a failed uninstall.

IME/HealthScripts Hardening
---------------------------

The remediation script wraps native tool execution with `Invoke-ProcessQuiet`:

- Captures child process stdout/stderr to temp files.
- Prevents noisy native stderr (for example, transient access denied during locked-file removal) from surfacing as script stderr in IME.
- Logs relevant events to `RemoveMcAfee.log` instead.

This reduces false failure reporting where remediation logic is successful but external command stderr pollutes HealthScripts result details.

Execution Commands
------------------

Run as script files (not dot-sourced):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_detect.ps1
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_remediate.ps1
```

Optional post-reboot mode (normally task-driven):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_remediate.ps1 -PostReboot
```

Operational Notes
-----------------

- Must run in SYSTEM/device context for full cleanup capability.
- All working files (ZIPs, extraction folders, reboot marker, post-reboot script) live in `C:\ProgramData\ITZero-McAfeeRemoval`, which the remediation script locks down on every run: owned by SYSTEM, access for SYSTEM and Administrators only, no inherited permissions. Anything inside it not created by SYSTEM/Administrators, and any junction or link, is removed. If the folder cannot be secured, the script stops without running any cleanup tool.
- Detection only honours a reboot marker owned by SYSTEM/Administrators in that folder, and treats a future-dated marker as invalid.
- Earlier versions used `C:\ProgramData\Debloat`, which standard users can write to. The remediation script removes its old files from there and unregisters any `McAfeeRemovalPostReboot` task that points outside the secured folder.
- Internet access is required during remediation to fetch the cleanup ZIPs from this repository (`raw.githubusercontent.com/IT-Zero-Ltd/McAfee-Script-Uninstall`), pinned to a specific commit.
- Each ZIP is SHA256-verified before it is reused, extracted or run; a mismatched file is deleted and never executed.
- To update the payloads, commit the new ZIPs, then update `$PayloadCommit` and both SHA256 values in `mcafee_remediate.ps1` together.
- If network blocks GitHub, cleanup tool download will fail and removal may be incomplete.
- Detection threshold is intentionally conservative (`10` files).
- If you need to force re-evaluation immediately, remove marker file and rerun detection/remediation.

Testing on a VM
---------------

`tests/Test-VMSafety.ps1` checks the safety behaviour on a real Windows machine. Run it **once, elevated, on a disposable test VM with no McAfee installed** (take a snapshot first):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\tests\Test-VMSafety.ps1                  # ~2-3 minutes
powershell.exe -ExecutionPolicy Bypass -File .\tests\Test-VMSafety.ps1 -IncludeFullRun   # also downloads payloads and runs the cleanup tool
```

It runs the real scripts as SYSTEM under Windows PowerShell 5.1 (as Intune does) against nine scenarios: working-folder lockdown, a real standard user being denied, planted files and junctions, legacy files/task retirement, untrusted and future-dated markers, and managed McAfee being left alone. It uses a temporary local user, scheduled task and registry entries, all removed afterwards. Results are saved to `C:\ProgramData\ITZero-VMTest\results.txt`; the exit code is the number of failures.

Troubleshooting
---------------

Primary logs:

- `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log`
- `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log`

What to check:

1. Final detection state in `RemoveMcAfee.log` (`clean`, `residual`, or `installed`).
2. Presence of marker file and startup task when reboot is pending.
3. HealthScripts policy result for this script:
   - `FirstDetectExitCode`
   - `RemediationExitCode`
   - `RemediationStatus`
   - `RemediationScriptErrorDetails`
