McAfee removal via Datto RMM
============================

Use this instead of Intune Remediations for clients whose licensing doesn't include Remediations
(e.g. Microsoft 365 Business Premium; Remediations need Windows Enterprise E3/E5, Education A3/A5 or VDA).

Two components, each a small wrapper with the real script attached:

| Component | Category | Script to paste | File to attach | Purpose |
|---|---|---|---|---|
| **IT Zero - McAfee consumer removal** | Scripts | `McAfeeRemoval-Component.ps1` | `mcafee_remediate.ps1` | Removes consumer McAfee. Run daily as a scheduled job. |
| **IT Zero - McAfee consumer present** | Monitors | `McAfeePresent-Monitor.ps1` | `mcafee_detect.ps1` | Alerts if consumer McAfee is still there after a grace period. |

Attach the scripts from the repository's `main` branch. Both wrappers check the attached file's SHA256
against the tested version and refuse to run anything else, and both run the script in **64-bit Windows
PowerShell** even if the Datto agent starts them as a 32-bit process.

Restarts: the removal script never restarts a device. When locked files need a restart it sets Datto's own
`C:\ProgramData\CentraStage\reboot.flag`, and cleanup finishes automatically after the restart.


1. Create the removal component
-------------------------------

1. In the Datto RMM component library, create a **new component**.
2. Name: `IT Zero - McAfee consumer removal`. Category: **Scripts**. Script type: **PowerShell**.
3. Paste the full contents of `datto/McAfeeRemoval-Component.ps1` as the script.
4. Attach the file `mcafee_remediate.ps1` (from the repository root, `main` branch).
5. No variables are needed. Save.


2. Create the monitor component
-------------------------------

1. Create another new component.
2. Name: `IT Zero - McAfee consumer present`. Category: **Monitors**. Script type: **PowerShell**.
3. Paste the full contents of `datto/McAfeePresent-Monitor.ps1` as the script.
4. Attach the file `mcafee_detect.ps1` (repository root, `main` branch).
5. Optional variable: `GraceHours` (number, default `72`) - how long consumer McAfee may remain after the
   monitor first sees it before an alert is raised. This gives the daily removal job and the user's restart
   time to finish.
6. Save.


3. Schedule the removal job (pilot first)
-----------------------------------------

1. Schedule a **job** using the removal component against the pilot devices (or a device filter for them).
2. Recurrence: **daily**, at a time the devices are usually on. It's safe to run repeatedly: on clean devices,
   or devices with managed McAfee/Trellix, it exits within seconds without changes.
3. If the job has a time limit, allow **at least 30 minutes**. A full run takes about 8-9 minutes; the script's
   own limits are 20 minutes per cleanup tool and 10 minutes per uninstaller.
4. After the pilot, widen the job to the client's site(s).


4. Add the monitor
------------------

1. In the client's monitoring policy, add a **component monitor** using `IT Zero - McAfee consumer present`.
2. Run it every few hours (detection takes a few seconds).
3. Set alert priority and ticketing as you would for other endpoint-security alerts. The alert diagnostics
   include the detection output and the last lines of the removal log, so the ticket explains itself.
4. If you later edit the component, re-push the monitoring policy so devices pick up the change.

What the monitor reports:

| Device state | Monitor result | Alert? |
|---|---|---|
| No consumer McAfee | `OK - no consumer McAfee detected` | No |
| Managed McAfee/Trellix present | `OK - managed McAfee/Trellix present, out of scope (...)` | No |
| Removal done, waiting for restart | `OK - McAfee removal waiting for a restart` | No |
| Consumer McAfee, first seen < `GraceHours` ago | `OK - consumer McAfee present, removal pending (...)` | No |
| Consumer McAfee still present after `GraceHours` | `Consumer McAfee still present after Nh (...)` | **Yes** |
| Detection script missing, modified or failing | `Monitor misconfigured ...` / `Detection script failed ...` | **Yes** |

"First seen" is kept in `HKLM\SOFTWARE\ITZero\McAfeeRemoval\FirstDetectedUtc` (writable only by SYSTEM and
administrators) and cleared once the device is clean.


Pilot checks
------------

- On a consumer-McAfee device: job output ends with `exit code 0` (or `1` if a restart is still needed);
  McAfee is gone after the restart; Defender is active; the monitor goes from "removal pending" to
  "no consumer McAfee".
- On a device left with locked files: Datto shows the device as needing a restart **and actually prompts the
  user** (Datto ties its reminder pop-up to its patch-policy reboot logic, so confirm this with your policies).
- On a managed McAfee/Trellix device: job output says "out of scope"; the monitor reports out of scope;
  nothing is changed.
- Confirm the job output's first line shows the 64-bit path
  (`...\System32\WindowsPowerShell\...` or `...\sysnative\WindowsPowerShell\...`).

Logs on the device: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log`
(the same path is used under Datto; the folder is created if Intune isn't present).


Updating the scripts later
--------------------------

When `mcafee_remediate.ps1` or `mcafee_detect.ps1` changes on `main`:

1. Get the new SHA256 (`Get-FileHash .\mcafee_remediate.ps1`).
2. Update `$ExpectedSha256` in the matching wrapper in this folder and commit.
3. In Datto, paste the updated wrapper, re-attach the new script, save, and re-push the monitoring policy.

Until both are updated together, the wrapper refuses to run the new file, by design.

Current pinned versions:

| File | SHA256 |
|---|---|
| `mcafee_remediate.ps1` | `DC8E89E23EE51C3EA093E35822A7ABA50A455B40397124E14C9C5D365E2ADFCF` |
| `mcafee_detect.ps1` | `E7959BFC90B2195BE478BBB24D7735D6E5E776A1721BBDA22BEB444D3CD97B1F` |
