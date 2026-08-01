# Hunt 03 — Registry Run-key persistence (and a telemetry gap)

**Tactic:** Persistence · **Technique:**
[T1547.001 (Registry Run Keys)](https://attack.mitre.org/techniques/T1547/001/)
**Verdict:** True positive · **Coverage:** partial — detected via PowerShell, blind via registry

---

## Hypothesis

An attacker added a **Registry Run-key** so their program relaunches at every login (persistence).
Anything under `HKCU\...\CurrentVersion\Run` (or `HKLM`) is executed automatically at logon.

## Data scoped

- Intended source: **Sysmon Event ID 13** (registry value set)
- Fallback source discovered during the hunt: **PowerShell Script Block Logging (Event ID 4104)**
- Field: `data.win.eventdata.targetObject` (EID 13), `data.win.eventdata.scriptBlockText` (4104)

## Method

Seeded a Run-key entry (T1547.001):

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "HuntCseed" -Value "powershell.exe -NoProfile -Command Write-Host persist" -PropertyType String -Force
```

Hunt query (registry):

```
data.win.system.eventID: "13" and data.win.eventdata.targetObject: *CurrentVersion*Run*
```

## Findings

**The registry hunt returned nothing** — a telemetry blind spot. Sysmon's RegistryEvent (EID 13)
is not surfacing this Run-key write to Wazuh (either not configured for the path, or no Wazuh rule
matches it so it is not indexed — the same "you can't detect/search what a rule doesn't match"
pattern seen with Sysmon EID 10).

**But the activity was caught by a different sensor.** In the main event view, rule **91844,
level 12 — "Possible addition of new item to Windows startup registry"** fired, sourced from
**PowerShell Script Block Logging (Event ID 4104)**:

```
scriptBlockText: New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                 -Name "HuntCseed" -Value "powershell.exe -NoProfile -Command Write-Host persist" ...
channel: Microsoft-Windows-PowerShell/Operational
```

The persistence was recorded because it was created **using PowerShell**, and Script Block Logging
captured the command.

## Two lessons

1. **One attack leaves traces in multiple data sources.** The registry lens was blind; the
   PowerShell lens caught it. Pivoting across sources is core hunting tradecraft.
2. **That coverage is fragile.** Had the Run key been written with `reg.exe` or a compiled binary
   instead of PowerShell, the 4104 event would never have fired — and with EID 13 blind, the
   persistence would have gone completely unseen.

## Verdict

**True positive** — the seed was detected, but only through PowerShell 4104 (rule 91844). The
registry data source (EID 13) is a blind spot.

## Detection gap & follow-up

**Real gap found.** Enable Sysmon **RegistryEvent (EID 13)** monitoring for autorun locations
(`\CurrentVersion\Run`, `\RunOnce`, services, etc.) and add a Wazuh rule that alerts on writes to
them. This makes persistence detection **source-independent** — it fires regardless of whether the
Run key was set by PowerShell, `reg.exe`, or malware. (This is the same class of fix applied to
Sysmon ProcessAccess/EID 10 in the Detection-Engineering project.)

## Cleanup

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "HuntCseed"
```

## Reusable hunt queries

```
# registry Run-key writes (needs Sysmon EID 13 enabled for these paths)
data.win.system.eventID: "13" and data.win.eventdata.targetObject: *CurrentVersion*Run*

# fallback: persistence set via PowerShell (Script Block Logging)
data.win.system.eventID: "4104" and data.win.eventdata.scriptBlockText: *CurrentVersion*Run*
```
