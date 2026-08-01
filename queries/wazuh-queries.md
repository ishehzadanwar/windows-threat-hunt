# Wazuh hunt queries

Every query used in these hunts, ready to paste into **Threat Hunting → search bar** (DQL). Set the
time range on the top-right before running.

## Sanity / baseline

```
# all Sysmon process-creation events (is telemetry flowing?)
data.win.system.eventID: "1"
```

## Hunt 1 — shell spawned by an unusual parent (T1047 / T1059.001)

```
# shells launched via WMI (parent is WmiPrvSE.exe in the \wbem\ folder)
data.win.eventdata.image: *powershell.exe* and data.win.eventdata.parentImage: *wbem*

# generalise to other suspicious launchers
data.win.eventdata.image: *powershell.exe* and (data.win.eventdata.parentImage: *mshta* or data.win.eventdata.parentImage: *wscript* or data.win.eventdata.parentImage: *cscript* or data.win.eventdata.parentImage: *winword* or data.win.eventdata.parentImage: *excel*)

# find a specific seeded command by its marker
data.win.eventdata.commandLine: *HuntBseed*
```

Seed used:
```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell.exe -NoProfile -Command Write-Host HuntBseed'}
```

## Hunt 2 — anomalous logons (T1110 / T1078)

```
# failed logons — bursts = brute force
data.win.system.eventID: "4625"

# privileged logons — baseline, scan for anomalies
data.win.system.eventID: "4672"

# lateral movement (needs 2+ hosts): RDP (type 10) and SMB (type 3) logons
data.win.system.eventID: "4624" and (data.win.eventdata.logonType: "10" or data.win.eventdata.logonType: "3")
```

Key 4625 pivot fields: `targetUserName`, `subStatus` (`0xC0000064` = user doesn't exist,
`0xC000006A` = bad password), `ipAddress`, `logonType`.

## Hunt 3 — Registry Run-key persistence (T1547.001)

```
# registry Run-key writes (needs Sysmon EID 13 enabled for these paths)
data.win.system.eventID: "13" and data.win.eventdata.targetObject: *CurrentVersion*Run*

# fallback: persistence set via PowerShell (Script Block Logging)
data.win.system.eventID: "4104" and data.win.eventdata.scriptBlockText: *CurrentVersion*Run*
```

Seed used:
```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "HuntCseed" -Value "powershell.exe -NoProfile -Command Write-Host persist" -PropertyType String -Force
# cleanup:
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "HuntCseed"
```

## DQL tips learned

- `*text*` = wildcard (any characters around `text`).
- `and` / `or` combine conditions; use **parentheses** to group ORs: `A and (B or C)`.
- Wildcards can be **case-sensitive** on keyword fields — matching the folder (`*wbem*`) instead of
  the mixed-case process name (`WmiPrvSE`) is more reliable.
- Wazuh only stores/searches events that **match a rule** — if a raw event has no rule, it won't
  appear (seen with Sysmon EID 10 and EID 13).
