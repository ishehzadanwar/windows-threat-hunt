# Hunt 01 — Shell spawned by an unusual parent (WMI)

**Tactic:** Execution · **Techniques:** [T1047 (WMI)](https://attack.mitre.org/techniques/T1047/),
[T1059.001 (PowerShell)](https://attack.mitre.org/techniques/T1059/001/)
**Verdict:** True positive (authorized red-team) · **Coverage:** already detected

---

## Hypothesis

A malicious document, script, or lateral-movement tool spawned a command shell. The program
(`powershell.exe`) looks normal, but the **parent process** gives it away — a shell launched by
something that has no business launching one (mshta, wscript, or `WmiPrvSE.exe`) is suspicious.

## Data scoped

- Source: **Sysmon Event ID 1** (process creation)
- Fields: `data.win.eventdata.image` (child), `data.win.eventdata.parentImage` (parent)
- Window: last 15 days

## Method

Seeded one known-good example so the hunt had a guaranteed target — a shell spawned via **WMI**
(a real technique, T1047), which makes the parent `WmiPrvSE.exe`:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell.exe -NoProfile -Command Write-Host HuntBseed'}
```

> An earlier attempt seeded `mshta.exe → powershell.exe`, but it produced **no telemetry** — a
> hunt finding in itself. mshta spawning a process is heavily blocked/inspected, so either
> Defender killed it or the script engine didn't fire. Switched to WMI, which is a legitimate
> cmdlet that reliably produces the suspicious parent.

Hunt query:

```
data.win.eventdata.image: *powershell.exe* and data.win.eventdata.parentImage: *wbem*
```

(`*wbem*` matches the folder in `C:\Windows\System32\wbem\WmiPrvSE.exe` and sidesteps the
upper/lowercase matching problem with `WmiPrvSE`.)

## Findings

Four PowerShell processes with a `WmiPrvSE.exe` parent, across two days:

| Timestamp | Rule | Level | Command line |
|---|---|:---:|---|
| Aug 1 04:46 | 92070 | 6 | `powershell.exe -NoProfile -Command Write-Host HuntBseed` (the seed) |
| Jul 25 12:08 | 92071 | 12 | `powershell.exe -NoProfile -E VwByAG...` (base64 encoded) |
| Jul 25 11:58 | 92071 | 12 | `powershell.exe -NoProfile -E VwByAG...` (base64 encoded) |
| Jul 25 11:52 | 92071 | 12 | `powershell.exe -NoProfile -E VwByAG...` (base64 encoded) |

Key fields on the events:
- `parentImage` = `C:\Windows\System32\wbem\WmiPrvSE.exe`
- `parentCommandLine` = `wmiprvse.exe -secured -Embedding`
- `parentUser` = `NT AUTHORITY\NETWORK SERVICE`

The three Jul-25 events are **WMI spawning PowerShell to run an obfuscated (base64) command** —
a genuinely malicious pattern (T1047 + T1059.001 + T1027). They had been sitting in the logs for
7 days, unreviewed. That is the value of hunting: surfacing activity no alert triage was looking at.

## Verdict

**True positive**, traced to authorized red-team activity — the Jul-25 events are the
Detection-Engineering project's Atomic Red Team tests, and the Aug-1 event is this hunt's seed.
No unknown adversary. In a production environment, `WmiPrvSE.exe → powershell.exe -E <base64>`
would be treated as a serious incident.

## Detection gap & follow-up

**No gap** — Wazuh already covers this:
- `92070` (WMI created a PowerShell process) — level 6
- `92071` (WMI created a PowerShell process running a base64-encoded command) — level 12

The hunt **confirmed existing coverage** rather than exposing a hole, which is a valid result. The
reusable hunt query (`image: powershell.exe AND parentImage: *wbem*`) is worth keeping as a saved
search for periodic hunting.

## Reusable hunt query

```
data.win.eventdata.image: *powershell.exe* and data.win.eventdata.parentImage: *wbem*
```

Generalize by swapping the parent for other unusual launchers: `*mshta*`, `*wscript*`,
`*cscript*`, `*winword*`, `*excel*`, `*outlook*`.
