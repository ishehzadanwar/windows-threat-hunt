# Threat-hunter's event-ID cheat sheet

The Windows and Sysmon events a hunter reaches for most, and *why*. This is the reference I used
while hunting — it turns "I don't know where to look" into "I know exactly which event ID answers
this hypothesis."

> In Wazuh, most of these fields live under `data.win.system.*` (the event envelope) and
> `data.win.eventdata.*` (the details). Search event ID with `data.win.system.eventID: "N"`.

## Windows Security log (channel: `Security`)

| Event ID | Meaning | Why a hunter cares |
|:---:|---|---|
| **4624** | Successful logon | The single most important event. Check `LogonType`. |
| **4625** | Failed logon | Clusters = brute force / password spray (T1110). |
| **4634 / 4647** | Logoff | Session timeline. |
| **4648** | Logon with **explicit credentials** | "runas" / one account using another's creds — lateral-movement tell (T1021, T1078). |
| **4672** | **Special privileges** assigned at logon | Someone logged in as admin/SYSTEM. Pair with 4624. |
| **4720** | User account **created** | Backdoor account (T1136). |
| **4722 / 4724** | Account enabled / password reset | Account manipulation (T1098). |
| **4732** | Member added to a **security group** | Privilege escalation (added to Administrators). |
| **4698 / 4702** | Scheduled task **created / updated** | Persistence (T1053.005). |
| **4688** | Process creation (native) | Like Sysmon 1 but less detail; needs audit policy on. |

### Logon types (the `LogonType` field on 4624/4625) — memorize these
| Type | Means | Hunt relevance |
|:---:|---|---|
| **2** | Interactive (at the keyboard) | Normal local login. |
| **3** | **Network** (SMB, file share) | Lateral movement over SMB (T1021.002). |
| **10** | **RemoteInteractive (RDP)** | Lateral movement over RDP (T1021.001). ⭐ |
| **4 / 5** | Batch / Service | Scheduled tasks & services. |
| **9** | NewCredentials | `runas /netonly` — often pass-the-hash style. |

## Sysmon (channel: `Microsoft-Windows-Sysmon/Operational`)

| Event ID | Meaning | Why a hunter cares |
|:---:|---|---|
| **1** | **Process creation** | The workhorse. `Image`, `CommandLine`, `ParentImage`, hashes. LOLBins, encoded PowerShell, weird parent→child chains. |
| **3** | Network connection | Beaconing, C2, data exfil (which process talked to which IP). |
| **7** | Image (DLL) loaded | DLL side-loading, unsigned DLLs in odd processes. |
| **8** | **CreateRemoteThread** | Process injection (T1055). |
| **10** | **ProcessAccess** | One process opening another's memory. `TargetImage=lsass.exe` = credential dumping (T1003.001). ⭐ |
| **11** | File create | Dropped payloads, `.dmp` files, staging. |
| **13** | Registry value set | **Run-key persistence** (T1547.001), config changes. |
| **22** | DNS query | Which process resolved which domain — C2 / exfil domains. |

## Key fields to pivot on

- `data.win.eventdata.image` — the program that ran
- `data.win.eventdata.parentImage` — what launched it (parent→child is where evil hides)
- `data.win.eventdata.commandLine` — the full command
- `data.win.eventdata.targetImage` — the process being accessed (EID 10)
- `data.win.eventdata.sourceImage` — the accessor (EID 10)
- `data.win.eventdata.user` / `subjectUserName` / `targetUserName` — who
- `data.win.eventdata.ipAddress` / `destinationIp` — where from / where to
- `data.win.system.eventID` — which event

## LOLBins to watch (living-off-the-land binaries)

Legit Windows tools attackers abuse so nothing "malicious" has to be downloaded:

`certutil.exe` · `mshta.exe` · `rundll32.exe` · `regsvr32.exe` · `wmic.exe` · `bitsadmin.exe`
`msbuild.exe` · `installutil.exe` · `cscript.exe` · `wscript.exe` · `powershell.exe` · `schtasks.exe`

Reference: [lolbas-project.github.io](https://lolbas-project.github.io/)
