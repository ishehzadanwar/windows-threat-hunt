# Hunt 02 — Anomalous logons (brute force / privileged access)

**Tactics:** Credential Access, Defense Evasion · **Techniques:**
[T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/),
[T1078 (Valid Accounts)](https://attack.mitre.org/techniques/T1078/)
**Verdict:** True positive (authorized) + benign · **Coverage:** already detected

---

## Hypothesis

An attacker either guessed a password (a burst of failed logons) or logged on with privileges
they should not have. Both are visible in the Windows Security log.

## Data scoped

- Source: **Windows Security log**
- Events: **4625** (failed logon), **4672** (special privileges assigned)
- Window: last 15 days

## Method & findings

### Part 1 — failed logons (4625)

```
data.win.system.eventID: "4625"
```

**14 hits, all clustered on Jul 23 at 09:24** — timestamps milliseconds apart
(`.975`, `.958`, `.943`, `.927` ...). Pivoted into one event:

| Field | Value | Interpretation |
|---|---|---|
| `targetUserName` | `evilhacker` | account being guessed |
| `subStatus` | `0xC0000064` | **"user name does not exist"** — spraying a nonexistent account |
| `logonType` | `2` | interactive logon attempts |
| `ipAddress` | `::1` | localhost (simulated attacker) |
| `subjectUserName` | `roota` | context it ran under |

Among the 14, Wazuh also fired **rule 60204 "Multiple Windows Logon Failures" (level 10)** — the
correlation engine collapsing the burst into one higher-severity alert.

**Hunter's tell:** 14 failures against a single nonexistent account in under one second is a
brute-force / password-spray pattern, not a mistyped password. A real user fails 2–3 times on
*their own* username, spread over seconds or minutes.

### Part 2 — privileged logons (4672)

```
data.win.system.eventID: "4672"
```

10 "Special privileges assigned to new logon" events (rule 67028, level 3) spread across several
days. This is the baseline view a hunter scans for a privileged logon that doesn't fit — an
unexpected account or an odd hour. All of these matched authorized admin sessions.

## Verdict

- **4625:** True positive — the burst is the Home-SOC project's brute-force test. Real attack
  pattern, authorized source (`::1`).
- **4672:** Benign — every privileged logon lines up with my own admin activity. No anomaly.

## Detection gap & follow-up

**No gap.** Rule 60204 already correlates a failed-logon burst into a level-10 alert. The hunt
confirmed existing coverage.

Follow-up idea for maturity: a **workstation-to-workstation** logon hunt using 4624 `logonType: 3`
(SMB) and `logonType: 10` (RDP) from unexpected internal source IPs would catch lateral movement —
which this single-endpoint lab can't produce, but is the natural next hunt with a second host.

## Reusable hunt queries

```
# failed-logon bursts (brute force)
data.win.system.eventID: "4625"

# privileged logons to baseline / scan for anomalies
data.win.system.eventID: "4672"

# lateral movement (needs 2+ hosts): RDP and SMB logons
data.win.system.eventID: "4624" and (data.win.eventdata.logonType: "10" or data.win.eventdata.logonType: "3")
```
