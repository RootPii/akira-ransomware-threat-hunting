# detection/rule_logic.md
# Akira Ransomware — Detection Logic Reference

**Purpose:** Define what to detect, why it matters, what telemetry supports it, and how to build reliable
detection logic around Akira's observed behaviors.  
**Audience:** Detection engineers, SOC analysts, threat hunters.  
**Based on:** CISA AA24-109A (Nov 2025), Unit 42 Howling Scorpius (Nov 2025), Sophos MDR, IBM X-Force,
Arctic Wolf Labs (Sep 2025), Picus Security (Feb 2026), AttackIQ emulation (Nov 2025).

> This is not a Sigma rule file. It's the thinking layer — what the rules should be based on,
> why those conditions matter, and how to correlate signals into confident findings.
> Sigma rules should be built from the logic documented here.

---

## Detection Philosophy

Akira affiliates do not operate in ways that generate a single clean alert. Most observed behaviors
rely on legitimate tools, living-off-the-land binaries, and dual-use utilities. Behavioral detection
is more reliable than static IOC matching across campaigns — hashes and IPs rotate, but the
underlying behaviors repeat.

- **Correlate weak signals, not individual events.** Most events in this document look benign in
  isolation. Velocity, sequencing, and session context are what make them suspicious.
- **Prioritize pre-encryption detection.** Data is exfiltrated before encryption. Credentials are
  stolen before lateral movement. Detection windows exist at each stage.
- **Work the session window.** Documented intrusions have moved from VPN login to encryption in
  as little as 55 minutes. A high-confidence indicator warrants immediate backward and forward
  review of the same session window.
- **Behavioral over static.** IOC matching has a role, but LSASS access, Ngrok DNS queries, and
  VSS deletion repeat across campaigns regardless of tooling changes.

**Assumption:** Sysmon is deployed with a tuned configuration that includes ProcessAccess, DNS,
DriverLoad, and network telemetry. Without this, several detections below will not fire.

---

## Log Sources Required

Before anything else: if these aren't configured, key detections won't fire.

| Source | Why It Matters |
|---|---|
| Sysmon (EID 1, 3, 6, 10, 11, 22) | Process creation, network connections, driver loads, LSASS access, file events, DNS queries |
| Windows Security Logs (EID 4624, 4648, 4698, 4720, 4732, 4769, 1102) | Logon events, account lifecycle, Kerberos, task creation, log clearing |
| Windows System Logs (EID 7036, 104) | Service state changes, System log clearing |
| PowerShell Script Block Logging (EID 4104) | Decoded command content — required to catch obfuscated commands |
| VPN / Firewall Auth Logs | Initial access — often the earliest artifact available |
| NetFlow / NDR | Lateral scan patterns, high-volume egress, C2 tunnel persistence |
| Hypervisor / ESXi Management Logs | SSH access, VM shutdowns, datastore changes |
| DNS Query Logs | Ngrok/Cloudflare tunnel detection — high-confidence early signal |

If Script Block Logging (EID 4104) is not enabled, PowerShell-based shadow copy deletion and
obfuscated staging commands will not be visible. This is a common detection gap.

---

## 1. Initial Access

### What to Detect

First-time successful VPN or RDP authentication from an external IP with no prior session history
for that account. No MFA event associated with the login.

### Why It Matters

Nearly all observed Akira intrusions start here. Credentials are purchased from initial access
brokers or obtained through brute force. In IAB cases, the login looks legitimate unless baselined.

### Telemetry

- VPN appliance auth logs (SonicWall, Cisco ASA, Fortinet)
- Win Security EID 4624 — Logon Type 3 or Type 10
- EID 4648 — Explicit credential use

### Detection Logic

```
Condition:
- Successful auth from an external IP with no prior login history for this account
- No preceding MFA event for this session
- Logon time outside established business hours for this account

Alert threshold: Any single match.
```

**Correlation:** If followed within 5–15 minutes by recon commands (see Section 3), confidence
jumps significantly.

**Baseline dependency:** Requires a prior logon baseline per account. Build the baseline first —
without it, first-seen IP alerting generates noise.

**Investigation start:** Pull all events from the source IP across all logs from the moment of
first auth. Recon typically starts within minutes.

---

## 2. Credential Access

### 2a. LSASS Memory Dump via comsvcs.dll

#### What to Detect

`rundll32.exe` invoking `comsvcs.dll` with `MiniDump` (or alternate export alias `#24`) targeting
the LSASS process.

#### Why It Matters

The primary credential dumping method observed across Akira incidents. Uses a built-in Windows DLL —
no external tooling dropped. By the time this fires, assume credentials are already extracted. Treat
as an escalation trigger, not just an alert.

#### Telemetry

- Sysmon EID 10 — ProcessAccess on `lsass.exe`, calling process is `rundll32.exe`
- Sysmon EID 1 — `rundll32.exe` with `comsvcs.dll` in command line

#### Detection Logic

```
Condition A (process access):
- Sysmon EID 10
- target_process = "lsass.exe"
- source_process = "rundll32.exe"
- source_process NOT IN [known_security_tools_allowlist]

Condition B (command line):
- process_name = "rundll32.exe"
- command_line CONTAINS "comsvcs.dll"
- command_line CONTAINS "MiniDump" OR "#24"
```

**False positives:** Rare. Some endpoint products access LSASS legitimately — maintain an allowlist
of known security tool processes and exclude them.

**Next step when fired:** Check for lateral movement in the same session window — `wmiexec` or
PsExec typically follow within 30–60 minutes.

---

### 2b. NTDS.dit Extraction via ntdsutil

#### What to Detect

`ntdsutil.exe` running with `ifm` and `create full` arguments, writing output to a non-standard path.

#### Why It Matters

Extracts the entire AD credential database offline. No LSASS access required — LSASS-based
detections will not catch this. With NTDS.dit and the SYSTEM hive, every domain credential
is available for offline cracking.

#### Telemetry

- Sysmon EID 1 — `ntdsutil.exe` with `ifm` and `create full` in command line
- EID 4688 (if process command line auditing is enabled)
- File creation events in staging paths (e.g., `C:\ProgramData\`)

#### Detection Logic

```
Condition (primary):
- process_name = "ntdsutil.exe"
- command_line CONTAINS "ifm"
- command_line CONTAINS "create full"

Secondary check:
- File created: *.dit outside C:\Windows\NTDS
- File created: SYSTEM hive copy in a writable directory
```

**Note:** There is almost no legitimate operational use of this command outside a planned ADFS or
RODC deployment. Any instance on a production DC should be treated as a confirmed compromise.

---

### 2c. Kerberoasting

#### What to Detect

Unusual RC4-encrypted TGS requests from a non-service account, particularly a burst of requests
from a single source.

#### Why It Matters

Kerberoasting does not touch LSASS — it operates entirely over standard Kerberos protocol calls.
Credential dumping alerts will not fire. The detection window is at the request stage, before
offline cracking begins.

#### Telemetry

- Win Security EID 4769 — Kerberos service ticket request
  - Filter: `TicketEncryptionType = 0x17` (RC4-HMAC)
  - Filter: requesting account is not a service account (no `$` suffix, no SPN registered)

#### Detection Logic

```
Condition:
- EID 4769
- TicketEncryptionType = 0x17
- requesting_account NOT LIKE "%$"
- requesting_account NOT IN [service_accounts_baseline]

Elevated confidence:
- 5+ EID 4769 events with 0x17 from the same account within 10 minutes
```

**Baseline note:** RC4 TGS requests are normal in some legacy environments. New accounts with no
prior TGS history requesting RC4 tickets are the cleaner signal.

---

### 2d. Veeam Credential Extraction

#### What to Detect

PowerShell or cmd executing against Veeam backup service processes or configuration files, or
exploitation indicators related to CVE-2023-27532.

#### Why It Matters

Veeam credentials often carry broad domain-level access. Operators consistently target Veeam
servers when present — extracted credentials can enable lateral movement paths that bypass LSASS.

#### Telemetry

- Sysmon EID 1 — PowerShell spawning from a Veeam service context, or unusual process accessing
  Veeam configuration database
- Network: incoming connections to Veeam server on port 9401 (CVE-2023-27532 exploitation path)

#### Detection Logic

```
Condition (credential extraction):
- Parent process is a remote session
- child_process = "powershell.exe"
- command_line CONTAINS Veeam-related strings ("VeeamBackup", "Get-Creds")

Condition (CVE-2023-27532):
- Inbound connection to Veeam server on TCP 9401 from unexpected internal IP
```

---

## 3. Reconnaissance / Discovery

### 3a. Scripted Recon Burst

#### What to Detect

Five or more native Windows discovery commands executing within a short window from the same
parent process or session.

#### Why It Matters

Individually, `whoami`, `ipconfig`, `net user`, `arp -a`, `route print` are benign. Executed in
rapid succession from a remote session, they indicate scripted environment enumeration — consistent
across all documented Akira intrusion timelines.

#### Telemetry

- Sysmon EID 1 — multiple process creation events from same parent (cmd.exe or powershell.exe)
- EID 4688 (if process auditing enabled)

#### Detection Logic

```
Condition:
- Within 5 minutes:
  Count of unique process names from {whoami.exe, ipconfig.exe, arp.exe, route.exe,
  net.exe, netstat.exe, hostname.exe, systeminfo.exe, nltest.exe} >= 5
- All processes share the same parent PID or session ID
- Parent process originated from a remote logon event
```

**Tuning note:** Anchor to the preceding logon event. The same commands run from an admin
workstation during troubleshooting look similar — session context is the differentiator.

---

### 3b. nltest Domain Controller Enumeration

#### What to Detect

`nltest.exe` executing with `/dclist:` or `/DOMAIN_TRUSTS` flags from a non-admin context.

#### Why It Matters

Explicitly called out in CISA AA24-109A. Used to identify domain controllers before pivoting.
Execution from a workstation outside domain admin context is suspicious.

#### Telemetry

- Sysmon EID 1 — `nltest.exe` with enumeration flags

#### Detection Logic

```
Condition:
- process_name = "nltest.exe"
- command_line CONTAINS "/dclist:" OR "/DOMAIN_TRUSTS" OR "/domain_trusts"
- executing_user NOT IN [domain_admin_group]
- parent_process originated from a remote session
```

---

### 3c. AD Enumeration — SharpHound / AdFind

#### What to Detect

SharpHound or AdFind executing from any non-admin or non-management host. SharpHound output ZIP
in a temp directory is a reliable post-execution artifact.

#### Why It Matters

SharpHound and AdFind output feeds lateral movement planning. Finding this artifact indicates
the domain has already been mapped — lateral movement to high-value systems typically follows.

#### Telemetry

- Sysmon EID 1 — known tool names, or binaries with characteristic command-line patterns
- Sysmon EID 11 — `.zip` file creation in `%TEMP%`, `C:\Users\Public\`, `C:\Windows\Temp\`
- Win Security EID 4661 / 4662 — directory object access burst

#### Detection Logic

```
Condition (tool execution):
- process_name IN ["SharpHound.exe", "adfind.exe"]
- NOT executing from a known IT management host

Condition (output artifact):
- File created: *.zip in %TEMP%, C:\Users\Public\, or C:\Windows\Temp\
- file_size > 100KB
- creation time correlates with a remote session

Condition (LDAP burst):
- More than 100 EID 4662 events from one account within 5 minutes
- targeting CN=Users or OU objects
```

**Investigation note:** If a SharpHound ZIP is found, check its creation timestamp against
authentication logs to anchor it in the intrusion timeline.

---

### 3d. Internal Network Scan

#### What to Detect

A single internal host connecting to many unique internal IPs on ports 445, 3389, or 22 within
a short window.

#### Why It Matters

Pre-lateral-movement scanning to map reachable hosts. The NetFlow pattern is often more reliable
than detecting the scanner binary, which may be renamed or run from memory.

#### Telemetry

- NetFlow / NDR: one source IP contacting many unique internal destinations
- Sysmon EID 3: high volume of outbound connections on port 445/3389/22 from one host

#### Detection Logic

```
Condition:
- Source IP = single internal host
- Destination count > 20 unique internal IPs
- Destination port IN [445, 3389, 22]
- Time window = 10 minutes

False positive check: exclude known IT management hosts running authorized vulnerability scans
```

---

## 4. Persistence

### 4a. Account Creation + Immediate Privilege Escalation

#### What to Detect

EID 4720 (account created) followed within minutes by EID 4732 (added to Administrators group)
for the same account.

#### Why It Matters

One of the most consistent Akira persistence behaviors across incidents. Account names vary —
`itadm`, `svcadmin` appear in reports — but the rapid creation-to-escalation sequence is the
reliable signal. No legitimate provisioning workflow produces a gap of seconds between account
creation and admin group membership outside of automation.

#### Telemetry

- Win Security EID 4720 — account created
- Win Security EID 4732 — added to local Administrators group

#### Detection Logic

```
Condition:
- EID 4720 (account created)
- FOLLOWED BY EID 4732 for the same account
- Time delta < 5 minutes
- Creation not associated with a known provisioning system or change ticket

Elevated confidence:
- New account authenticates elsewhere (EID 4624 on other hosts) within 30 minutes of creation
```

---

### 4b. Scheduled Task — Binary in Writable Directory

#### What to Detect

A scheduled task created pointing to a binary in `C:\Users\Public\`, `C:\Windows\Temp\`, or
similar user-writable paths, running as SYSTEM.

#### Why It Matters

Provides callback persistence that survives reboots. SYSTEM-context tasks pointing to writable
user directories have no legitimate explanation.

#### Telemetry

- Win Security EID 4698 — scheduled task created
- Task Scheduler EID 106 — task registered
- Sysmon EID 1 — task binary execution (follow-on)

#### Detection Logic

```
Condition:
- EID 4698
- task_action_path CONTAINS "C:\Users\Public" OR "C:\Windows\Temp" OR "%APPDATA%"
- task_run_as = "SYSTEM" OR "NT AUTHORITY\SYSTEM"
- creating_user is not a known automation account
```

---

## 5. C2 and Tunneling

### 5a. Ngrok DNS Query from Internal Host

#### What to Detect

Internal host resolving `*.ngrok.io` or `*.ngrok-free.app`.

#### Why It Matters

One of the highest-confidence Akira indicators available without endpoint visibility. Ngrok is
rarely used legitimately in enterprise environments. CISA explicitly calls this out in the
November 2025 advisory.

#### Telemetry

- DNS query logs (internal resolver or endpoint DNS)
- Sysmon EID 22 — DNS query event

#### Detection Logic

```
Condition:
- dns_query MATCHES "*.ngrok.io" OR "*.ngrok-free.app"
- source is an internal host

No additional conditions required — alert on any match in enterprise environments.

Cloudflare Tunnel alternative:
- dns_query MATCHES "*.trycloudflare.com"
```

**Note:** False positive rate is very low in most corporate networks. Treat any match as
requiring immediate investigation.

---

### 5b. Remote Access Tool — Silent Install from Writable Path

#### What to Detect

AnyDesk, LogMeIn, RustDesk, or similar RAT binaries executing with silent install flags from
a non-standard path.

#### Why It Matters

Installed as backup C2 channels. The detection differentiation from legitimate IT use is the
combination of installation path (not `Program Files`) and silent install flags, correlated
with other suspicious session activity.

#### Telemetry

- Sysmon EID 1 — RAT binary with `--silent` or `/S` flags
- Sysmon EID 3 — outbound connection to vendor relay infrastructure
- Sysmon EID 11 — binary drop to non-standard path

#### Detection Logic

```
Condition:
- process_name IN ["AnyDesk.exe", "LogMeIn.exe", "rustdesk.exe"]
- command_line CONTAINS "--silent" OR "/S" OR "--install"
- process_path NOT CONTAINS "Program Files"

Correlation: Occurrence within 60 minutes of new account creation or LSASS access —
escalate immediately.
```

---

## 6. Lateral Movement

### 6a. RDP from Workstation to Domain Controller

#### What to Detect

Logon Type 10 on a domain controller sourced from a workstation.

#### Why It Matters

Legitimate admin access to domain controllers should come from designated management hosts or
jump servers. Workstation-to-DC RDP is consistently the lateral movement step that gives
operators domain controller access for credential database extraction.

#### Telemetry

- Win Security EID 4624 — Logon Type 10 on DC
- EID 4648 — alternate credential use

#### Detection Logic

```
Condition:
- EID 4624 on a domain controller
- logon_type = 10
- source_host NOT in [designated management/jump host list]
- source_host is a standard workstation

Elevated confidence:
- Authenticating account was recently created (correlate with EID 4720 timestamp)
- OR source_host had a suspicious external logon earlier in the session
```

---

### 6b. WmiPrvSE Spawning cmd.exe or PowerShell

#### What to Detect

`WmiPrvSE.exe` (WMI Provider Service) spawning `cmd.exe`, `powershell.exe`, or similar shells
on a target system.

#### Why It Matters

The Impacket `wmiexec` footprint on victim systems. Commands execute remotely over WMI — agentless
and fileless on the target side. The only artifact is the process tree on the target. Rarely
legitimate and should alert with high confidence.

#### Telemetry

- Sysmon EID 1 — `cmd.exe` or `powershell.exe` with parent `WmiPrvSE.exe`

#### Detection Logic

```
Condition:
- parent_process = "WmiPrvSE.exe"
- process_name IN ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]

False positives: Some WMI-based management solutions create this pattern.
Build an exclusion list for known-good tools and alert on everything else.
```

---

### 6c. SSH from Windows Workstation to Internal Server

#### What to Detect

`ssh.exe` or `plink.exe` executing on a Windows workstation, making outbound TCP 22 connections
to internal infrastructure — particularly ESXi or Linux hosts.

#### Why It Matters

Outbound SSH from a standard Windows workstation to internal servers has limited legitimate use.
This is the path used to reach ESXi hypervisors for Akira_v2 deployment. The June 2025 incident
involving Nutanix AHV followed this pattern.

#### Telemetry

- Sysmon EID 1 — `ssh.exe` or `plink.exe` executing
- Sysmon EID 3 — outbound TCP 22 to an internal server IP
- Hypervisor auth logs

#### Detection Logic

```
Condition:
- process_name IN ["ssh.exe", "plink.exe"]
- destination is an internal IP
- source is a standard Windows workstation (not a designated admin host)

Elevated: destination resolves to an ESXi or Nutanix management IP
```

---

## 7. Defense Evasion

### 7a. Windows Defender Disabled via PowerShell

#### What to Detect

`Set-MpPreference -DisableRealtimeMonitoring $true` executed via PowerShell, particularly with
`-ExecutionPolicy Bypass`.

#### Why It Matters

Consistently observed before payload staging or exfiltration. Commands may be encoded —
Script Block Logging decodes them.

#### Telemetry

- Sysmon EID 1 — `powershell.exe` with `-ExecutionPolicy Bypass` or `-enc`
- PowerShell EID 4104 — decoded script block containing `Set-MpPreference`

#### Detection Logic

```
Condition A (script block):
- EID 4104 script block CONTAINS "Set-MpPreference" AND "DisableRealtimeMonitoring"

Condition B (command line):
- process_name = "powershell.exe"
- command_line CONTAINS "DisableRealtimeMonitoring" AND "true"
```

---

### 7b. Malicious Driver Load — POORTRY / STONESTOP

#### What to Detect

A kernel driver loading from a user-writable directory (`C:\Users\Public\`, `C:\Windows\Temp\`)
with an anomalous, revoked, or unexpected signature.

#### Why It Matters

POORTRY (also tracked as ABYSSWORKER / BurntCigar) is a signed malicious kernel driver used in
2025 Akira incidents to kill EDR processes. Newer variants delete security tool files entirely.
Once the driver loads, endpoint visibility may be immediately compromised.

#### Telemetry

- Sysmon EID 6 — DriverLoad event (check image path and signing certificate)
- Security agent process termination (no preceding stop command)

#### Detection Logic

```
Condition A (path-based):
- Sysmon EID 6
- driver_image_path CONTAINS "C:\Users\Public" OR "C:\Windows\Temp" OR "%APPDATA%"

Condition B (signature-based):
- Sysmon EID 6
- driver_signature status is revoked, expired, or not from a trusted vendor

Correlated alert:
- Security process (EDR agent) terminates within 60 seconds of a suspicious DriverLoad event
- AND no preceding service stop or update event for that agent
```

---

### 7c. Log Clearing — EID 1102 + EID 104

#### What to Detect

Security log cleared (EID 1102) and System log cleared (EID 104) in the same session window.

#### Why It Matters

Occurs in the same window as VSS deletion, just before encryption. Log forwarding to a SIEM
preserves these events even after local clearing — this is why remote log forwarding matters.

#### Telemetry

- Win Security EID 1102 — Security log cleared
- Win System EID 104 — System log cleared

#### Detection Logic

```
Condition:
- EID 1102 on any production host
- NOT associated with a documented IR test, compliance activity, or authorized admin action

Elevated confidence:
- EID 1102 AND EID 104 within the same 10-minute window on the same host
- AND VSS deletion activity (see Section 8) in the same session
```

---

## 8. Exfiltration

### 8a. Rclone Executing Outside Program Files

#### What to Detect

`rclone.exe` (or any binary with Rclone-characteristic command-line arguments) executing from
`C:\Users\Public\`, `C:\Windows\Temp\`, or other non-standard paths.

#### Why It Matters

The most consistently observed exfiltration tool across Akira incidents. Syncs directly to cloud
storage — most often Mega — at high throughput. Has been renamed to blend in (`svchost.exe` is a
documented example). Path and outbound traffic volume are the primary detection signals.

#### Telemetry

- Sysmon EID 1 — `rclone.exe` or binary with Rclone-like flags (`--transfers`, `--multi-thread-streams`)
- Sysmon EID 3 — high-volume outbound connections to Mega or other cloud storage
- NetFlow — sustained high-volume egress from single internal host

#### Detection Logic

```
Condition A (binary name):
- process_name = "rclone.exe"
- process_path NOT CONTAINS "Program Files"

Condition B (command line — catches renamed binary):
- Any binary
- command_line CONTAINS "--multi-thread-streams" OR "--transfers" OR "remote:"
- process_path NOT CONTAINS "Program Files"

NetFlow correlation:
- Single internal host with sustained outbound > 500 MB in under 30 minutes
- Destination is a cloud storage IP range (Mega, Dropbox, etc.)
```

**Investigation note:** If Rclone is found, check for WinRAR or 7-Zip archive creation in the
same timeframe — staging precedes transfer. Check archive write times against session logs.

---

### 8b. FileZilla / WinSCP Forensic Artifacts

#### What to Detect

MRU registry entries, application configuration files, or process creation for FileZilla or
WinSCP on hosts that have no documented need for SFTP clients.

#### Why It Matters

In the Unit 42 November 2025 incident, approximately 1 TB was exfiltrated via FileZillaPortable
before encryption. Both tools leave registry and filesystem artifacts even after the binary
is deleted.

#### Telemetry

- Registry: `HKCU\Software\FileZilla3\RecentServers` — contains server and credential history
- Registry: WinSCP MRU entries under `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`
- Sysmon EID 1 — process creation for `FileZillaPortable.exe` or `WinSCP.exe`

#### Detection Logic

```
Condition:
- Registry key access or creation under FileZilla3\RecentServers or WinSCP 2\Sessions
- accessing_process is not an approved IT tool
- host is not a designated file transfer system

Hunting query: scan for these registry keys across the fleet for recent writes
```

---

## 9. Pre-Encryption Signals

These are the most urgent detections in this document. By the time these fire, encryption is
either imminent or already underway. Trigger immediate containment — not just a high-priority ticket.

### 9a. VSS Deletion — Any Method

#### What to Detect

Any process executing shadow copy deletion via `vssadmin`, `wmic`, or PowerShell WMI.

#### Why It Matters

Present in nearly every documented Akira attack immediately before encryption. IBM X-Force
confirmed that Akira's encryptor deletes shadow copies via COM objects — not by spawning
`vssadmin.exe` — so rules that only watch for the `vssadmin` process will miss COM-based deletion.
There is no legitimate operational reason to delete all shadow copies on a production host.

#### Telemetry

- Sysmon EID 1 — `vssadmin.exe delete shadows`
- Sysmon EID 1 — `wmic.exe shadowcopy delete`
- PowerShell EID 4104 — script block containing `Win32_ShadowCopy` with `Remove-WmiObject` or `.Delete()`
- WMI activity logs — VSS deletion via COM

#### Detection Logic

```
Condition A (vssadmin):
- process_name = "vssadmin.exe"
- command_line CONTAINS "delete shadows"

Condition B (wmic):
- process_name = "wmic.exe"
- command_line CONTAINS "shadowcopy" AND "delete"

Condition C (PowerShell WMI — catches COM-based deletion):
- EID 4104 script block CONTAINS "Win32_ShadowCopy"
- AND script block CONTAINS "Remove-WmiObject" OR ".Delete()"

Alert priority: CRITICAL on any match.
```

**Important:** Condition C requires PowerShell Script Block Logging (EID 4104). Without it,
COM-based shadow copy deletion is invisible to process-based detections.

---

### 9b. Service Stop — Backup Agents and Databases

#### What to Detect

`net stop` or `sc stop` targeting known backup agent services (Veeam, BackupExec, Windows Backup)
or database services in rapid succession.

#### Why It Matters

Services are stopped before encryption to release file locks. Veeam Backup Service is explicitly
called out across multiple Akira incident reports as a consistent target. Multiple backup and
database services stopping in the same session window as VSS deletion is a near-certain
pre-encryption indicator.

#### Telemetry

- Win Security EID 4688 — `net.exe` with stop argument
- Win System EID 7036 — service entered stopped state

#### Detection Logic

```
Condition:
- process_name = "net.exe"
- command_line CONTAINS "stop"
- service_name IN ["VeeamBackupSvc", "VeeamTransportSvc", "MSSQLSERVER", "OracleService",
  "SQLSERVERAGENT", "wbengine", "BackupExecAgentAccelerator", "BackupExecJobEngine"]

Elevated confidence:
- 3+ stop events on backup/DB services within 10 minutes
- AND VSS deletion in the same session window
```

---

### 9c. File Permission Modification via icacls

#### What to Detect

`icacls.exe` granting broad permissions (Everyone / full access) on directories, executed from
a SYSTEM context or via a scheduled task.

#### Why It Matters

Used in some incidents to ensure the encryptor can access files regardless of ACL restrictions.
In the same session window as other pre-encryption indicators, this confirms encryption preparation
is underway.

#### Telemetry

- Sysmon EID 1 — `icacls.exe` with grant arguments
- EID 4688 with command line detail

#### Detection Logic

```
Condition:
- process_name = "icacls.exe"
- command_line CONTAINS "/grant"
- command_line CONTAINS "Everyone" OR ":(OI)(CI)F"
- executing context is SYSTEM or from a scheduled task
```

---

## 10. Hypervisor-Specific Detections

### 10a. Unexpected SSH to ESXi / Nutanix AHV

#### What to Detect

SSH connection to an ESXi host or Nutanix AHV management interface from an unexpected internal
source IP.

#### Why It Matters

SSH to the hypervisor using harvested credentials is the precursor to Akira_v2 deployment. Once
an operator has interactive hypervisor access, they can shut down VMs and encrypt disk files
directly, bypassing all guest-level security controls.

#### Telemetry

- ESXi shell audit logs — SSH login events
- vCenter events — SSH enable, unexpected configuration changes
- Nutanix AHV audit logs

#### Detection Logic

```
Condition A:
- SSH login to ESXi host
- source IP NOT in [designated management VLAN or jump server list]

Condition B:
- SSH access enabled on ESXi via vCenter
- initiating account not in the hypervisor admin group baseline

Elevated urgency:
- Bulk VM power-off events following an unexpected SSH session
```

---

### 10b. ESX Admins AD Group Creation

#### What to Detect

An Active Directory group named `ESX Admins` created outside of a documented deployment process.

#### Why It Matters

In domain-joined ESXi environments, membership in an AD group named `ESX Admins` automatically
grants hypervisor administrative access. Creating this group and adding a compromised account
provides hypervisor admin rights without directly authenticating to the management interface.

#### Telemetry

- Win Security EID 4731 — security group created
- Group name match: `ESX Admins`

#### Detection Logic

```
Condition:
- EID 4731
- group_name = "ESX Admins"
- creation NOT associated with a documented vSphere deployment or change request
```

---

## 11. Impact

### 11a. Ransom Note File Creation

#### What to Detect

Creation of `akira_readme.txt`, `fn.txt`, or `akiranew.txt` across multiple directories.

#### Why It Matters

Confirmed post-impact indicator. If this fires, encryption is already underway or complete.
Immediately check whether backup and hypervisor systems have been reached.

#### Telemetry

- Sysmon EID 11 — file creation
- File integrity monitoring

#### Detection Logic

```
Condition:
- file_name IN ["akira_readme.txt", "fn.txt", "akiranew.txt"]
- file_count in unique directories > 3 within 1 minute

Response: Immediate isolation. Shift to IR. Check backup and ESXi systems.
```

---

### 11b. Mass File Extension Changes

#### What to Detect

High-rate file extension renaming to `.akira`, `.akiranew`, or `.aki` across multiple directories.

#### Why It Matters

Active encryption in progress — the prevention window is gone. Preserve any remaining SIEM-forwarded
logs (local logs may already be cleared). Identify the host running the encryptor.

#### Telemetry

- Sysmon EID 11 / EID 23 — file creation and modification at high rate
- FIM: extension changes in bulk

#### Detection Logic

```
Condition:
- File extension changed to ".akira" OR ".akiranew" OR ".aki"
- event_count > 50 within 2 minutes
- source_process NOT in [known legitimate backup or archival tool list]
```

---

## Detection Priority Summary

| Priority | Detection | Phase | Primary Signal |
|---|---|---|---|
| 🔴 Critical | VSS deletion (any method) | Pre-encryption | EID 4104 / vssadmin / wmic |
| 🔴 Critical | Log clearing — EID 1102 + 104 | Pre-encryption | Same window as VSS deletion |
| 🔴 Critical | Ransom note file creation | Impact | `akira_readme.txt` across dirs |
| 🟠 High | LSASS access from rundll32 | Credential Access | Sysmon EID 10 |
| 🟠 High | Ngrok DNS query from internal host | C2 | Sysmon EID 22 / DNS logs |
| 🟠 High | Account creation + admin elevation (rapid) | Persistence | EID 4720 → 4732 |
| 🟠 High | NTDS.dit extraction via ntdsutil | Credential Access | EID 1 + ifm command |
| 🟠 High | WmiPrvSE spawning a shell | Lateral Movement | Sysmon EID 1 |
| 🟠 High | Malicious driver load from writable path | Defense Evasion | Sysmon EID 6 |
| 🟡 Medium | Scripted recon burst (5+ commands) | Discovery | EID 1 velocity + session context |
| 🟡 Medium | Rclone outside Program Files | Exfiltration | EID 1 + NetFlow |
| 🟡 Medium | SharpHound / AdFind execution | Discovery | EID 1 + ZIP artifact |
| 🟡 Medium | Kerberoasting (RC4 TGS burst) | Credential Access | EID 4769 + EncType 0x17 |
| 🟡 Medium | RDP workstation → DC | Lateral Movement | EID 4624 Type 10 |
| 🟡 Medium | Backup / DB service stops | Pre-encryption | EID 7036 + net stop |

---

## Correlation Chains

Single events are rarely enough. These chains represent sequences that build high-confidence
findings for escalation or containment.

**Chain 1 — Credential access → lateral movement:**
> LSASS dump (EID 10) → itadm account created (EID 4720 + 4732) → RDP to DC (EID 4624 Type 10) → NTDS.dit extraction

Confidence: High. Domain compromise is underway.

**Chain 2 — Exfiltration pipeline:**
> SharpHound ZIP in temp path → Rclone from C:\Users\Public\ → Large outbound to Mega → WinRAR archives in staging paths

Confidence: High. Data is leaving the network.

**Chain 3 — Pre-encryption final stage:**
> Backup service stops → VSS deletion (PowerShell WMI method) → Log clearing (EID 1102 + 104) → icacls permission modification

Confidence: Near-certain pre-encryption. Last containment window. Escalate immediately.

**Chain 4 — Hypervisor attack path:**
> VPN auth from new IP → SSH to ESXi from non-management host → Bulk VM power-off outside change window → Akira_v2 on hypervisor

Confidence: High. Guest-level controls will not help at this stage — isolate vCenter and the
management network.

**Chain 5 — C2 persistence:**
> Ngrok DNS query → Scheduled task with binary in C:\Users\Public\ → AnyDesk silent install from non-standard path

Confidence: Medium (standalone) / High (correlated with any credential access event).

---

## Coverage Gaps and Limitations

- **COM-based shadow copy deletion:** Only visible via PowerShell Script Block Logging (EID 4104)
  or WMI activity logs. Process-based rules alone miss this. If EID 4104 is not enabled, this
  is a blind spot.

- **NTDS.dit via offline VMDK:** In at least one 2025 incident, operators powered down a DC VM,
  copied the VMDK, and extracted NTDS.dit from the offline disk. No LSASS access means credential
  dumping alerts will not fire. Detection surface is the hypervisor — look for unexpected VMDK
  copies or new VM creation for an offline disk mount.

- **Renamed Rclone:** Binary name detection will miss Rclone renamed to `svchost.exe` or similar.
  Command-line pattern matching (`--transfers`, `--multi-thread-streams`) and NetFlow-based
  high-volume egress detection are required fallbacks.

- **ESXi environments without vCenter logging:** If ESXi host-level logging is not forwarded to
  SIEM, SSH access and hypervisor events will be invisible until post-incident.

- **Encrypted C2 via Ngrok:** DNS-based detection works on initial tunnel setup but will not reveal
  activity within the tunnel. HTTPS inspection is required for content visibility.

---

## Transition to Sigma Rules

This document provides the logic foundation. When writing Sigma rules:

- Start with the 🔴 Critical and 🟠 High priority detections — these have the best
  signal-to-noise ratio.
- Write separate rules for each detection condition, not combined mega-rules. Simpler rules
  are easier to tune and maintain.
- Each Sigma rule should map to a single MITRE ATT&CK technique — reference `intel/ttp_table.md`
  for the correct mappings.
- Use the correlation chains above as the basis for composite detection logic in SIEM platforms
  that support multi-event correlation (Splunk correlation searches, Elastic EQL sequences).
- Tag each rule with the relevant EID and log source so ingestion requirements are clear.

---

*Sources: CISA AA24-109A (Nov 2025) · Unit 42 Howling Scorpius (Nov 2025) · Arctic Wolf Labs
(Sep 2025) · Sophos MDR · IBM X-Force · Picus Security (Feb 2026) · AttackIQ emulation (Nov 2025)
· ANY.RUN behavioral analysis*  
*All detection logic is based on behaviors confirmed in incident reporting. Coverage depends on
log source availability and configuration — gaps are noted where relevant.*
