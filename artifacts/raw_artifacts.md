# Akira Ransomware - Raw Artifacts

**Purpose:** Investigation-facing notes on what analysts actually see on compromised systems.  
**Coverage:** 2023–2026 (validated against CISA AA24-109A Nov 2025, Unit 42 Howling Scorpius, IBM X-Force, Halcyon, Picus Security Feb 2026)  
**Status:** Living document - update as new intrusions come in

> Cross-reference: `artifacts/command_patterns.md` for full command details, `intel/ttp_table.md` for MITRE mapping.  
> Payload internals and CVE details live in `intel/threat_actor_profile.md`.

---

## Priority Signals (Quick Triage)

These are the signals that usually matter most during an investigation. If you're in triage mode, start here.

Pre-encryption:
- VSS deletion (any method)
- Log clearing - EID 1102 + EID 104 in the same session window

High confidence:
- LSASS access from a non-security process
- Internal DNS queries to `*.ngrok.io` or `*.ngrok-free.app`

Post-impact:
- Ransom note present (`akira_readme.txt`, `fn.txt`, `akiranew.txt`)
- File extensions changed to `.akira`, `.akiranew`, or `.aki`

---

## 1. Filesystem Artifacts

These are the most reliable post-incident indicators - low noise, high fidelity.

### Ransom Notes

Notes are dropped into **every encrypted directory**, not just root.

| Filename | Location | Context |
|---|---|---|
| `akira_readme.txt` | `C:\`, `C:\Users\*`, every encrypted dir | Windows - consistent since 2023 |
| `fn.txt` | `C:\`, `C:\Users\*` | Akira_v2 Windows variant |
| `akiranew.txt` | Directories with newly encrypted files | Akira_v2 Linux / ESXi |

Notes contain no ransom amount - only a unique victim code and a `.onion` URL. Victims initiate contact through the portal. In some cases, operators follow up with phone calls.

### Encrypted File Extensions

| Extension | Encryptor |
|---|---|
| `.akira` | C++ original / Akira_v2 (Windows) |
| `.akiranew` | Akira_v2 (Linux / ESXi) |
| `.aki` | Akira_v2 (some Windows incidents) |
| `.powerranges` | Megazord - largely out of use since 2024 |

> During large-file encryption, a `.arika` (note the typo — not `.akira`) temp file may briefly appear on Hyper-V and ESXi systems. It's an auto-save artifact from the encryptor, not a separate strain.

### Known Encryptor Hashes

Filenames change between campaigns — don't rely on these as the only detection layer.

| Filename | SHA-256 |
|---|---|
| `w.exe` | `d2fd0654710c27dcf37b6c1437880020824e161dd0bf28e3a133ed777242a0ca` |
| `Win.exe` (part 1) | `dcfa2800754e5722acf94987bb03e814` |
| `Win.exe` (part 2) | `edcb9acebda37df6da1987bf48e5b05e` |
| Akira_v2 ESXi | `3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75` |
| Akira_v2 ESXi | `0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c` |

*Source: CISA AA24-109A (Nov 2025). IOCs cover June 2023–August 2025 — vet against current threat feeds before blocking.*

### Common Staging Paths

Tools and payloads are typically dropped in:
- `C:\Users\Public\`
- `C:\Windows\Temp\`
- `%APPDATA%\` or user-owned directories, sometimes under a fake tool name

A newly created or modified binary in one of these paths, executed shortly after a remote session was established, is worth investigating even without a known hash.

---

## 2. Account and Credential Artifacts

### Account Created During Intrusion

Noted across incidents: an admin account named `itadm` gets created specifically for persistence.

```
EID 4720 — Account created: itadm
EID 4732 — Added to Administrators group
```

The gap between these two events is usually seconds to minutes. That rapid sequence is the real detection signal — the account name varies across intrusions, but the behavior is consistent.

### Credential Dumping

Three methods come up consistently across incidents:

**`[HIGH CONFIDENCE]` `[LOW NOISE]` LSASS via comsvcs.dll (living off the land)**  
Detected via Sysmon EID 10 (`ProcessAccess` on `lsass.exe` from `rundll32.exe`). LSASS access from `rundll32` is rarely legitimate - when you see this, credentials are likely already stolen. Treat it as urgent.

> Investigation tip: if you see this, check for subsequent lateral movement within the same session window - `wmiexec` or PsExec are common next steps.

**Mimikatz and LaZagne**  
Seen in several environments as dropped binaries, sometimes renamed to blend in with legitimate tools. LaZagne goes after browser and application passwords; Mimikatz handles pass-the-hash and Kerberos tickets. Rubeus has also appeared in some 2025 incidents for Kerberoasting.

**NTDS.dit via offline VMDK**  
Observed in at least one 2025 case where operators powered down a DC VM, copied its VMDK, mounted it on a separate VM, then pulled `NTDS.dit` and the SYSTEM hive from the offline disk. No LSASS process access, so standard alerts won't fire. Look for unexpected VMDK copy events on the hypervisor and new VM creation as the tell.

---

## 3. Defense Evasion

### EDR Killing - Two Paths Observed

**PCHunter64 / PowerTool**  
Kernel-level tools for terminating EDR processes, seen across multiple reports. Look for the binary executing, a driver loading from a non-standard path, and a security agent process dying with no preceding stop command.

**POORTRY + STONESTOP (2025 — high priority)**  
STONESTOP installs POORTRY, a signed malicious kernel driver that terminates — and in newer variants, deletes the files of — AV/EDR processes. Confirmed in Akira intrusions and shared across other RaaS groups. This is usually a strong signal of intrusion when seen alongside other activity. Note that POORTRY is also tracked as ABYSSWORKER/BurntCigar in some vendor reporting; they refer to the same driver family.

Detection angle:
- Sysmon EID 6 (DriverLoad) from a user-writable directory
- Driver carrying an anomalous, revoked, or forged signature
- Security tool process terminates immediately after

> KillAV was also observed alongside POORTRY in 2025 cases. HeartCrypt (a packer-as-a-service) and the newer Shanya crypter have both been used to obfuscate payloads before delivery.

---

## 4. Reconnaissance and Lateral Movement

### Recon Pattern

Reported in several environments: a burst of native Windows reconnaissance commands executed in rapid succession from a single remote session - `whoami`, `net user`, `ipconfig`, `arp`, `route print`, AD/domain queries. No single command here is malicious; it's the velocity and the session context that matter.

Seeing five or six of these within a few minutes of an unusual remote logon is a reliable indicator of scripted recon.

### AD Enumeration

SharpHound, AdFind, and `nltest` show up across Akira incident reports as the standard go-to tools before lateral movement. SharpHound drops a ZIP with BloodHound-compatible JSON — unexplained `.zip` files in temp directories after these events are worth a closer look.

> Investigation tip: if you find a SharpHound ZIP, check its creation time against recent remote sessions to anchor the timeline.

### Network Scanning

NetScan and Advanced IP Scanner are both noted in IR reports. The NetFlow artifact is usually more useful than the tool itself: a single internal host connecting to many unique internal IPs on port 445, 3389, or 22 within a short window.

### Lateral Movement

Impacket's `wmiexec` comes up consistently for remote execution without touching disk on the target. The process tree on the victim side - `WmiPrvSE.exe` spawning `cmd.exe` or PowerShell — is the main Sysmon artifact. PsExec, RDP, and SSH are also used depending on what's available in the environment.

---

## 5. Pre-Encryption Signals (Critical)

### `[PRE-ENCRYPTION]` VSS Deletion

Multiple command variations seen in reports, all achieving the same result: wiping shadow copies before encryption runs. There's almost no legitimate operational reason for this on a production host. If you catch this during a live incident, treat it as urgent - encryption is either imminent or has already started.

Detection: `vssadmin`, `wmic shadowcopy delete`, or PowerShell-based shadow copy deletion from any production host.

### `[PRE-ENCRYPTION]` `[HIGH CONFIDENCE]` Log Clearing

`wevtutil` clearing the Security and System logs is seen across incidents - typically in the same session window as VSS deletion. Generates EID 1102 (Security log cleared) and EID 104 (System log cleared). Catching both in the same window alongside other artifacts is a strong indicator that encryption follows shortly.

---

## 6. Network Artifacts

### `[HIGH CONFIDENCE]` `[LOW NOISE]` C2 - Ngrok

Ngrok is the most consistently reported tunneling tool in Akira intrusions. It creates an encrypted reverse tunnel to an external relay, making traffic look like outbound HTTPS to most perimeter tools.

The detection angle that actually works: **DNS queries to `*.ngrok.io` or `*.ngrok-free.app` from internal hosts.** This is unusual in most enterprise environments. An internal host making this query during or after a suspicious logon is a strong C2 indicator — worth alerting on regardless of other context.

Cloudflare Tunnel (`cloudflared.exe`, outbound to `*.trycloudflare.com`) is also observed as an alternative.

### Remote Access Tools

AnyDesk and LogMeIn are seen installed during intrusions to maintain access independently of the original foothold. The detection challenge is that both are also used legitimately by IT teams — so the hunt angle is tools installed outside of IT-managed deployment (no asset record, no change ticket) at a time that correlates with other suspicious events.

Cobalt Strike and SystemBC appear in some incidents; MobaXterm and RustDesk are noted less frequently but worth including in unauthorized-tool hunts.

### Exfiltration

Rclone is the most commonly observed exfiltration tool across reports. It syncs directly to cloud storage - most often Mega - and leaves fewer Windows artifacts than GUI tools. It has also been observed renamed to blend in with legitimate processes (e.g., as `svchost.exe`).

WinRAR and 7-Zip are used to stage and compress data before transfer. WinSCP and FileZilla are also noted; both leave MRU entries in the registry and application config files.

> Investigation tip: if you find Rclone running from a non-standard path, check for recent archive creation (WinRAR / 7-Zip) in the same timeframe — staging usually precedes transfer.

**Detection note:** In at least one 2025 incident, exfiltration started just over two hours after initial access. That window is short - waiting for encryption to detect the intrusion means data is already gone.

Network artifact: large outbound transfers to Mega, cloud SFTP, or FTP endpoints outside expected business geography. Rclone running from `C:\Users\Public\` or `C:\Windows\Temp\` is the endpoint-side signal.

---

## 7. Persistence

### Scheduled Tasks

Tasks created for callback persistence — typically named to resemble system tasks. Binary path usually points to a user-writable directory.

```
EID 4698 — Scheduled task created
Task runs as SYSTEM
Binary path in C:\Users\Public\ or C:\Windows\Temp\
```

### Remote Access Tool Installations (as persistence)

AnyDesk and LogMeIn are also installed as a fallback persistence mechanism, not just for initial access. The pattern is the same: installed outside normal IT deployment, service created under LocalSystem, outbound connection shortly after installation.

Level.io (an RMM platform) has also appeared in CISA reporting as a persistence mechanism - less common, but worth including in unauthorized-RMM hunts.

---

## 8. ESXi / Hypervisor Notes

Access path seen in several incidents: SSH directly to the ESXi host using credentials harvested from LSASS or NTDS.dit, or pivoting through vCenter to enable SSH on the host. Akira_v2 is then run with flags to target only VMs (`vmonly`) and optionally shut them down first (`stopvm`).

In domain-joined ESXi environments: creating an AD group named `ESX Admins` can grant hypervisor admin access. Worth checking AD for this group name if ESXi is in scope.

**June 2025 — Nutanix AHV:** First observed case of Akira encrypting Nutanix AHV VM disk files. If Nutanix AHV is in the environment, it should be included in any Akira-focused hunt.

---

## 9. Patterns That Repeat Across Incidents

Some patterns show up consistently regardless of the specific environment:

**Initial access:**
- VPN login from a new external IP, no MFA, no prior session baseline

**Credential access:**
- LSASS access from a non-security process
- Kerberoasting activity (EID 4769, encryption type 0x17)

**Discovery and lateral movement:**
- `itadm` (or similar) account created, then added to Administrators within minutes
- SharpHound or AdFind executing from a workstation
- Internal DNS query to `*.ngrok.io`

**Pre-encryption:**
- VSS deletion via any method - treat as urgent
- EID 1102 + EID 104 in the same session window

**Exfiltration and impact:**
- Rclone or WinSCP running from a non-standard path
- `akira_readme.txt` or `fn.txt` present in a directory - encryption has already occurred

---

## Limitations

Not every Akira intrusion shows all of these artifacts — some incidents are more stripped down, especially where affiliates have less operational discipline. These signals work best when correlated across a timeframe or session window rather than used individually. A single artifact in isolation is usually noise; multiple signals from the same window are what anchor a finding.

---

## How to Use This File

This file answers one question: *what do I actually see on a compromised system?*

Use it alongside:
- `intel/ttp_table.md` : MITRE ATT&CK mapping for each behavior
- `artifacts/command_patterns.md` : full command-level detail when you need it
- `analysis/attack_timeline.md` : sequencing artifacts into an intrusion timeline

Don't hunt on single indicators. The value here is correlation - multiple signals from the same timeframe or session window are far more reliable than any individual artifact. The patterns in Section 9 are a good starting anchor.

---

*Sources: CISA AA24-109A (Nov 2025) · FBI Joint Advisory · Unit 42 Howling Scorpius (Nov 2025) · IBM X-Force · Halcyon · Picus Security (Feb 2026) · AttackIQ (Nov 2025) · Sophos X-Ops · Elastic Security Labs*  
*All behaviors sourced from incident reports. Not every Akira intrusion exhibits all of these.*
