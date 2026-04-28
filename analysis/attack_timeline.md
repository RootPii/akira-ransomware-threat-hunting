# Akira Ransomware — Attack Timeline

**Purpose:** Reconstruct how an Akira intrusion actually unfolds, from the attacker's first touch to encryption.  
**Audience:** SOC analysts, threat hunters, IR responders.  
**Based on:** CISA AA24-109A (Nov 2025), Arctic Wolf Labs (Sep 2025), Unit 42 Howling Scorpius, Halcyon, Picus Security, Sophos X-Ops, IBM X-Force, and the artifacts documented in `artifacts/raw_artifacts.md`.

> This isn't a theoretical kill chain — it's based on patterns seen in real incidents.  
> Cross-reference `intel/ttp_table.md` for MITRE mappings. Cross-reference `artifacts/raw_artifacts.md` for observable evidence details.

---

## A Note on Timing

Dwell time in Akira intrusions is short — often measured in hours, not days. Arctic Wolf documented intrusions where the gap between initial VPN login and encryption was as little as 55 minutes. In multiple other incidents, exfiltration started within two hours of initial access. Some cases do show longer dwell (days), especially where operators are working through a broker's prior foothold or conducting more deliberate recon before moving.

The timeline below reflects the faster end of observed behavior, which is increasingly common in 2025 campaigns. Don't assume you have days to respond.

> Timings are approximate and vary across incidents — some intrusions compress these steps further, others spread them over hours or days depending on the affiliate and environment. Note: individual signals may look benign in isolation — the value is in how they appear together within a short time window.

---

## Timeline Table

| # | Phase | Approx. Timing | What Happened | Observable Evidence | Detection Opportunity |
|---|---|---|---|---|---|
| 1 | **Initial Access** | T+0 | Attacker authenticates to an SSL VPN or RDP endpoint using stolen or brute-forced credentials. No MFA in place. Source IP is a new external address with no prior session history. Common entry points: SonicWall (CVE-2024-40766), Cisco ASA (CVE-2023-20269), or credentials bought from an initial access broker. | VPN/firewall auth log — successful login from an external IP not seen before. No MFA event. Logon outside business hours is common. | First-time external IP login to VPN. No preceding MFA event. Outside business hours is common. |
| 2 | **Foothold Established** | T+0 to T+5 min | RDP or reverse shell session established from the beachhead host. Attacker now has interactive access to an internal system. In some cases, AnyDesk or LogMeIn is deployed almost immediately as a backup channel. | EID 4624 — logon type 10 (remote interactive) or type 3 (network). New RDP session from an internal system the VPN account hasn't connected to before. AnyDesk process creation if deployed early. | Alert on first-time internal RDP sessions sourced from a VPN-associated IP. Any unauthorized remote access tool installation at this stage is a strong signal. |
| 3 | **Local Reconnaissance** | T+5 to T+15 min | A burst of native Windows commands runs in rapid succession from the same session: `whoami`, `net user`, `ipconfig /all`, `arp -a`, `route print`. No single command is malicious — it's the velocity and session context that matter. | Process creation logs — five or more of these commands spawning from the same parent process within a few minutes. Sysmon EID 1 (ProcessCreate) with `cmd.exe` or `powershell.exe` as parent. | Velocity-based detection: five or more recon commands within a few minutes from a single session. Correlate with the logon event from Step 1. |
| 4 | **C2 Tunnel Established** | T+10 to T+30 min | Ngrok (or Cloudflare Tunnel) deployed to create an encrypted outbound channel. This replaces or supplements the original RDP access and keeps the attacker's connection alive even if the initial foothold is disrupted. | DNS query to `*.ngrok.io` or `*.ngrok-free.app` from an internal host. `ngrok.exe` process creation. Outbound HTTPS to Ngrok relay infrastructure. Alternatively: `cloudflared.exe` connecting to `*.trycloudflare.com`. | DNS-based alert on `*.ngrok.io` queries from internal hosts. This is rarely legitimate in enterprise environments and should be high-priority regardless of other context. |
| 5 | **Persistence — Account Creation** | T+15 to T+45 min | Attacker creates a local or domain admin account (commonly `itadm`) and immediately adds it to the Administrators group. This happens fast — the two events are typically seconds to minutes apart. Also common: a scheduled task is created pointing to a binary in `C:\Users\Public\` or `C:\Windows\Temp\`. | EID 4720 — new account created. EID 4732 — account added to Administrators. EID 4698 — scheduled task created. The fast gap between 4720 and 4732 is the tell. | Alert on any account creation immediately followed by privilege escalation. A scheduled task created at this time, with a binary path in a user-writable directory, is also worth flagging. |
| 6 | **Credential Dumping** | T+20 to T+60 min | LSASS accessed via `comsvcs.dll` using `rundll32.exe` — a living-off-the-land technique that avoids dropping Mimikatz. In some incidents, Mimikatz or LaZagne are dropped anyway, sometimes renamed. Rubeus used for Kerberoasting in 2025 cases. Goal: harvest plaintext credentials, NTLM hashes, Kerberos tickets. | Sysmon EID 10 — `ProcessAccess` on `lsass.exe` with `rundll32.exe` as the calling process. EID 4769 (Kerberos service ticket request) with encryption type 0x17 indicating Kerberoasting. Binary creation in staging paths if Mimikatz/LaZagne dropped. | Sysmon EID 10 on lsass.exe from rundll32 — credentials likely compromised at this point, escalate quickly. EID 4769 with RC4 encryption is a reliable Kerberoasting indicator. |
| 7 | **AD and Network Enumeration** | T+30 to T+90 min | SharpHound or AdFind runs to map the domain — users, groups, GPOs, trust relationships, admin paths. NetScan or Advanced IP Scanner sweeps internal subnets. `nltest` used to identify domain controllers. The output of this phase feeds the lateral movement decisions. | SharpHound drops a `.zip` in a temp directory with BloodHound-compatible JSON. AdFind command-line execution visible in process logs. NetFlow: single internal host connecting to many internal IPs on port 445/3389/22 in a short window. | SharpHound ZIP in a temp path is a reliable post-execution artifact. Lateral scan traffic (one-to-many internal connections) should trigger a NetFlow alert. |
| 8 | **Lateral Movement** | T+45 to T+120 min | Attacker pivots to high-value systems — domain controllers, file servers, backup servers, hypervisor management. Most common methods: Impacket `wmiexec` (agentless, fileless on target), PsExec, RDP with the newly created `itadm` credentials, or SSH. In ESXi environments, SSH to the hypervisor host using harvested credentials is documented. | Sysmon: `WmiPrvSE.exe` spawning `cmd.exe` or PowerShell on target systems — this is the `wmiexec` footprint. EID 4624 with type 3 logon using `itadm` on systems it hasn't accessed before. PsExec service creation on remote hosts. | `WmiPrvSE.exe` spawning a shell is rarely legitimate. Any authentication by the newly created admin account reaching multiple systems is a high-confidence lateral movement signal. |
| 9 | **Exfiltration (Data Theft)** | T+90 to T+180 min | Files are staged using WinRAR or 7-Zip, then synced to Mega or another cloud endpoint via Rclone. Rclone is often renamed (e.g., `svchost.exe`) and run from `C:\Users\Public\` or `C:\Windows\Temp\`. WinSCP or FileZilla are used in some cases. In at least one documented 2025 incident, exfiltration started just over two hours after initial access. | Rclone (or renamed binary) executing from a non-standard path. Large outbound data transfers to Mega or external cloud storage IP ranges. WinRAR/7-Zip creating archives in staging paths. MRU registry entries for WinSCP or FileZilla. Process creation in `C:\Users\Public\`. | Rclone executing outside of `Program Files` should be flagged. Large outbound transfers to Mega.nz or non-business-geography destinations are a network-level signal. |
| 10 | **EDR Killed / Defense Suppression** | Variable — often before lateral movement or just before encryption | PCHunter64 or PowerTool used to terminate EDR processes. In 2025 cases, STONESTOP drops POORTRY (also tracked as ABYSSWORKER/BurntCigar) — a signed malicious kernel driver that terminates, and in newer variants outright deletes, security tool files. HeartCrypt or Shanya crypter used to obfuscate the loader. Timing varies: some operators kill EDR early, others wait until just before detonation. | Sysmon EID 6 (DriverLoad) from a user-writable path. Driver with a revoked, forged, or anomalous signature. Security agent process dying with no preceding stop command or update event. KillAV execution alongside STONESTOP in some 2025 cases. | A signed driver loading from `C:\Users\Public\` or `C:\Windows\Temp\` should never happen. Any security process termination not tied to a known update or admin action is worth immediate investigation. |
| 11 | **Pre-Encryption — VSS Deletion** | T+final hour, shortly before encryption | Shadow copies wiped via `vssadmin`, `wmic shadowcopy delete`, or PowerShell WMI. Sometimes all three methods used across different systems. This removes the easiest recovery option for the victim. There is no legitimate operational reason to do this on a production host. | Process creation: `vssadmin.exe delete shadows`, `wmic shadowcopy delete`, or PowerShell `Get-WmiObject Win32_Shadowcopy` with deletion. | This is a near-certain pre-encryption signal. If caught live, treat as an immediate escalation — containment must start now. |
| 12 | **Pre-Encryption — Log Clearing** | Same window as VSS deletion | `wevtutil` used to clear the Security and System event logs. Typically happens in the same session window as VSS deletion — attackers clear their tracks just before encryption so responders have less to work with. | EID 1102 — Security log cleared. EID 104 — System log cleared. Both generated at the time of clearing (ironically, these events survive if forwarded to a SIEM or remote syslog before clearing). | EID 1102 + EID 104 appearing together, especially in the same timeframe as VSS deletion, is a very strong pre-encryption indicator. Alert and isolate affected systems. |
| 13 | **Encryption — Windows** | T+impact | Encryptor (`w.exe`, `Win.exe`, or Akira_v2 variant) deployed to target systems, often via the C2 channel or a shared path. Uses ChaCha20 + RSA-4096 hybrid encryption. Intermittent encryption used on large files for speed. Files renamed with `.akira`, `.akiranew`, or `.aki` extension. `akira_readme.txt` (or `fn.txt`) dropped in every encrypted directory. During large-file encryption on Hyper-V/ESXi, a `.arika` temp file may briefly appear — this is an auto-save artifact from the encryptor, not a separate strain. | File extension changes across the filesystem. `akira_readme.txt` or `fn.txt` present in directories. Encryptor binary executing from a staging path. High disk I/O across multiple systems simultaneously. | At this point, the window for prevention has closed. Focus shifts to containment: isolate affected hosts, preserve any remaining logs, and check whether hypervisor or backup systems have been reached. |
| 14 | **Encryption — ESXi / Hypervisor** | Same window as Windows encryption, or shortly after | If credentials for the hypervisor were harvested, Akira_v2 is deployed via SSH. Flags: `--vmonly` (target VMs only), `--stopvm` (shut down VMs before encrypting). VM disk files encrypted. `akiranew.txt` dropped. In June 2025, Nutanix AHV disk files were encrypted for the first time. In domain-joined ESXi environments, attackers may have created an `ESX Admins` AD group to gain hypervisor admin rights. | SSH session to ESXi host from an internal system using harvested credentials. Akira_v2 binary executing on the hypervisor. VM disk files showing `.akiranew` extension. AD group `ESX Admins` created. | Unexpected SSH to ESXi, especially from a non-management system, should be alerted. Monitor vCenter for unexpected VM shutdowns or configuration changes in bulk. |
| 15 | **Post-Encryption** | After encryption completes | Attacker may maintain access for a period via AnyDesk, LogMeIn, or Ngrok tunnel. Victim discovers notes and initiates contact through the `.onion` portal. In some cases, operators follow up by phone. | Ransom notes in directories. File extensions changed. Remote access tools still running. C2 tunnel may still be active. | Incident response mode. Preserve logs (especially from SIEM/syslog — local logs may have been cleared). Check for active C2 tunnels and remote access tools still running. Identify the patient zero host. |

---

## How the Artifacts Connect

This section shows how the evidence from `raw_artifacts.md` maps to the timeline above, so you can trace observed artifacts back to a phase.

| Artifact | Phase | Notes |
|---|---|---|
| VPN auth from new IP, no MFA | 1 — Initial Access | Usually the starting point — most activity follows from here. |
| EID 4624 (logon type 10) from VPN-associated IP | 2 — Foothold | Confirms interactive session established. |
| Burst of recon commands from single session | 3 — Local Recon | Velocity is the signal, not individual commands. |
| DNS query to `*.ngrok.io` | 4 — C2 Tunnel | High-confidence signal even without other context. |
| EID 4720 + EID 4732 (itadm, seconds apart) | 5 — Persistence | Rapid elevation gap is the tell. Account name varies. |
| EID 4698 (scheduled task, binary in Public/) | 5 — Persistence | Callback task for long-term access. |
| Sysmon EID 10 — rundll32 → lsass.exe | 6 — Credential Dumping | Credentials are likely compromised at this point — escalate quickly. |
| EID 4769 with encryption type 0x17 | 6 — Credential Dumping | Kerberoasting. |
| SharpHound ZIP in temp path | 7 — AD Enumeration | Check creation time to anchor the timeline. |
| `WmiPrvSE.exe` spawning cmd.exe | 8 — Lateral Movement | wmiexec footprint on victim systems. |
| Rclone in non-standard path, large outbound transfer | 9 — Exfiltration | Check for WinRAR/7-Zip archives in same timeframe. |
| Sysmon EID 6 (driver load from writable dir) | 10 — Defense Evasion | POORTRY delivery. EDR process termination follows. |
| `vssadmin delete shadows` or equivalent | 11 — Pre-Encryption | Urgent. Encryption is imminent or already started. |
| EID 1102 + EID 104 | 12 — Log Clearing | If these appear together with VSS deletion, alert and act. |
| `.akira` / `.akiranew` extensions, ransom notes | 13/14 — Encryption | Post-impact. Recovery and IR phase. |

---

## Analyst Notes

A few things worth keeping in mind when working through an Akira case:

The timeline above shows a reasonably fast intrusion. In practice, some intrusions skip or compress steps — not every operator follows the same playbook. A few things that vary: some affiliates do credential dumping before establishing C2; some skip Ngrok entirely and run everything over RDP; some kill EDR very early, others only shortly before encryption.

Some things are more consistent across incidents: VSS deletion before encryption, log clearing in the same window, and ransom notes in every directory. If you see those, the intrusion is already at its end stage.

The best detection windows are Steps 4 (Ngrok DNS), 6 (LSASS access), 11, and 12 (VSS + log clearing). Catching any of those should trigger immediate escalation rather than just a ticket.

If the initial VPN auth logs are missing — which happens if the attacker cleared them — work backward from the `itadm` account creation time. EID 4720 and 4732 on the DC give you a floor timestamp for when the attacker had domain-level access.

---

*Sources: CISA AA24-109A (Nov 2025) · Arctic Wolf Labs (Sep 2025) · Unit 42 Howling Scorpius (Nov 2025) · Halcyon · IBM X-Force · Picus Security (Feb 2026) · Sophos X-Ops · ConnectWise Threat Research*  
*All behaviors sourced from confirmed incident reports. Timing is approximate and varies by campaign and affiliate.*
