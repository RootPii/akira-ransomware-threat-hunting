<div style="overflow-x: auto;">

<table>
<thead>
<tr>
<th>#</th>
<th>Stage</th>
<th>Technique</th>
<th>Behavior</th>
<th>Artifacts</th>
<th>Detection</th>
<th>Correlation Signal</th>
<th>Confidence</th>
<th>Source</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>Initial Access</td>
<td><strong>T1190</strong> - Exploit Public-Facing Application</td>
<td>Affiliates exploit unpatched VPN appliances lacking MFA. Observed in reports targeting SonicWall (CVE-2024-40766), Cisco ASA (CVE-2020-3259), and Fortinet (CVE-2022-40684). June 2025: CVE-2024-40766 used to reach Nutanix AHV.</td>
<td>VPN auth logs; Sysmon EID 3; firewall connection logs</td>
<td><strong>Detect:</strong><br>• Multiple failed auth attempts from same external IP<br>• Successful login immediately following failures<br>• First-ever session from new ASN or geo</td>
<td>Failed auths + success same IP + new session baseline → Brute-force or exploit precursor</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025)</td>
</tr>
<tr>
<td>2</td>
<td>Initial Access</td>
<td><strong>T1078</strong> - Valid Accounts</td>
<td>In observed incidents, affiliates purchase credentials from initial access brokers (IABs) or reuse breach data. No exploit traffic is generated, making this harder to separate from legitimate logins.</td>
<td>Win Security EID 4624 (Type 3/10); EID 4648</td>
<td><strong>Detect:</strong><br>• First-seen source IP for a privileged account<br>• Login outside established business hours<br>• Account with no prior authentication history</td>
<td>New IP + privileged account + off-hours logon → Likely IAB-sourced access</td>
<td>Medium</td>
<td>CISA AA24-109A (Nov 2025); Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>3</td>
<td>Initial Access</td>
<td><strong>T1566 / ClickFix</strong> - Phishing / Social Engineering</td>
<td>Confirmed in at least one Howling Scorpius intrusion (Unit 42, Nov 2025). A fake CAPTCHA on a compromised website delivered SectopRAT. Less common than VPN exploitation but worth tracking as a vector.</td>
<td>Sysmon EID 1 (browser child process); EID 11 (binary in temp path); outbound from browser child</td>
<td><strong>Detect:</strong><br>• Browser spawning PowerShell, cmd, or mshta as child process<br>• Unexpected binary dropped to writable directory<br>• Outbound connection from browser child process</td>
<td>Browser child process + binary drop + outbound connection → ClickFix delivery</td>
<td>Medium</td>
<td>Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>4</td>
<td>Execution</td>
<td><strong>T1059.001</strong> - PowerShell</td>
<td>Used throughout intrusions for recon, credential dumping, payload staging, and VSS deletion. Observed in reports with encoded commands to evade basic string detection.</td>
<td>Sysmon EID 1; PowerShell EID 4104 (Script Block Logging)</td>
<td><strong>Detect:</strong><br>• <code>-EncodedCommand</code> or <code>-ExecutionPolicy Bypass</code> flags<br>• Parent process is a remote session<br>• Script block contains environment enumeration or staging logic [EID 4104]</td>
<td>Encoded command + remote session parent + file write to temp → Staged payload execution</td>
<td>Medium</td>
<td>CISA AA24-109A (Nov 2025)</td>
</tr>
<tr>
<td>5</td>
<td>Execution</td>
<td><strong>T1059.003</strong> — Windows Command Shell</td>
<td><code>cmd.exe</code> is used to chain discovery and execution commands in a single session. Commonly seen before encryption. Commands are chained to minimize interactive footprint.</td>
<td>Sysmon EID 1; Win Security EID 4688</td>
<td><strong>Detect:</strong><br>• <code>cmd.exe</code> spawning <code>wmic.exe</code> with shadow copy arguments<br>• Drive enumeration tool run from a remote session child process<br>• Account or group query from a non-admin context [EID 4688]</td>
<td>Drive enum + account query + shadow copy deletion in same session → Pre-encryption scripted chain</td>
<td>Medium</td>
<td>CISA AA24-109A; ANY.RUN analysis</td>
</tr>
<tr>
<td>6</td>
<td>Execution</td>
<td><strong>T1059.005</strong> — VBScript</td>
<td>Observed in reports following the CISA November 2025 update. Likely used as an alternative when PowerShell activity is more heavily monitored.</td>
<td>Sysmon EID 1: <code>wscript.exe</code> / <code>cscript.exe</code>; EID 4688</td>
<td><strong>Detect:</strong><br>• Script host spawned from a remote session process<br>• Script file located in a user-writable directory<br>• Unexpected parent process for script host</td>
<td>VBScript from writable path + remote session parent → Execution staging</td>
<td>Medium</td>
<td>CISA AA24-109A (Nov 2025)</td>
</tr>
<tr>
<td>7</td>
<td>Persistence</td>
<td><strong>T1136.001 / T1136.002</strong> - Create Local / Domain Account</td>
<td>Commonly seen in reports — operators create new accounts to maintain access if the original is revoked. CISA noted <code>itadm</code> as a specific account name used in some incidents. Admin rights typically assigned immediately.</td>
<td>Win Security EID 4720 (created); EID 4732 (added to Administrators)</td>
<td><strong>Detect:</strong><br>• Account creation followed immediately by admin group membership<br>• Creation outside change management windows<br>• New account authenticating shortly after creation [EID 4776]</td>
<td>Account created + admin group assigned in rapid sequence → Persistence backdoor</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025); AttackIQ emulation (Nov 2025)</td>
</tr>
<tr>
<td>8</td>
<td>Persistence</td>
<td><strong>T1053.005</strong> - Scheduled Task</td>
<td>Used to survive reboots or maintain periodic C2 callbacks. Tasks are named to blend with system processes and point to binaries in writable directories.</td>
<td>Win Security EID 4698; Task Scheduler EID 106; Sysmon EID 1</td>
<td><strong>Detect:</strong><br>• Task created by a non-admin or from a remote session<br>• Task binary path resolves to a writable directory<br>• Task runs as SYSTEM despite standard-user creation</td>
<td>Remote session + SYSTEM task + writable binary path → Scheduled persistence</td>
<td>Medium</td>
<td>CISA AA24-109A; PacketWatch CTI (Nov 2025)</td>
</tr>
<tr>
<td>9</td>
<td>🔶 Cred Access</td>
<td><strong>T1003.001</strong> - LSASS Memory Dump</td>
<td>LSASS dumping is consistently observed across Akira incidents. Tools like Mimikatz and LaZagne appear in several reports. <code>comsvcs.dll</code> via <code>rundll32.exe</code> is used as a living-off-the-land alternative. Extracted hashes enable pass-the-hash.</td>
<td>Sysmon EID 10 (ProcessAccess on <code>lsass.exe</code>); EID 4663</td>
<td><strong>Detect:</strong><br>• Unexpected process accessing <code>lsass.exe</code> memory [Sysmon EID 10]<br>• <code>rundll32.exe</code> invoking <code>comsvcs.dll</code><br>• Source process is not a known security tool</td>
<td>Unknown process + LSASS access + not a security tool → Credential dump in progress</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025); Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>10</td>
<td>🔶 Cred Access</td>
<td><strong>T1558.003</strong> - Kerberoasting</td>
<td>Operators request TGS tickets for SPN-registered accounts, then crack them offline — without touching LSASS directly. RC4 ticket requests from standard user accounts are the primary tell in observed incidents.</td>
<td>Win Security EID 4769 with <code>TicketEncryptionType = 0x17</code> (RC4)</td>
<td><strong>Detect:</strong><br>• RC4 TGS requests from a non-service account [EID 4769]<br>• Rapid sequence of TGS requests from one source<br>• Requesting account has no prior TGS history</td>
<td>RC4 TGS burst from one account + no baseline → Kerberoasting</td>
<td>Medium</td>
<td>CISA AA24-109A; Picus Security (Feb 2026)</td>
</tr>
<tr>
<td>11</td>
<td>Defense Evasion</td>
<td><strong>T1562.001</strong> - Disable Security Tools</td>
<td>Prior to lateral movement or encryption, tools like PCHunter64 and PowerTool64 are observed in reports being used to kill EDR/AV processes at kernel level.</td>
<td>Sysmon EID 1: <code>PCHunter64.exe</code> / <code>PowerTool64.exe</code>; EDR agent terminates unexpectedly</td>
<td><strong>Detect:</strong><br>• Known driver-based process-killer binary executes<br>• Security agent process terminates without a preceding service stop command<br>• Kernel driver loaded from a non-standard path</td>
<td>Process-killer binary + security agent termination + no stop command → Forced EDR kill</td>
<td>High</td>
<td>CISA AA24-109A; PacketWatch CTI (Nov 2025)</td>
</tr>
<tr>
<td>12</td>
<td>Defense Evasion</td>
<td><strong>T1070.001</strong> - Clear Event Logs</td>
<td>Logs are commonly cleared after credential theft and before encryption. Both Security and System logs are targeted. Rarely legitimate in production environments.</td>
<td>Win Security EID 1102 (Security log cleared); Win System EID 104</td>
<td><strong>Detect:</strong><br>• EID 1102 outside a documented IR or compliance test<br>• EID 104 in System log<br>• Either event from an interactive user session</td>
<td>EID 1102 + EID 104 in same session window → Anti-forensic pre-encryption step</td>
<td>High</td>
<td>CISA AA24-109A; ANY.RUN analysis</td>
</tr>
<tr>
<td>13</td>
<td>Defense Evasion</td>
<td><strong>T1027</strong> - Obfuscated Files / Information</td>
<td>PowerShell commands are Base64-encoded in observed incidents to evade command-line detection. Script Block Logging decodes these — making log configuration a direct factor in whether this is detectable.</td>
<td>Sysmon EID 1 (<code>-EncodedCommand</code> in args); PowerShell EID 4104</td>
<td><strong>Detect:</strong><br>• <code>-EncodedCommand</code> or <code>-enc</code> flag in process creation logs [EID 1]<br>• Decoded script block reveals staging or enumeration logic [EID 4104]<br>• Script Block Logging disabled on the endpoint (detection gap)</td>
<td>Encoded command + decoded block shows staging intent → Obfuscated payload delivery</td>
<td>Medium</td>
<td>CISA AA24-109A; Picus Security (Feb 2026)</td>
</tr>
<tr>
<td>14</td>
<td>Defense Evasion</td>
<td><strong>T1222.001</strong> - File Permission Modification</td>
<td>Observed in reports where <code>icacls.exe</code> is used to grant broad permissions on target directories before encryption, ensuring the encryptor can access files regardless of ACL restrictions.</td>
<td>Sysmon EID 1: <code>icacls.exe</code> with broad grant arguments; EID 4688</td>
<td><strong>Detect:</strong><br>• <code>icacls.exe</code> granting full access to Everyone on a directory<br>• Execution from SYSTEM context via a scheduled task<br>• Targets directories outside standard admin paths</td>
<td>SYSTEM-context permission grant + writable path targets + encryptor drop follows → Pre-encryption access staging</td>
<td>Medium</td>
<td>CISA AA24-109A; SOCPrime detection notes</td>
</tr>
<tr>
<td>15</td>
<td>Discovery</td>
<td><strong>T1016</strong> - Network Configuration Discovery</td>
<td>Early in intrusions, operators enumerate drives, adapters, ARP cache, and routes. Commonly seen run in rapid sequence from the same remote session, suggesting scripted recon.</td>
<td>Sysmon EID 1: <code>ipconfig.exe</code>, <code>arp.exe</code>, <code>route.exe</code>, <code>fsutil.exe</code> in sequence; EID 4688</td>
<td><strong>Detect:</strong><br>• Multiple discovery binaries run in rapid sequence from same session<br>• Commands originating from a remote session process<br>• No administrative justification in surrounding context</td>
<td>Rapid sequential recon commands + remote session parent → Scripted environment mapping</td>
<td>Medium</td>
<td>CISA AA24-109A</td>
</tr>
<tr>
<td>16</td>
<td>Discovery</td>
<td><strong>T1018</strong> - Remote System Discovery</td>
<td>Network scanning tools are deployed in observed incidents to identify reachable internal hosts. <code>netscan.exe</code> and Advanced IP Scanner appear most frequently in reports.</td>
<td>Sysmon EID 1: <code>netscan.exe</code> / <code>advanced_ip_scanner.exe</code>; NetFlow: one host sweeping many internal IPs</td>
<td><strong>Detect:</strong><br>• Known scanner binary executing from a user session<br>• Single internal host connecting to many unique internal IPs in a short window<br>• Scanner binary dropped to writable directory before execution</td>
<td>Scanner binary + internal sweep pattern from one host → Active lateral movement preparation</td>
<td>Medium</td>
<td>CISA AA24-109A; Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>17</td>
<td>Discovery</td>
<td><strong>T1087.002</strong> - Domain Account Discovery</td>
<td>AD enumeration is consistently observed before lateral movement. SharpHound, AdFind, and <code>nltest</code> appear across multiple Akira incident reports as primary tools.</td>
<td>Sysmon EID 1: <code>SharpHound.exe</code>, <code>adfind.exe</code>, <code>nltest.exe</code>; Win Security EID 4661/4662</td>
<td><strong>Detect:</strong><br>• SharpHound or AdFind executing from a non-admin workstation<br>• <code>nltest.exe</code> with domain controller enumeration flags<br>• Burst of directory object access from one account [EID 4662]</td>
<td>AD enumeration + Kerberoasting in same session + RDP to DC → Full pre-lateral-movement recon chain</td>
<td>Medium</td>
<td>CISA AA24-109A; Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>18</td>
<td>Discovery</td>
<td><strong>T1082</strong> - System Information Discovery</td>
<td>In some incidents, the encryptor itself queries system info and the <code>MachineGUID</code> registry key on execution — likely for environment fingerprinting before proceeding.</td>
<td>Win Security EID 4663 (registry access on <code>HKLM\SOFTWARE\Microsoft\Cryptography</code>); Sysmon EID 1</td>
<td><strong>Detect:</strong><br>• Newly dropped binary querying <code>MachineGUID</code> registry key<br>• System API calls from a process shortly before file modification begins<br>• Registry access from an unknown or recently created binary</td>
<td>Registry read + API call + file modification follows → Encryptor environment fingerprint</td>
<td>Medium</td>
<td>CISA AA24-109A; AttackIQ emulation (Nov 2025)</td>
</tr>
<tr>
<td>19</td>
<td>Lateral Movement</td>
<td><strong>T1021.001</strong> - Remote Desktop Protocol</td>
<td>RDP is the most commonly observed lateral movement method in Akira incidents. Operators pivot from workstations to domain controllers and backup servers using harvested credentials. Pass-the-hash also observed in reports.</td>
<td>Win Security EID 4624 (Type 10 on target); EID 4648; EID 4778</td>
<td><strong>Detect:</strong><br>• Logon Type 10 from a workstation to a domain controller<br>• RDP from a host with no prior baseline of originating RDP<br>• Alternate credential use during session establishment [EID 4648]</td>
<td>Workstation → DC RDP + no baseline + alternate creds → Lateral movement to high-value target</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025); Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>20</td>
<td>Lateral Movement</td>
<td><strong>T1021.002</strong> - SMB / Admin Shares</td>
<td>SMB is observed in reports alongside RDP and SSH — particularly in multi-domain environments. Used to move files or execute payloads across admin shares with harvested credentials.</td>
<td>Win Security EID 4624 (Type 3); Sysmon EID 3 (port 445 internal)</td>
<td><strong>Detect:</strong><br>• Type 3 logins to multiple internal hosts in rapid succession from one source<br>• Access to <code>ADMIN$</code> or <code>C$</code> from a standard workstation account<br>• SMB from a host with no baseline of admin share access</td>
<td>Rapid Type 3 logins to multiple hosts + admin share access → SMB-based lateral spread</td>
<td>Medium</td>
<td>Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>21</td>
<td>Lateral Movement</td>
<td><strong>T1021.004</strong> - SSH</td>
<td>Used in observed incidents to reach Linux systems, ESXi hosts, and Nutanix AHV environments. In the June 2025 incident, SSH to the hypervisor management plane followed the SonicWall compromise. <code>plink.exe</code> also observed on Windows hosts.</td>
<td>Sysmon EID 1: <code>ssh.exe</code> / <code>plink.exe</code>; outbound TCP 22 from workstation; hypervisor auth logs</td>
<td><strong>Detect:</strong><br>• Outbound SSH from a Windows workstation to an internal server<br>• <code>plink.exe</code> executing from any user session<br>• SSH login to a hypervisor from an unexpected source IP</td>
<td>Workstation SSH + hypervisor as target + VM shutdown follows → Pre-encryption hypervisor pivot</td>
<td>High</td>
<td>CISA AA24-109A (Jun 2025); Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>22</td>
<td>C2</td>
<td><strong>T1219</strong> - Remote Access Tools</td>
<td>Commercial RATs maintain redundant C2 alongside the initial VPN access. AnyDesk, LogMeIn, MobaXterm, and RustDesk all appear in observed incident reports. Installed silently from writable directories.</td>
<td>Sysmon EID 1 / EID 11: RAT binary dropped and executed; EID 3: outbound to vendor relay</td>
<td><strong>Detect:</strong><br>• Known RAT binary executing from a writable path<br>• Silent install flag used during execution<br>• Outbound connection to vendor relay from an unexpected host</td>
<td>RAT binary drop + silent install + relay connection → Parallel C2 channel established</td>
<td>Medium</td>
<td>CISA AA24-109A; Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
<tr>
<td>23</td>
<td>C2</td>
<td><strong>T1572</strong> - Protocol Tunneling (Ngrok)</td>
<td>Ngrok is used in observed incidents to wrap C2 traffic in HTTPS, bypassing egress filtering. Explicitly noted in the CISA November 2025 update. DNS queries to Ngrok domains are a reliable detection point.</td>
<td>Sysmon EID 1: <code>ngrok.exe</code>; EID 22 (DNS query to <code>*.ngrok.io</code>); EID 3: outbound HTTPS from ngrok</td>
<td><strong>Detect:</strong><br>• <code>ngrok.exe</code> executing from any internal host<br>• DNS resolution of <code>ngrok.io</code> or <code>ngrok-free.app</code> internally<br>• Sustained outbound HTTPS connection from ngrok process</td>
<td>Ngrok execution + DNS query to ngrok domain → Active egress tunnel</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025)</td>
</tr>
<tr>
<td>24</td>
<td>Exfiltration</td>
<td><strong>T1560.001</strong> - Archive via Utility</td>
<td>Data staging through compression is commonly seen before exfiltration in Akira incidents. WinRAR is most frequently observed. In the Unit 42 November 2025 incident, large archives were staged across multiple shares over several days.</td>
<td>Sysmon EID 1: <code>winrar.exe</code> / <code>7z.exe</code>; EID 11: large <code>.rar</code> / <code>.7z</code> files in writable paths</td>
<td><strong>Detect:</strong><br>• Archive tool spawned from a remote session process<br>• Large compressed files written to world-writable paths<br>• Archives created across multiple shares in a short window</td>
<td>Archive creation across multiple shares + remote session parent + exfil tool execution follows → Data staged for exfiltration</td>
<td>Medium</td>
<td>Unit 42 Howling Scorpius (Nov 2025); CISA AA24-109A</td>
</tr>
<tr>
<td>25</td>
<td>Exfiltration</td>
<td><strong>T1048</strong> - Exfiltration Over Alternative Protocol</td>
<td>FileZillaPortable and rclone are observed across multiple Akira incident reports. In the Unit 42 November 2025 incident, close to 1 TB was moved out using FileZillaPortable before encryption began.</td>
<td>Sysmon EID 1 / EID 3: <code>rclone.exe</code> / <code>filezillaportable.exe</code> with outbound connections; NetFlow: sustained high-volume egress</td>
<td><strong>Detect:</strong><br>• <code>rclone.exe</code> or <code>filezillaportable.exe</code> executing from a user session<br>• Exfil tool spawned from a remote session process<br>• Sustained high-volume outbound traffic from a single host</td>
<td>rclone / FileZilla execution + high-volume egress + staging archives precede it → Active data exfiltration</td>
<td>High</td>
<td>Unit 42 Howling Scorpius (Nov 2025); CISA AA24-109A</td>
</tr>
<tr>
<td>26</td>
<td>🔴 Pre-Impact</td>
<td><strong>T1490</strong> - Inhibit System Recovery</td>
<td>Shadow copy deletion is present in nearly all documented Akira attacks immediately before encryption. Multiple methods used — <code>vssadmin</code>, <code>wmic</code>, and PowerShell WMI — suggesting it is a mandatory step in the playbook.</td>
<td>Sysmon EID 1 / EID 4688: <code>vssadmin.exe delete shadows</code>; PowerShell EID 4104</td>
<td><strong>Detect:</strong><br>• Any execution of <code>vssadmin delete shadows</code> — treat as incident-level<br>• WMI shadow copy deletion from a non-SYSTEM process<br>• PowerShell block referencing <code>Win32_ShadowCopy.Delete()</code> [EID 4104]</td>
<td>VSS deletion + service stops in same session → Near-certain pre-encryption stage</td>
<td>High</td>
<td>CISA AA24-109A; ANY.RUN analysis</td>
</tr>
<tr>
<td>27</td>
<td>🔴 Pre-Impact</td>
<td><strong>T1489</strong> - Service Stop</td>
<td>Backup agents, databases, and application services are stopped before encryption to release file locks. Veeam Backup Service is specifically targeted across multiple Akira incident reports.</td>
<td>Win Security EID 4688: <code>net.exe stop</code>; Win System EID 7036 (service stopped)</td>
<td><strong>Detect:</strong><br>• <code>net stop</code> targeting known backup agent services (Veeam, BackupExec, Windows Backup)<br>• Multiple critical services stopped in rapid sequence from same session<br>• Database services stopping alongside backup services</td>
<td>Backup + DB service stops in rapid sequence + VSS deletion → Pre-encryption infrastructure shutdown</td>
<td>High</td>
<td>CISA AA24-109A; PacketWatch CTI (Nov 2025)</td>
</tr>
<tr>
<td>28</td>
<td>Impact</td>
<td><strong>T1486</strong> - Data Encrypted for Impact</td>
<td>The encryptor (commonly named <code>w.exe</code>) targets local drives and network shares. Akira_v2 uses partial interleaved encryption for speed. Ransom note <code>akira_readme.txt</code> written to each encrypted directory. Megazord (<code>.powerranges</code>) believed largely out of use since 2024.</td>
<td>Sysmon EID 11: high-rate <code>.akira</code> file creation; EID 23: mass file modification; <code>akira_readme.txt</code> in multiple directories</td>
<td><strong>Detect:</strong><br>• High-rate file extension changes to <code>.akira</code> across multiple directories [EID 11]<br>• Ransom note (<code>akira_readme.txt</code>) appearing in multiple paths simultaneously<br>• Mass file modification following prior VSS deletion [EID 23]</td>
<td>Ransom note drop + mass modification + prior VSS deletion → Confirmed active encryption</td>
<td>High</td>
<td>CISA AA24-109A (Nov 2025); Unit 42; ANY.RUN analysis</td>
</tr>
<tr>
<td>29</td>
<td>Impact</td>
<td><strong>T1529</strong> - System Shutdown / Reboot</td>
<td>In hypervisor-targeted attacks, VMs are powered off via management interfaces before disk files are encrypted directly on the datastore. Observed in the June 2025 Nutanix AHV incident. Bypasses in-guest security tools entirely.</td>
<td>ESXi / Nutanix AHV management logs: VM power-off commands from unexpected account or IP</td>
<td><strong>Detect:</strong><br>• VM power-off commands outside maintenance windows<br>• Multiple VMs shut down sequentially by the same account<br>• Shutdown from an unexpected source IP or account</td>
<td>SSH to hypervisor + bulk VM shutdown outside change window → Pre-encryption hypervisor staging</td>
<td>High</td>
<td>CISA AA24-109A (Jun 2025); Unit 42 Howling Scorpius (Nov 2025)</td>
</tr>
</tbody>
</table>

</div>

---

## Detection Priority at a Glance

<div style="overflow-x: auto;">

| Priority | Technique | Why It Matters |
|----------|-----------|----------------|
| 🔴 Critical | T1490 - VSS Deletion | Present in nearly all documented attacks; any instance = incident-level response |
| 🔴 Critical | T1070.001 - Log Clearing | EID 1102 / EID 104 have almost no legitimate use in production |
| 🔴 Critical | T1486 - Ransomware | `akira_readme.txt` is a low-noise, confirmed IOC |
| 🟠 High | T1003.001 - LSASS Dump | Sysmon EID 10 against LSASS from an unrecognized process is a reliable, low-noise signal |
| 🟠 High | T1572 - Ngrok | Internal `ngrok.io` DNS resolution has very limited legitimate enterprise use |
| 🟠 High | T1021.001 - RDP to DC | Workstation → DC via Logon Type 10 is rarely legitimate |
| 🟡 Medium | T1087.002 - AD Enumeration | SharpHound / AdFind execution is a reliable pre-lateral-movement indicator |
| 🟡 Medium | T1136 - Account Creation | EID 4720 → 4732 rapid sequence is a consistent persistence signal |
| 🟡 Medium | T1560.001 - Data Staging | Large archive creation in temp/public paths warrants investigation |

</div>

---

## Kill-Chain Correlation Sequences

*Multi-event chains are the foundation of confident triage decisions. A single event rarely tells the full story.*

**Chain 1 - Pre-encryption (highest urgency):**
> VSS deletion (T1490) + Service stop (T1489) + Permission grant (T1222) → **Encryption is imminent**

**Chain 2 - Credential abuse → lateral movement:**
> LSASS dump (T1003.001) + Kerberoasting (T1558.003) + RDP to DC (T1021.001) → **Domain compromise in progress**

**Chain 3 - Staging → exfiltration:**
> AD enumeration (T1087.002) + Archive creation (T1560.001) + rclone / FileZilla (T1048) → **Data exfiltration underway**

**Chain 4 - Hypervisor attack path:**
> VPN access (T1190 / T1078) + SSH to hypervisor (T1021.004) + Bulk VM shutdown (T1529) → **ESXi / AHV encryption imminent**

---

*Sources: CISA AA24-109A (Nov 2025) · Unit 42 Howling Scorpius (Nov 2025) · FBI Joint Advisory · PacketWatch CTI (Nov 2025) · ANY.RUN behavioral analysis · Picus Security (Feb 2026) · AttackIQ emulation (Nov 2025)*  
*Windows-based Event IDs unless otherwise noted. "Observed in reports" and "commonly seen" reflect that behaviors are sourced from incident reporting, not universal across all intrusions.*
