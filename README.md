# Purple Team Homelab — Attack, Detect, Remediate, Verify

An end-to-end purple-team project built in a personal homelab: I emulated a real
attack chain against a Windows endpoint, engineered detections for it in Splunk,
ran an authenticated vulnerability assessment with Nessus, and remediated and
re-validated the findings. The goal was to practice the full loop a SOC / blue
team actually runs — **generate attacker telemetry, detect it, fix the underlying
weaknesses, and prove the fix** — not just run tools.

Much of the value of this project was in the **problems I hit and worked through**,
which are documented honestly in the [Problems & Learning Curves](#problems--learning-curves)
section below.

---

## Architecture

Three machines on an isolated lab subnet (private RFC1918 addressing, `192.168.30.0/24`):

| Machine | Role | Key software |
| --- | --- | --- |
| **Kali Linux** | Attacker | nmap, hydra, Impacket, Metasploit |
| **Ubuntu Server** | Security / SIEM + scanner | Splunk Enterprise (web 8000, receiver 9997), Nessus (8834) |
| **Windows 11** | Victim / endpoint | Sysmon, Splunk Universal Forwarder |

**Telemetry flow:** Sysmon + Windows Event Logs on Windows 11 → Splunk Universal
Forwarder → Ubuntu Splunk receiver on 9997 → indexed in `win-security`. Nessus on
Ubuntu scans Windows 11 over SMB. Kali attacks Windows 11; the resulting events are
forwarded to Splunk and matched against detections.

```
        attacks                      logs (UF → :9997)
 Kali  ───────────▶  Windows 11  ──────────────────────▶  Ubuntu (Splunk + Nessus)
(attacker)          (victim)      ◀──────────────────────
                                   credentialed scan (:8834)
```

---

## Tooling & techniques (MITRE ATT&CK)

| Phase | Technique | ID | Tool |
| --- | --- | --- | --- |
| Recon | Network Service Discovery | T1046 | nmap |
| Credential Access | Brute Force | T1110 | hydra (RDP) |
| Execution / Lateral Movement | SMB/Admin Shares, Service Execution, Command Shell | T1021.002, T1569.002, T1059.003 | Impacket `smbexec` |

---

## What I did (process)

### 1. Stood up telemetry
Installed **Sysmon** (SwiftOnSecurity config) on Windows 11 and confirmed the
Universal Forwarder was shipping the **Security**, **System**, and
**Microsoft-Windows-Sysmon/Operational** channels to Splunk. Installed the
**Splunk Add-on for Microsoft Windows** and **Splunk Add-on for Sysmon** on the
Ubuntu Splunk instance so the XML events are field-extracted.

### 2. Discovered weaknesses (Nessus)
Ran an **authenticated / credentialed** scan of Windows 11 and triaged the
findings down to three actionable items (see
[findings/findings_and_remediation.md](findings/findings_and_remediation.md)).

### 3. Attacked (Kali)
- **Recon** — `nmap -sV -sC` to enumerate services (T1046).
- **Brute force** — `hydra` against a throwaway low-privilege account (T1110).
  Pivoted from SMB to **RDP** after discovering SMB null-session false positives
  (see learning curves).
- **Execution** — got a `NT AUTHORITY\SYSTEM` shell via Impacket **`smbexec`**
  after `psexec` was blocked by Windows Defender (T1021.002 / T1569.002).

### 4. Detected (Splunk)
Built four MITRE-mapped detections and saved them as scheduled alerts. The SPL for
each is in [detections/](detections/):

| Detection | ID | Source |
| --- | --- | --- |
| RDP/SMB brute force (4625 → 4624) | T1110 | Windows Security |
| Port scan (distinct dest ports from one source) | T1046 | Windows Filtering Platform (5156/5157) |
| Suspicious / encoded command execution | T1059 | Sysmon EID 1 |
| smbexec service execution | T1021.002 | Sysmon EID 1 |

### 5. Remediated & verified
Fixed two of the three findings and re-scanned to confirm closure. One finding
(Intel BHI) was intentionally left unremediated due to a lab limitation, documented
honestly below.

---

## Findings & remediation summary

| Finding | CVE | Severity | Status |
| --- | --- | --- | --- |
| WinVerifyTrust signature validation | CVE-2013-3900 | High (8.8) | **Fixed & verified** |
| Windows Update reboot required | — | High (8.4) | **Fixed & verified** |
| Intel Branch History Injection (BHI) | CVE-2022-0001 | Medium (6.5) | **Not remediated** (see note) |

**Why BHI was not remediated:** BHI is a CPU speculative-execution side-channel
whose mitigation depends on the **microcode exposed by the hypervisor host**, which
Windows Update cannot change from inside a guest VM. I applied all OS-level updates,
but residual exposure depends on the host CPU microcode — so this finding remained
after re-scan. This is an expected virtualization limitation, not a failed
remediation, and it is a good illustration that **not every finding is fully
fixable from the asset itself**. Full detail in
[findings/findings_and_remediation.md](findings/findings_and_remediation.md).

---

## Problems & Learning Curves

This is the part I'm proudest of — each of these was a real dead-end I diagnosed and
worked through, and each taught me something about how these systems actually behave.

### Networking
- **Ubuntu subnet mask set to /32.** Logs weren't reaching Splunk at all. Root cause:
  I'd set the mask to `255.255.255.255`, which tells the host it's the only machine on
  the network, so it couldn't route to the forwarder. **Lesson:** when *nothing* can
  reach a box, suspect Layer 3 (IP/mask/gateway) before the application — a simple
  `ping` would have caught it in seconds.

### Vulnerability scanning
- **Nessus returned 0 vulnerabilities (twice).** The scans were running
  *unauthenticated*: Windows was receiving the SMB traffic but dropping it, because my
  inbound firewall rule for SMB-In had the **wrong remote IP** (I'd entered the
  Windows host's own IP instead of the scanner's). **Lesson:** "0 findings" on a
  credentialed scan is a red flag, not a win — it usually means the scan never
  authenticated. The *remote address* in a firewall allow-rule is the **source** you're
  permitting, not the host itself.

### Getting Sysmon into Splunk (the big one)
- **Security & System logs forwarded, but Sysmon didn't.** Config looked perfect.
  Root cause: the Universal Forwarder runs as the low-privilege virtual account
  `NT SERVICE\SplunkForwarder`, which could read the classic logs but was **denied the
  Sysmon Operational channel** — `splunkd.log` showed `errorCode=5` (ACCESS_DENIED).
  Fix: add the account to the local **Event Log Readers** group.
  ```
  net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
  ```
  **Lesson:** "some logs work but one channel doesn't" is almost always a permissions
  gap on that specific channel, not a config typo. Read the forwarder's own log first.
- **The fix didn't take until a restart.** The group membership had actually been added
  earlier, but a Windows service only re-evaluates its permissions on restart.
  **Lesson:** forwarder config/permission changes require a service restart to apply.
- **Add-ons "installed" but nothing parsed.** They weren't in `$SPLUNK_HOME/etc/apps/` —
  the UI install had silently no-op'd. Installing the `.spl` files properly (and
  restarting) fixed it. **Lesson:** verify apps actually land in `etc/apps` and confirm
  extractions with `btool props list --debug`.
- **"The XML won't parse."** `XmlWinEventLog` events always display as a raw XML blob —
  that never changes and isn't a failure. "Parsed" means the **fields** (`Image`,
  `CommandLine`, …) are extracted on top of the raw XML; you see them when you `| table`
  them or in the Fields sidebar. **Lesson:** ingestion and parsing are different layers.

### Attacking
- **hydra SMB got no response — SMBv1 default.** hydra's `smb` module negotiates
  **SMBv1** by default, which Windows 11 disables. Forcing **SMB2** (`-m smb2`) fixed it.
  **Lesson:** modern Windows killed SMBv1 after EternalBlue; legacy tools that default to
  it silently fail.
- **hydra reported *every* password as valid.** The "successes" logged as
  `ANONYMOUS LOGON` — the box was accepting **null sessions**, so hydra's session setup
  "succeeded" regardless of the password. No real credential was cracked. **Lesson:**
  always check the `Account_Name` on a "success" and validate with a deliberately-wrong
  password before trusting brute-force results. I pivoted the brute force to **RDP**,
  which validates credentials properly.
- **psexec was caught, smbexec evaded — defense in depth.** `psexec` failed because
  Windows Defender quarantined the service binary it drops to disk. I pivoted to
  **`smbexec`**, which is effectively file-less (it runs commands through `cmd.exe` via a
  service and reads output back over SMB), so there was no binary for AV to flag — and it
  returned `NT AUTHORITY\SYSTEM`. **Lesson:** this is defense-in-depth in action —
  *prevention* (AV) blocked the noisy technique, the stealthier technique beat file-based
  AV, but it stays catchable by *detection* (it spams service-creation events).
- **Metasploit found nothing against the CVEs.** Expected — neither CVE-2022-0001 (a CPU
  side-channel) nor CVE-2013-3900 (a signature-validation weakness) is a remotely
  exploitable RCE. **Lesson:** severity ≠ exploitability. My actual code execution came
  from the credential-access chain, a far more realistic path.

### Detection engineering
- **Port scan only showed one port in Sysmon.** Sysmon EID 3 is **process-attributed** —
  it only logs connections a process actually handles, so it's blind to closed-port
  scan hits. **Lesson:** firewall / WFP logs (5156/5157) are the correct source for
  scan detection because they record every connection attempt, open or closed.
- **Searches returned 0 / no columns.** Two recurring traps: my data was in
  `index=win-security` (not the `index=win` placeholder), and `| stats` output lives
  under the **Statistics** tab, not **Events**. **Lesson:** confirm the index, and know
  where transformed results render.

---

## Skills demonstrated

- SIEM detection engineering in Splunk (SPL, saved alerts, MITRE ATT&CK mapping)
- Endpoint telemetry with Sysmon and the Splunk add-on pipeline
- Authenticated vulnerability assessment and the remediate-and-verify loop (Nessus)
- Offensive technique emulation (nmap, hydra, Impacket) and adapting when blocked
- Cross-layer troubleshooting: network → firewall → service permissions → log parsing
- Honest analysis: distinguishing false positives, severity vs. exploitability, and
  the limits of remediating a virtualized asset

---

## Repository layout

```
purple-team-homelab/
├── README.md                         # this file
├── detections/                       # Splunk SPL for each detection (MITRE-mapped)
│   ├── 01_brute_force_T1110.spl
│   ├── 02_port_scan_wfp_T1046.spl
│   ├── 03_suspicious_exec_T1059.spl
│   └── 04_smbexec_T1021.spl
├── findings/
│   └── findings_and_remediation.md   # the 3 Nessus findings, fixes, verification
└── screenshots/                      # add your evidence images here (see its README)
```

> **Note on IPs/credentials:** all addresses are private lab addresses; the only account
> credentials referenced are a throwaway lab account created for testing. No real
> credentials or externally routable hosts appear in this repo.
