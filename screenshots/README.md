# Screenshots

Drop your evidence images here and reference them from the main README. Suggested
set (captured during the project):

- `01_sysmon_operational.png` — Sysmon Operational log filling in Event Viewer
- `02_splunk_sourcetypes.png` — `index=win-security | stats count by sourcetype` showing data arriving
- `03_sysmon_parsed_fields.png` — Sysmon EID 1 with Image / CommandLine / ParentImage extracted
- `04_nessus_findings_pre.png` — credentialed scan findings (before)
- `05_kali_attack.png` — nmap + hydra (RDP) success + smbexec SYSTEM shell
- `06_splunk_dashboard.png` — SOC detections dashboard with alerts firing
- `07_nessus_findings_post.png` — re-scan showing findings 1 & 2 resolved

Tip: sanitize anything you don't want public (hostnames tied to your real identity).
Private lab IPs (192.168.x.x) are fine to leave, but note in the README that they're
private RFC1918 addresses.
