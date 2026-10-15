# Nessus Findings & Remediation

Authenticated (credentialed) Nessus scan of the Windows 11 endpoint. Three
findings were triaged for remediation. Two were fixed and verified by re-scan;
one (Intel BHI) could not be fully remediated from inside the guest VM.

| # | Finding | CVE | CVSS | Severity | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | WinVerifyTrust signature validation (cert padding) | CVE-2013-3900 | 8.8 | High | **Fixed & verified** |
| 2 | Windows Update reboot required | — | 8.4 | High | **Fixed & verified** |
| 3 | Intel Branch History Injection (BHI) | CVE-2022-0001 | 6.5 | Medium | **Not remediated** |

---

## 1. WinVerifyTrust / CVE-2013-3900 — Fixed

**Issue:** missing/misconfigured `EnableCertPaddingCheck` registry values let a
signed binary be modified without invalidating its Authenticode signature.

**Remediation** (admin, both paths on a 64-bit OS; value is a REG_SZ of `1`):
```
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
```

**Verification:** `reg query` returns `1` on both paths; the finding no longer
appears in the `Win11-credentialed-post` re-scan.

---

## 2. Windows Update reboot required — Fixed

**Issue:** security-relevant updates were installed but pending a reboot, leaving
the host exposed until the reboot completed.

**Remediation:** installed all pending updates and rebooted.
```
shutdown /r /t 0
```

**Verification:** the pending-reboot registry flag cleared after reboot; the
finding cleared in the re-scan.

---

## 3. Intel BHI / CVE-2022-0001 — Not remediated (documented limitation)

**Issue:** a CPU speculative-execution side-channel (Branch History Injection).
The mitigation is delivered through Windows cumulative updates **and CPU
microcode**.

**Action taken:** applied all available Windows updates and rebooted.

**Why it remained:** this Windows 11 host is a **virtual machine**. BHI mitigation
depends on the microcode exposed by the **hypervisor host's CPU**, which a guest
cannot change via Windows Update. After patching, residual exposure still depends
on the host's microcode, so Nessus continued to report the finding.

**Assessment:** this is an expected virtualization limitation rather than a failed
remediation, and a useful illustration that not every finding can be fully resolved
from the affected asset alone. Full remediation would require updating the host's
BIOS/UEFI microcode (out of scope for this lab).

---

## Remediate-and-verify loop

1. Baseline credentialed scan → `Win11-credentialed-pre`
2. Apply fixes (above)
3. Single reboot to apply registry + updates + clear pending-reboot
4. Re-scan → `Win11-credentialed-post`
5. Confirm findings 1 & 2 cleared; document finding 3's residual exposure
