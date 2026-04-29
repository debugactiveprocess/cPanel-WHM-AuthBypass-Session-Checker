# CVE-2026-41940 Session Validation Tool

A companion tool for the watchTowr CVE-2026-41940 authentication bypass exploit. After running the main exploit against a cPanel/WHM target, this script validates whether the injected session actually grants authenticated access by testing multiple endpoints (HTML pages, JSON API, WHM Terminal) distinguishing between targets where the session injection succeeds but the server is patched (403 on all endpoints) versus fully compromised targets where the docheckpass_whostmgrd bypass works and root access is achieved.

## PoC Result

```bash
python3 check_session.py --target https://127.0.0.1:2087/
```

![PoC Result](https://i.imgur.com/UOVQYze.png)

---

## Research Attribution

The original research and technical analysis referenced in this project were conducted by **watchTowr Labs**.

- **Title:** *The Internet is Falling Down, Falling Down, Falling Down – cPanel & WHM Authentication Bypass (CVE-2026-41940)*  
- **Source:** https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/

## Acknowledgment

All credit for the discovery, investigation, and disclosure of **CVE-2026-41940** belongs to *watchTowr Labs*.  
This project does not claim ownership of the original findings and is intended solely for educational, analytical, or defensive security purposes.

## Disclaimer

This material is provided for informational and security research purposes only.  
Users are responsible for ensuring that any testing or usage complies with applicable laws and is performed only in authorized environments.
