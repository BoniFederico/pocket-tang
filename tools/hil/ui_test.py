"""Admin UI checks over the LAN (requires LAN admin enabled and a known admin password).

Exercises authentication, login back-off, the session cookie flags, CSRF protection, key
rotation, the recovery lock and the security headers, without joining the setup access point.
"""
from __future__ import annotations

import http.client
import json
import re
import time
import urllib.parse


class Client:
    def __init__(self, host: str, port: int = 80):
        self.host, self.port = host, port
        self.cookie = ""

    def req(self, method: str, path: str, form: dict | None = None, cookie: bool = True):
        c = http.client.HTTPConnection(self.host, self.port, timeout=30)
        headers = {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie and self.cookie:
            headers["Cookie"] = self.cookie
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, hdrs, data


def csrf_of(html: str) -> str:
    m = re.search(r'name=csrf value="([^"]+)"', html)
    return m.group(1) if m else ""


def run(base: str, password: str, rec_check) -> dict:
    """rec_check() -> HTTP status of a valid /rec request."""
    u = urllib.parse.urlparse(base)
    cl = Client(u.hostname, u.port or 80)
    res: dict[str, object] = {}

    st, h, body = cl.req("GET", "/admin")
    res["login_page"] = st == 200 and "Admin password" in body
    res["csp_header"] = "default-src 'none'" in h.get("content-security-policy", "")
    res["no_store"] = h.get("cache-control") == "no-store"
    res["frame_deny"] = h.get("x-frame-options") == "DENY"

    st, _, _ = cl.req("POST", "/admin/rotate", {"csrf": "x"})
    res["unauth_post_refused"] = st in (200, 403)  # renders the login page, no action

    statuses = [cl.req("POST", "/admin/login", {"password": "wrong-password"})[0] for _ in range(4)]
    res["wrong_password_statuses"] = statuses
    res["backoff_engaged"] = 429 in statuses
    time.sleep(6)  # third failure blocks for 5 s

    st, h, _ = cl.req("POST", "/admin/login", {"password": password})
    sc = h.get("set-cookie", "")
    res["login_ok"] = st == 303 and "ptsid=" in sc
    res["cookie_flags"] = all(f in sc for f in ("HttpOnly", "SameSite=Strict", "Path=/admin"))
    cl.cookie = sc.split(";")[0]

    st, _, body = cl.req("GET", "/admin")
    token = csrf_of(body)
    res["dashboard"] = st == 200 and "Rotate keys" in body and bool(token)
    # A JWK private member or any PEM private key block must never appear.
    res["no_private_material"] = '"d":' not in body and "PRIVATE KEY-----" not in body
    thp_before = re.findall(r"<td>signing</td><td><code>([^<]+)</code>", body)

    st, _, body = cl.req("POST", "/admin/rotate", {"csrf": "AAAAAAAAAAAAAAAAAAAAAA"})
    res["bad_csrf_refused"] = "Session expired" in body

    st, _, body = cl.req("POST", "/admin/rotate", {"csrf": token})
    thp_after = re.findall(r"<td>signing</td><td><code>([^<]+)</code>", body)
    res["rotate_ok"] = "Keys rotated" in body and thp_after != thp_before
    token = csrf_of(body) or token

    st, _, body = cl.req("POST", "/admin/lock", {"csrf": token, "lock": "1"})
    res["lock_page"] = "Recovery locked" in body
    res["rec_when_locked"] = rec_check()
    st, _, body = cl.req("POST", "/admin/lock", {"csrf": token, "lock": "0"})
    res["rec_when_unlocked"] = rec_check()

    st, _, body = cl.req("POST", "/admin/factory-reset", {"csrf": token, "confirm": "nope"})
    res["reset_needs_confirmation"] = "Type RESET" in body

    st, _, _ = cl.req("POST", "/admin/logout", {"csrf": token})
    st, _, body = cl.req("GET", "/admin")
    res["logout_ok"] = "Admin password" in body

    res["passed"] = all(
        v is True for k, v in res.items()
        if isinstance(v, bool)) and res["rec_when_locked"] == 403 and res["rec_when_unlocked"] == 200
    return res


if __name__ == "__main__":
    import sys
    print(json.dumps(run(sys.argv[1], sys.argv[2], lambda: 0), indent=2))
