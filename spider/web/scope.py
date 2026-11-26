"""Allowlist that every web request must pass. Nothing outside it is ever contacted.

Always allowed: loopback (localhost, 127.0.0.0/8, ::1, *.localhost), which is where practice labs
such as DVWA or OWASP Juice Shop run on your own machine.
Everything else must be named explicitly by you (--allow host, SPIDER_ALLOW, or --allow-file).
There is no "allow all" option on purpose.
"""
import ipaddress
import os
from urllib.parse import urlsplit


class ScopeError(RuntimeError):
    """Raised when a URL is outside the allowlist. The request is never sent."""


def _norm(entry):
    e = entry.strip().lower()
    if not e or e.startswith("#"):
        return None
    if "://" in e:
        e = urlsplit(e).hostname or ""
    e = e.split("/")[0]
    if e.count(":") == 1:  # host:port -> host (ports are not part of the allowlist)
        e = e.split(":")[0]
    return e.strip("[]") or None


def _is_loopback(host):
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Scope:
    BLOCKED_WILDCARDS = {"*", "*.*", "*.com", "*.net", "*.org", "*.io", "*.gov", "*.edu"}

    def __init__(self, allow=()):
        self.allow = set()
        for a in allow:
            n = _norm(a)
            if not n:
                continue
            if n in self.BLOCKED_WILDCARDS or (n.startswith("*.") and n[2:].count(".") == 0):
                raise ScopeError(f"allowlist entry '{a}' is too broad; name the host you own, e.g. app.example.com or *.example.com")
            self.allow.add(n)

    @classmethod
    def from_sources(cls, allow=(), allow_file=None, env=None):
        items = list(allow)
        env = os.environ.get("SPIDER_ALLOW", "") if env is None else env
        items += [x for x in env.replace(";", ",").split(",") if x.strip()]
        if allow_file:
            with open(allow_file, encoding="utf-8") as fh:
                items += fh.read().splitlines()
        return cls(items)

    def host_allowed(self, host):
        host = (host or "").lower().strip("[]")
        if not host:
            return False
        if _is_loopback(host) or host in self.allow:
            return True
        return any(a.startswith("*.") and host.endswith(a[1:]) for a in self.allow)

    def check(self, url):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"refusing {url!r}: only http(s) URLs are supported")
        if not self.host_allowed(parts.hostname):
            raise ScopeError(
                f"refusing {url!r}: host '{parts.hostname}' is not on your allowlist. "
                "SPIDER only tests localhost and hosts you name with --allow (systems you own or are authorized to test).")
        return url

    def describe(self):
        return "localhost/loopback" + ("".join(f", {a}" for a in sorted(self.allow)))
