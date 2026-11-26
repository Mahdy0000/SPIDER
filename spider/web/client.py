"""HTTP client for web review. Read-only (GET/HEAD), allowlist-checked on every request and redirect."""
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

from .scope import Scope, ScopeError

UA = "SPIDER-defensive-review/0.3 (authorized security review)"
MAX_BODY = 400_000


class BudgetExceeded(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Response:
    def __init__(self, url, status, headers, body, redirected_from=None):
        self.url, self.status, self.headers, self.body = url, status, headers, body
        self.redirected_from = redirected_from or []

    def header(self, name, default=""):
        return self.headers.get(name, default)

    def set_cookies(self):
        return self.headers.get_all("Set-Cookie") or []


class ScopedClient:
    def __init__(self, scope, max_requests=200, delay=0.0, timeout=15, max_redirects=5):
        if not isinstance(scope, Scope):
            raise TypeError("scope must be a Scope")
        self.scope, self.max_requests, self.delay, self.timeout = scope, max_requests, delay, timeout
        self.max_redirects = max_redirects
        self.count = 0
        self.log = []
        self._opener = urllib.request.build_opener(_NoRedirect)

    def get(self, url, headers=None):
        """GET url, following redirects only while every hop stays in scope."""
        chain = []
        for _ in range(self.max_redirects + 1):
            self.scope.check(url)  # raises ScopeError before anything is sent
            if self.count >= self.max_requests:
                raise BudgetExceeded(f"request budget of {self.max_requests} reached")
            self.count += 1
            if self.delay:
                time.sleep(self.delay)
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA, **(headers or {})})
            try:
                r = self._opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                r = e
            except (urllib.error.URLError, OSError) as e:
                self.log.append((url, "error"))
                raise ConnectionError(f"cannot reach {url}: {e}")
            status = r.status if hasattr(r, "status") else r.code
            self.log.append((url, status))
            if status in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                chain.append(url)
                url = urljoin(url, r.headers["Location"])
                continue
            body = r.read(MAX_BODY).decode("utf-8", errors="replace")
            return Response(url, status, r.headers, body, chain)
        raise ConnectionError("too many redirects")
