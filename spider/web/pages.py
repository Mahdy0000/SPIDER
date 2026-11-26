"""Crawler: BFS over same-host links inside the allowlist; extracts links, forms and comments."""
import re
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .client import BudgetExceeded
from .scope import ScopeError


class Page:
    def __init__(self, response):
        self.url = response.url
        self.response = response
        self.links, self.forms, self.scripts, self.comments, self.mixed = [], [], [], [], []
        ctype = response.header("Content-Type", "")
        self.is_html = "html" in ctype.lower() or response.body.lstrip()[:15].lower().startswith(("<!doctype", "<html"))
        if self.is_html:
            self._parse(response.body)

    def _parse(self, html):
        page = self

        class P(HTMLParser):
            form = None

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "a" and a.get("href"):
                    page.links.append(urljoin(page.url, a["href"]))
                elif tag == "script" and a.get("src"):
                    src = urljoin(page.url, a["src"])
                    page.scripts.append(src)
                    if page.url.startswith("https:") and src.startswith("http:"):
                        page.mixed.append(src)
                elif tag == "form":
                    self.form = {"action": urljoin(page.url, a.get("action") or page.url),
                                 "method": (a.get("method") or "get").lower(), "inputs": [],
                                 "autocomplete": (a.get("autocomplete") or "").lower()}
                    page.forms.append(self.form)
                elif tag in ("input", "textarea", "select") and self.form is not None:
                    self.form["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower(),
                                                "autocomplete": (a.get("autocomplete") or "").lower()})

            def handle_endtag(self, tag):
                if tag == "form":
                    self.form = None

            def handle_comment(self, data):
                page.comments.append(data.strip())

        try:
            P().feed(html)
        except Exception:  # malformed HTML must not stop a review
            pass

    def query_params(self):
        q = urlsplit(self.url).query
        return [kv.split("=")[0] for kv in q.split("&") if kv]


def crawl(client, start, max_pages=25, max_depth=2):
    """Return (pages, errors). Out-of-scope links are skipped silently; the start URL must be in scope."""
    client.scope.check(start)
    host = urlsplit(start).netloc
    seen, queue, pages, errors = set(), [(start, 0)], [], []
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        url = urldefrag(url)[0]
        if url in seen:
            continue
        seen.add(url)
        try:
            r = client.get(url)
        except ScopeError:
            continue
        except BudgetExceeded as e:
            errors.append(str(e))
            break
        except ConnectionError as e:
            errors.append(str(e))
            continue
        page = Page(r)
        pages.append(page)
        if depth < max_depth:
            for link in page.links:
                p = urlsplit(link)
                if p.scheme in ("http", "https") and p.netloc == host and link not in seen:
                    if not re.search(r"\.(png|jpe?g|gif|svg|ico|css|woff2?|pdf|zip|mp4)(\?|$)", p.path, re.I):
                        queue.append((link, depth + 1))
    return pages, errors
