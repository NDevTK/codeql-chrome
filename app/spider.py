"""CDP-based spider — drives Chrome through the live DOM.

Discovers links via Runtime.evaluate on the rendered page (not HTML parsing),
so it handles SPAs, JS-rendered navigation, and dynamic content. Each page
visited triggers the existing capture + analysis pipeline automatically.
"""
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlparse

from app.cdp_client import CDPPageClient


@dataclass
class SpiderConfig:
    scope: str = "same-origin"  # same-origin | same-domain | prefix | regex
    scope_pattern: str = ""     # for prefix/regex modes
    max_depth: int = 3
    max_pages: int = 50
    wait_after_load: float = 3.0  # seconds to wait after navigation for scripts
    navigate_timeout: float = 15.0


@dataclass
class PageResult:
    url: str
    depth: int
    links_found: int
    status: str  # "ok" | "error" | "skipped"
    error: str = ""


# JS to extract all navigable links from the live DOM
_EXTRACT_LINKS_JS = """
(() => {
    const links = new Set();
    // <a href>
    document.querySelectorAll('a[href]').forEach(a => {
        try { links.add(new URL(a.href, location.href).href); } catch(e) {}
    });
    // <area href>
    document.querySelectorAll('area[href]').forEach(a => {
        try { links.add(new URL(a.href, location.href).href); } catch(e) {}
    });
    // <form action>
    document.querySelectorAll('form[action]').forEach(f => {
        try { links.add(new URL(f.action, location.href).href); } catch(e) {}
    });
    // Filter to http(s) only, strip fragments
    const result = [];
    for (const u of links) {
        try {
            const parsed = new URL(u);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                parsed.hash = '';
                result.push(parsed.href);
            }
        } catch(e) {}
    }
    return result;
})()
"""


class Spider:
    def __init__(self, page_client: CDPPageClient, config: SpiderConfig,
                 on_page_start: Callable[[str, int], None] | None = None,
                 on_page_done: Callable[[PageResult], None] | None = None,
                 on_link_found: Callable[[str], None] | None = None):
        self._client = page_client
        self._config = config
        self._on_page_start = on_page_start
        self._on_page_done = on_page_done
        self._on_link_found = on_link_found

        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._stop = False
        self._start_origin: str = ""
        self._start_domain: str = ""

    @property
    def visited_count(self) -> int:
        return len(self._visited)

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    def stop(self):
        self._stop = True

    def crawl(self, start_url: str):
        """BFS crawl starting from start_url. Blocks until done or stopped."""
        parsed = urlparse(start_url)
        self._start_origin = f"{parsed.scheme}://{parsed.netloc}"
        self._start_domain = self._registered_domain(parsed.hostname or "")

        self._queue.append((self._normalize(start_url), 0))

        while self._queue and not self._stop:
            if len(self._visited) >= self._config.max_pages:
                break

            url, depth = self._queue.popleft()
            if url in self._visited:
                continue

            self._visited.add(url)

            if self._on_page_start:
                self._on_page_start(url, depth)

            result = self._visit(url, depth)

            if self._on_page_done:
                self._on_page_done(result)

    def _visit(self, url: str, depth: int) -> PageResult:
        """Navigate to a URL, wait for load, extract links, queue them."""
        try:
            self._client.navigate(url, timeout=self._config.navigate_timeout)
        except Exception as e:
            return PageResult(url=url, depth=depth, links_found=0,
                              status="error", error=str(e))

        # Wait for scripts to arrive and debounce to start
        time.sleep(self._config.wait_after_load)

        # Extract links from the live DOM
        try:
            result = self._client.evaluate(_EXTRACT_LINKS_JS)
            raw_links = result.get("result", {}).get("value", [])
            if not isinstance(raw_links, list):
                raw_links = []
        except Exception:
            raw_links = []

        # Filter and queue new links
        queued = 0
        if depth < self._config.max_depth:
            for link in raw_links:
                link = self._normalize(link)
                if link in self._visited:
                    continue
                if not self._in_scope(link):
                    continue
                if self._on_link_found:
                    self._on_link_found(link)
                self._queue.append((link, depth + 1))
                queued += 1

        return PageResult(url=url, depth=depth, links_found=len(raw_links),
                          status="ok")

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is within the configured crawl scope."""
        parsed = urlparse(url)
        scope = self._config.scope

        if scope == "same-origin":
            return f"{parsed.scheme}://{parsed.netloc}" == self._start_origin

        if scope == "same-domain":
            return self._registered_domain(parsed.hostname or "") == self._start_domain

        if scope == "prefix":
            prefix = self._config.scope_pattern
            return url.startswith(prefix) if prefix else True

        if scope == "regex":
            pattern = self._config.scope_pattern
            return bool(re.search(pattern, url)) if pattern else True

        return True

    @staticmethod
    def _normalize(url: str) -> str:
        """Strip fragment, trailing slash consistency."""
        parsed = urlparse(url)
        # Remove fragment
        clean = parsed._replace(fragment="").geturl()
        return clean

    @staticmethod
    def _registered_domain(hostname: str) -> str:
        """Simple domain extraction: last two parts for normal domains,
        last three for co.uk style."""
        parts = hostname.lower().rstrip(".").split(".")
        if len(parts) <= 2:
            return hostname.lower()
        # Handle two-part TLDs like co.uk, com.au
        if len(parts[-2]) <= 3 and len(parts[-1]) <= 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
