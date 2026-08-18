"""Scope & safety boundary for the agentic engine.

This is the guardrail every network-touching step consults.  It answers two
questions deterministically, before any browser navigation or request:

* ``is_in_scope(url)`` — is this URL allowed at all?  (host allowlist derived
  from the seed URL + an optional subdomain policy, plus optional path prefixes.)
* ``is_destructive(method, url, form)`` — would acting on this change server
  state?  In read-only mode the collector never fires these, so the tool stays a
  *detector*, not an attacker.

Keeping the policy in one small, dependency-free module means the boundary is
easy to audit and easy to unit-test without a browser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

# Methods that can change state on the server.
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# URL/action substrings that signal a state-changing or dangerous operation even
# on a GET (e.g. ``/logout``, ``/account/delete?id=3``).  Kept deliberately broad
# — in read-only mode a false positive only means "we don't submit it".
_DESTRUCTIVE_PATTERNS = re.compile(
    r"(logout|signout|sign-out|delete|remove|destroy|drop|reset|"
    r"pay|payment|checkout|purchase|order/place|transfer|withdraw|"
    r"password|passwd|deactivate|disable|revoke|admin|grant|"
    r"unsubscribe|cancel|refund|wipe|truncate)",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _root_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@dataclass
class Scope:
    """The set of targets a scan is authorized to touch.

    Built from a seed URL with :meth:`from_seed`.  By default the scope is the
    seed's exact host; ``allow_subdomains`` widens it to the whole root domain.
    """

    seed_url: str
    hosts: List[str] = field(default_factory=list)
    allow_subdomains: bool = False
    path_prefixes: List[str] = field(default_factory=list)
    max_pages: int = 40
    read_only: bool = True

    @classmethod
    def from_seed(
        cls,
        seed_url: str,
        allow_subdomains: bool = False,
        path_prefixes: Optional[List[str]] = None,
        max_pages: int = 40,
        read_only: bool = True,
    ) -> "Scope":
        host = _host(seed_url)
        return cls(
            seed_url=seed_url,
            hosts=[host] if host else [],
            allow_subdomains=allow_subdomains,
            path_prefixes=list(path_prefixes or []),
            max_pages=max_pages,
            read_only=read_only,
        )

    def is_in_scope(self, url: str) -> bool:
        """True if ``url`` is on an allowed host (and path prefix, if set)."""
        if not url or not url.lower().startswith(("http://", "https://")):
            return False
        host = _host(url)
        if not host:
            return False

        allowed = False
        for base in self.hosts:
            if host == base:
                allowed = True
                break
            if self.allow_subdomains and _root_domain(host) == _root_domain(base):
                allowed = True
                break
        if not allowed:
            return False

        if self.path_prefixes:
            path = urlparse(url).path or "/"
            if not any(path.startswith(p) for p in self.path_prefixes):
                return False
        return True

    def is_destructive(
        self, method: str = "GET", url: str = "", form: Optional[dict] = None
    ) -> bool:
        """True if acting on this target could change server state.

        A write HTTP method is destructive by definition; a GET is flagged only
        when its URL/action matches a destructive keyword.
        """
        m = (method or "GET").upper()
        action = url or (form or {}).get("action", "")
        if m in _WRITE_METHODS:
            return True
        if action and _DESTRUCTIVE_PATTERNS.search(action):
            return True
        return False
