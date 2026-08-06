# -*- coding: utf-8 -*-
"""
Security primitives shared by every protocol module.
"""
from __future__ import annotations

import html
import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape


class TargetPolicyError(ValueError):
    """Raised when an active-scan target violates the safety policy."""


def html_escape(value: Any) -> str:
    """Strict HTML entity escaping for any untrusted value."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(html_escape(v) for v in value)
    return html.escape(str(value), quote=True)


def safe_render(
    template_name: str,
    context: dict[str, Any],
    template_dir: str | os.PathLike[str] = "reports/templates",
) -> str:
    """Render a Jinja2 template with autoescape ON."""
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "htm", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template(template_name)
    return tmpl.render(**context)


_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def is_safe_target(
    target: str,
    *,
    allow_public: bool = False,
    max_hosts: int = 256,
) -> bool:
    """Return True if target (single IP or CIDR) is safe to actively probe."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise TargetPolicyError(f"Invalid IP/CIDR: {target!r}: {exc}") from exc

    if net.num_addresses > max_hosts:
        raise TargetPolicyError(
            f"CIDR {target} expands to {net.num_addresses} hosts "
            f"(max {max_hosts}). Narrow the range or raise `max_hosts`."
        )

    if net.is_loopback or net.is_link_local or net.is_private or net.is_reserved:
        return True

    if allow_public:
        return True

    raise TargetPolicyError(
        f"Refusing to scan public address {target}. "
        "Pass allow_public=True only after written authorization from the asset owner."
    )


def filter_targets(
    targets: Iterable[str],
    *,
    allow_public: bool = False,
    max_hosts: int = 256,
) -> list[str]:
    """Apply `is_safe_target` over a list and return the safe subset."""
    safe: list[str] = []
    for t in targets:
        try:
            if is_safe_target(t, allow_public=allow_public, max_hosts=max_hosts):
                safe.append(t)
        except TargetPolicyError as exc:
            logging.getLogger("ics_scanner").warning("Skipping unsafe target %s: %s", t, exc)
    return safe


_TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|%2e%2e)", re.IGNORECASE)


def safe_join_path(base: str | os.PathLike[str], *parts: str) -> Path:
    """Join path parts while rejecting any traversal attempt."""
    base_path = Path(base).resolve()
    for p in parts:
        if _TRAVERSAL_RE.search(p):
            raise ValueError(f"Path traversal attempt blocked: {p!r}")
    full = (base_path / Path(*parts)).resolve()
    if base_path not in full.parents and full != base_path:
        raise ValueError(f"Resolved path escapes base: {full}")
    return full


def configure_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Configure a logger with a consistent format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
    return logger
