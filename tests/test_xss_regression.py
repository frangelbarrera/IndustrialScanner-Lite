# -*- coding: utf-8 -*-
"""Verify that HTML reports escape untrusted input (XSS regression)."""
from __future__ import annotations

from pathlib import Path

from dnp3_monitor.dnp3_analyze import build_html


def test_dnp3_html_escapes_untrusted_payload():
    """A PCAP-derived field containing <script> MUST NOT appear verbatim in HTML."""
    malicious = "<script>alert('XSS')</script>"
    report = {
        "meta": {"generated_at": "2025-01-01T00:00:00Z", "pcap_file": malicious},
        "summary": {
            "total_packets": 0,
            "dnp3_packets": 0,
            "suspect_functions": 0,
            "unique_hosts": [malicious],
        },
        "results": [
            {"src": malicious, "dst": malicious, "function": malicious,
             "length": 0, "hints": [malicious], "suspect": True}
        ],
    }
    html = build_html(report)

    # Executable HTML tags MUST NOT appear verbatim — they get escaped.
    assert "<script>" not in html
    assert "</script>" not in html
    assert "&lt;script&gt;" in html

    # The browser-rendered text DOES contain "alert(" as visible content,
    # but the markup is inert. Verify the dangerous <script>...</script>
    # sequence is broken into escaped entities.
    assert "<script>alert(" not in html
