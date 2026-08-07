"""Unified CLI entry point for IndustrialScanner (Click + Rich)."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from ics_scanner.security import (
    TargetPolicyError,
    configure_logging,
    filter_targets,
)

console = Console()
log = configure_logging("ics_scanner.cli")


@click.group(help="IndustrialScanner — read-only ICS/OT analyzer.")
@click.version_option(package_name="ics-ot-scanner")
def cli() -> None:
    """Entry group."""


@cli.command("modbus", help="Read-only Modbus/TCP scan against one or more targets.")
@click.option("--targets", required=True, help="Comma-separated IPs, CIDR (<= /24), or @file")
@click.option("--port", default=502, show_default=True, help="Modbus/TCP port")
@click.option("--unit", default=1, show_default=True, help="Modbus Unit ID")
@click.option("--timeout", default=2.0, show_default=True, help="Socket timeout (s)")
@click.option("--json-out", default=None, help="JSON report path")
@click.option("--html-out", default=None, help="HTML report path")
@click.option("--allow-public", is_flag=True, default=False,
              help="Allow scanning public IPs (REQUIRES WRITTEN AUTHORIZATION)")
def modbus_cmd(targets: str, port: int, unit: int, timeout: float,
               json_out: str | None, html_out: str | None,
               allow_public: bool) -> None:
    from modbus_scanner.modbus_scan import (
        expand_targets,
        scan_targets,
        write_html_report,
        write_json_report,
    )
    from modbus_scanner.utils import utc_ts

    raw = expand_targets(targets)
    safe = filter_targets(raw, allow_public=allow_public)
    if not safe:
        console.print("[red]No safe targets after policy filtering. Aborting.[/red]")
        sys.exit(2)

    log.info("Scanning %d target(s): %s", len(safe), safe)
    data = scan_targets(targets=safe, port=port, unit_id=unit, timeout=timeout)

    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/modbus_batch/modbus_scan_{ts}.json")
    html_path = Path(html_out or f"reports/modbus_batch/modbus_scan_{ts}.html")
    write_json_report(data, json_path)
    write_html_report(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")

    t = Table(title="Modbus Scan Summary")
    t.add_column("IP"); t.add_column("Reachable"); t.add_column("Latency ms"); t.add_column("Errors")
    for r in data["results"]:
        t.add_row(r["ip"], "OK" if r["reachable"] else "FAIL",
                  str(r["latency_ms"]), str(len(r["errors"])))
    console.print(t)


@cli.command("s7", help="Passive S7Comm analyzer (single PCAP).")
@click.option("--pcap", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--json-out", default=None)
@click.option("--html-out", default=None)
def s7_cmd(pcap: str, json_out: str | None, html_out: str | None) -> None:
    from modbus_scanner.utils import utc_ts
    from s7_comm_analyzer.s7_analyze import analyze_pcap, write_html_report, write_json_report

    data = analyze_pcap(pcap)
    base = Path(pcap).stem
    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/s7_batch/{base}_{ts}.json")
    html_path = Path(html_out or f"reports/s7_batch/{base}_{ts}.html")
    write_json_report(data, json_path)
    write_html_report(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")


@cli.command("dnp3", help="Passive DNP3 analyzer (single PCAP).")
@click.option("--pcap", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--json-out", default=None)
@click.option("--html-out", default=None)
def dnp3_cmd(pcap: str, json_out: str | None, html_out: str | None) -> None:
    from dnp3_monitor.dnp3_analyze import analyze_pcap, save_html, save_json
    data = analyze_pcap(pcap)
    base = Path(pcap).stem
    json_path = json_out or f"reports/dnp3_batch/{base}.json"
    html_path = html_out or f"reports/dnp3_batch/{base}.html"
    save_json(data, json_path)
    save_html(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")


def main() -> None:
    try:
        cli()
    except TargetPolicyError as exc:
        console.print(f"[red]Target policy violation:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
