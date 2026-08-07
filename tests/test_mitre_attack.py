"""Tests for MITRE ATT&CK for ICS mapping."""

from __future__ import annotations

from ics_scanner.mitre_attack import (
    TECHNIQUE_CATALOG,
    enrich_report_with_attack,
    map_function_to_techniques,
)


class TestMapFunctionToTechniques:
    def test_modbus_read_returns_discovery(self):
        techs = map_function_to_techniques("modbus", "ReadCoils")
        tech_ids = [t.technique_id for t in techs]
        assert "T0801" in tech_ids  # Monitor Process State
        assert "T0802" in tech_ids  # Automated Discovery

    def test_s7comm_writevar_returns_execution(self):
        techs = map_function_to_techniques("s7comm", "WriteVar")
        tech_ids = [t.technique_id for t in techs]
        assert "T0848" in tech_ids  # Modify Program

    def test_s7comm_start_returns_change_mode(self):
        techs = map_function_to_techniques("s7comm", "Start")
        tech_ids = [t.technique_id for t in techs]
        assert "T0858" in tech_ids  # Change Operating Mode

    def test_s7comm_firmware_update_multiple_tactics(self):
        techs = map_function_to_techniques("s7comm", "FirmwareUpdate")
        tech_ids = {t.technique_id for t in techs}
        assert "T0858" in tech_ids
        assert "T0885" in tech_ids
        assert "T0879" in tech_ids

    def test_dnp3_operate_returns_impact(self):
        techs = map_function_to_techniques("dnp3", "Operate")
        tech_ids = [t.technique_id for t in techs]
        assert "T0858" in tech_ids
        assert "T0894" in tech_ids

    def test_unknown_function_returns_empty(self):
        assert map_function_to_techniques("modbus", "UnknownFunc") == []

    def test_unknown_protocol_returns_empty(self):
        assert map_function_to_techniques("profinet", "ReadVar") == []


class TestEnrichReportWithAttack:
    def test_s7comm_report_enriched(self):
        report = {
            "results": [
                {"function_code": "WriteVar", "src": "1.1.1.1", "dst": "2.2.2.2"},
                {"function_code": "ReadVar", "src": "1.1.1.1", "dst": "2.2.2.2"},
            ]
        }
        enriched = enrich_report_with_attack(report, "s7comm")
        assert "mitre_attack" in enriched["results"][0]
        assert len(enriched["results"][0]["mitre_attack"]) > 0
        assert "T0848" in [t["technique_id"] for t in enriched["results"][0]["mitre_attack"]]

    def test_dnp3_report_enriched(self):
        report = {
            "results": [
                {"function": "Operate", "src": "1.1.1.1", "dst": "2.2.2.2"},
            ]
        }
        enriched = enrich_report_with_attack(report, "dnp3")
        assert "mitre_attack" in enriched["results"][0]
        assert len(enriched["results"][0]["mitre_attack"]) > 0

    def test_empty_results_handled(self):
        report = {"results": []}
        enriched = enrich_report_with_attack(report, "s7comm")
        assert enriched["results"] == []


class TestTechniqueCatalog:
    def test_catalog_has_known_techniques(self):
        assert "T0801" in TECHNIQUE_CATALOG
        assert "T0858" in TECHNIQUE_CATALOG
        assert "T0859" in TECHNIQUE_CATALOG

    def test_technique_has_url(self):
        t = TECHNIQUE_CATALOG["T0801"]
        assert t.url.startswith("https://attack.mitre.org/techniques/")
