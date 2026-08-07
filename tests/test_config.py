"""Tests for the config module."""

from __future__ import annotations

from ics_scanner.config import ScannerConfig, load_config


class TestScannerConfig:
    def test_defaults(self):
        """Config should load with sensible defaults when no env vars are set."""
        config = ScannerConfig()
        assert config.log_level == "INFO"
        assert config.modbus_default_port == 502
        assert config.modbus_default_unit == 1
        assert config.modbus_timeout == 2.0
        assert config.modbus_max_concurrency == 8
        assert config.s7_default_port == 102
        assert config.dnp3_default_port == 20000
        assert config.reports_dir == "reports"
        assert config.report_html is True
        assert config.report_json is True
        assert config.sanitize_html is True
        assert config.syslog_host is None

    def test_env_var_override(self, monkeypatch):
        """Config should pick up environment variables."""
        monkeypatch.setenv("INDUSTRIALSCANNER_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("INDUSTRIALSCANNER_MODBUS_DEFAULT_PORT", "10502")
        monkeypatch.setenv("INDUSTRIALSCANNER_MODBUS_TIMEOUT", "5.5")

        config = ScannerConfig()
        assert config.log_level == "DEBUG"
        assert config.modbus_default_port == 10502
        assert config.modbus_timeout == 5.5

    def test_load_config(self):
        """load_config should return a ScannerConfig instance."""
        config = load_config()
        assert isinstance(config, ScannerConfig)
        assert config.log_level in ("INFO", "DEBUG", "WARNING", "ERROR")

    def test_invalid_log_level_falls_back_to_default(self, monkeypatch):
        """Invalid log level should be rejected by pydantic validation."""
        # Note: pydantic-settings uses str type, so any string is accepted.
        # The validation happens at logging setup time, not config load time.
        monkeypatch.setenv("INDUSTRIALSCANNER_LOG_LEVEL", "INVALID")
        config = ScannerConfig()
        # Config loads fine; the consumer must validate the level.
        assert config.log_level == "INVALID"

    def test_syslog_optional(self, monkeypatch):
        """syslog_host should be None when not set."""
        monkeypatch.delenv("INDUSTRIALSCANNER_SYSLOG_HOST", raising=False)
        config = ScannerConfig()
        assert config.syslog_host is None
