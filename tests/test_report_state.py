"""Tests for ReportState — the shared memory between Red Teamer and Reporter."""

import pytest
from src.client.report_state import ReportState, Finding, ToolStep


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_severity_normalization(self):
        """Severity should be normalized to uppercase."""
        f = Finding(
            title="Test", severity="high", description="desc",
            impact="imp", remediation="rem", tool_source="nmap",
            raw_evidence="raw",
        )
        assert f.severity == "HIGH"

    def test_invalid_severity_defaults_to_info(self):
        """Invalid severity should default to INFO."""
        f = Finding(
            title="Test", severity="banana", description="desc",
            impact="imp", remediation="rem", tool_source="nmap",
            raw_evidence="raw",
        )
        assert f.severity == "INFO"

    def test_valid_severities(self):
        """All valid severities should be accepted."""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f = Finding(
                title="Test", severity=sev, description="d",
                impact="i", remediation="r", tool_source="t",
                raw_evidence="e",
            )
            assert f.severity == sev


class TestReportState:
    """Tests for the ReportState class."""

    def setup_method(self):
        """Create a fresh ReportState for each test."""
        self.state = ReportState(target="http://example.com", scan_mode="recon")

    def test_initial_state(self):
        """Initial state should have empty findings and 0 risk."""
        assert len(self.state.findings) == 0
        assert self.state.risk_score == 0.0
        assert self.state.target == "http://example.com"
        assert self.state.scan_mode == "recon"

    def test_add_finding(self):
        """Adding a finding should increase count."""
        finding = Finding(
            title="XSS Found", severity="HIGH", description="Reflected XSS",
            impact="Account takeover", remediation="Sanitize input",
            tool_source="nuclei", raw_evidence="<script>alert(1)</script>",
        )
        self.state.add_finding(finding)
        assert len(self.state.findings) == 1
        assert self.state.findings[0].title == "XSS Found"

    def test_add_finding_dedup(self):
        """Duplicate findings (by title) should be rejected."""
        f1 = Finding(
            title="SQL Injection", severity="CRITICAL", description="d1",
            impact="i", remediation="r", tool_source="sqlmap", raw_evidence="e",
        )
        f2 = Finding(
            title="SQL Injection", severity="HIGH", description="d2",
            impact="i", remediation="r", tool_source="nuclei", raw_evidence="e",
        )
        self.state.add_finding(f1)
        self.state.add_finding(f2)
        assert len(self.state.findings) == 1  # Second one rejected

    def test_add_step(self):
        """Adding a tool step should be recorded."""
        step = ToolStep(
            step_number=1, tool_name="docker_scan_ports_fast",
            arguments={"target": "example.com"}, result_snippet="22,80,443",
            status="SUCCESS",
        )
        self.state.add_step(step)
        assert len(self.state.methodology) == 1
        assert self.state.methodology[0].tool_name == "docker_scan_ports_fast"

    def test_risk_score_only_increases(self):
        """Risk score should only increase, never decrease."""
        self.state.update_risk_score(5.0)
        assert self.state.risk_score == 5.0

        self.state.update_risk_score(3.0)
        assert self.state.risk_score == 5.0  # Should NOT decrease

        self.state.update_risk_score(8.0)
        assert self.state.risk_score == 8.0

    def test_risk_score_capped_at_10(self):
        """Risk score should be capped at 10."""
        self.state.update_risk_score(15.0)
        assert self.state.risk_score == 10.0

    def test_add_recommendation_dedup(self):
        """Duplicate recommendations should be rejected."""
        self.state.add_recommendation("Upgrade Apache")
        self.state.add_recommendation("Upgrade Apache")
        self.state.add_recommendation("Enable WAF")
        assert len(self.state.recommendations) == 2

    def test_severity_counts(self):
        """Severity counts should be accurate."""
        for sev in ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW", "INFO", "INFO"]:
            self.state.add_finding(Finding(
                title=f"Finding {sev} {len(self.state.findings)}",
                severity=sev, description="d", impact="i",
                remediation="r", tool_source="t", raw_evidence="e",
            ))
        counts = self.state.get_severity_counts()
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 1
        assert counts["INFO"] == 2

    def test_overall_risk_label(self):
        """Risk label should be based on highest severity finding."""
        assert self.state.get_overall_risk_label() == "INFO"

        self.state.add_finding(Finding(
            title="Low Finding", severity="LOW", description="d",
            impact="i", remediation="r", tool_source="t", raw_evidence="e",
        ))
        assert self.state.get_overall_risk_label() == "LOW"

        self.state.add_finding(Finding(
            title="Critical Finding", severity="CRITICAL", description="d",
            impact="i", remediation="r", tool_source="t", raw_evidence="e",
        ))
        assert self.state.get_overall_risk_label() == "CRITICAL"

    def test_to_dict(self):
        """to_dict should contain all required keys."""
        self.state.finalize(red_teamer_answer="Done.")
        d = self.state.to_dict()
        required_keys = [
            "target", "scan_mode", "start_time", "end_time",
            "executive_summary", "findings", "methodology",
            "risk_score", "risk_label", "severity_counts",
            "recommendations", "conclusion",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"

    def test_get_current_summary(self):
        """Summary should include target and risk info."""
        summary = self.state.get_current_summary()
        assert "example.com" in summary
        assert "Risk Score" in summary

    def test_get_reporter_feedback_block(self):
        """Feedback block should contain risk score."""
        block = self.state.get_reporter_feedback_block(
            latest_suggestion="Scan port 3306",
            latest_comment="3 ports found",
        )
        assert "SOC ANALYST" in block
        assert "Scan port 3306" in block

    def test_finalize(self):
        """Finalize should set end_time and red_teamer_answer."""
        self.state.finalize(red_teamer_answer="Final answer here.")
        assert self.state.end_time is not None
        assert self.state.red_teamer_final_answer == "Final answer here."

    def test_to_json(self):
        """to_json should produce valid JSON string."""
        import json
        self.state.finalize()
        json_str = self.state.to_json()
        parsed = json.loads(json_str)
        assert parsed["target"] == "http://example.com"

    def test_calculate_baseline_risk(self):
        """Baseline risk should calculate correctly based on findings."""
        assert self.state.calculate_baseline_risk() == 0.0

        # Adding a LOW finding -> base 2.0
        self.state.add_finding(Finding(
            title="Low finding", severity="LOW", description="d",
            impact="i", remediation="r", tool_source="t", raw_evidence="e",
        ))
        assert self.state.calculate_baseline_risk() >= 2.0
        assert self.state.risk_score >= 2.0

        # Adding a CRITICAL finding -> base 9.0+
        self.state.add_finding(Finding(
            title="Critical RCE", severity="CRITICAL", description="d",
            impact="i", remediation="r", tool_source="t", raw_evidence="e",
        ))
        assert self.state.calculate_baseline_risk() >= 9.0
        assert self.state.risk_score >= 9.0

    def test_add_finding_upgrades_severity(self):
        """Adding same title with higher severity should upgrade existing finding."""
        f_medium = Finding(
            title="Apache Vuln", severity="MEDIUM", description="d1",
            impact="i1", remediation="r1", tool_source="nmap", raw_evidence="e1",
        )
        self.state.add_finding(f_medium)
        assert self.state.findings[0].severity == "MEDIUM"

        # Now report same title as CRITICAL (from nuclei)
        f_critical = Finding(
            title="Apache Vuln", severity="CRITICAL", description="d2",
            impact="i2", remediation="r2", tool_source="nuclei", raw_evidence="e2",
        )
        self.state.add_finding(f_critical)
        assert len(self.state.findings) == 1
        assert self.state.findings[0].severity == "CRITICAL"
        assert self.state.findings[0].tool_source == "nuclei"

    def test_findings_by_severity(self):
        """findings_by_severity should filter findings correctly and case-insensitively."""
        f_crit = Finding(title="Crit 1", severity="CRITICAL", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")
        f_high = Finding(title="High 1", severity="HIGH", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")
        f_low = Finding(title="Low 1", severity="LOW", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")

        self.state.add_finding(f_crit)
        self.state.add_finding(f_high)
        self.state.add_finding(f_low)

        crits = self.state.findings_by_severity("critical")
        assert len(crits) == 1
        assert crits[0].title == "Crit 1"

        highs = self.state.findings_by_severity("HIGH")
        assert len(highs) == 1
        assert highs[0].title == "High 1"

        mediums = self.state.findings_by_severity("MEDIUM")
        assert len(mediums) == 0

    def test_get_findings_sorted(self):
        """get_findings_sorted should return findings in descending severity order."""
        f_low = Finding(title="Low 1", severity="LOW", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")
        f_crit = Finding(title="Crit 1", severity="CRITICAL", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")
        f_med = Finding(title="Med 1", severity="MEDIUM", description="d", impact="i", remediation="r", tool_source="t", raw_evidence="e")

        self.state.add_finding(f_low)
        self.state.add_finding(f_crit)
        self.state.add_finding(f_med)

        sorted_findings = self.state.get_findings_sorted()
        assert [f.severity for f in sorted_findings] == ["CRITICAL", "MEDIUM", "LOW"]

    def test_record_rag_applied_and_stored_patterns(self):
        """Should record applied and stored RAG patterns without duplicates."""
        patterns = [
            {"id": "ap1", "cwe_id": "CWE-89", "successful_vector": "sqlmap -u ...", "similarity_score": 0.92},
            {"id": "ap2", "cwe_id": "CWE-79", "successful_vector": "xss test", "similarity_score": 0.88},
        ]
        self.state.record_rag_applied_patterns(patterns)
        assert len(self.state.rag_applied_patterns) == 2
        # Duplicate should be ignored
        self.state.record_rag_applied_patterns([patterns[0]])
        assert len(self.state.rag_applied_patterns) == 2

        new_pattern = {"cwe_id": "CWE-22", "entry_point": "/download", "successful_vector": "curl ../.."}
        self.state.record_rag_stored_pattern(new_pattern, stored_id="ap_stored_1")
        assert len(self.state.rag_stored_patterns) == 1
        assert self.state.rag_stored_patterns[0]["id"] == "ap_stored_1"
        assert "timestamp" in self.state.rag_stored_patterns[0]

        # Check export in to_dict
        d = self.state.to_dict()
        assert "rag_applied_patterns" in d
        assert "rag_stored_patterns" in d
        assert len(d["rag_applied_patterns"]) == 2
        assert len(d["rag_stored_patterns"]) == 1

        # Check export in to_markdown
        md = self.state.to_markdown()
        assert "## 9. TRÍ NHỚ CHIẾN THUẬT DÀI HẠN & KỊCH BẢN TỰ HỌC" in md
        assert "CWE-89" in md
        assert "CWE-22" in md
        assert "## 10. KẾT LUẬN & KIỂM TOÁN" in md

    def test_service_discovery_and_tactical_queue(self):
        """Should register discovered services and enqueue tactical attack actions."""
        self.state.register_discovered_service(21, "ftp", host="ftp.test.com")
        self.state.register_discovered_service(3306, "mysql", host="db.test.com")

        assert 21 in self.state.discovered_services
        assert 3306 in self.state.discovered_services
        assert len(self.state.tactical_action_queue) > 0

        # Verify summary contains queued tools
        summary = self.state.get_tactical_queue_summary()
        assert "Hàng đợi tác chiến chuyên sâu" in summary
        assert "docker_bruteforce" in summary

        # Pop next tactical action
        next_action = self.state.get_next_tactical_action()
        assert next_action is not None
        assert "tool" in next_action
        assert "port" in next_action

    def test_checkpoint_save_and_load(self, tmp_path):
        """Should save and load complete ReportState checkpoint."""
        self.state.session_id = "test_sess_001"
        self.state.add_finding(Finding(
            title="SQL Injection Checkpoint Test",
            severity="CRITICAL",
            description="Found SQLi",
            impact="Data leak",
            remediation="Parameterized queries",
            tool_source="docker_sqlmap_scan",
            raw_evidence="SELECT * FROM users",
        ))
        self.state.register_discovered_service(8080, "http-proxy")
        self.state.attack_surface.open_ports[8080] = {"service": "http-proxy"}

        checkpoint_file = str(tmp_path / "test_session.json")
        self.state.save_checkpoint(checkpoint_file)

        # Load checkpoint
        loaded = ReportState.load_checkpoint(checkpoint_file)
        assert loaded.session_id == "test_sess_001"
        assert loaded.target == self.state.target
        assert len(loaded.findings) == 1
        assert loaded.findings[0].title == "SQL Injection Checkpoint Test"
        assert loaded.findings[0].severity == "CRITICAL"
        assert 8080 in loaded.discovered_services
        assert 8080 in loaded.attack_surface.open_ports
        assert len(loaded.tactical_action_queue) > 0



