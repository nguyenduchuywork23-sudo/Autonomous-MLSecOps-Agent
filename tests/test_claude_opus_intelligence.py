"""
Unit Tests for Claude Opus-Tier Cognitive Intelligence Architecture
===================================================================
Tests for:
1. SecretExtractor (Semantic De-obfuscation & Shannon Entropy Secrets)
2. ExploitChainingEngine (Multi-Hop Attack Chaining & Lateral Movement)
3. PayloadMutator (Genetic Payload Mutations & Evasion Synthesizer)
4. CognitiveCouncil (Multi-Persona Deliberative Strategic Council)
"""

import pytest
from src.utils.secret_extractor import SecretExtractor, calculate_shannon_entropy
from src.utils.exploit_chaining import ExploitChainingEngine
from src.utils.payload_mutator import PayloadMutator
from src.utils.cognitive_council import CognitiveCouncil, CouncilDeliberation
from src.utils.tree_of_thought import TreeOfThoughtEngine
from src.client.report_state import ReportState, Finding


class TestSecretExtractor:
    """Tests for deep signal extraction and entropy analysis."""

    def test_shannon_entropy(self):
        # Repetitive string has low entropy
        low_ent = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
        assert low_ent == 0.0

        # Highly random alphanumeric string has high entropy (> 4.0)
        high_ent = calculate_shannon_entropy("qW8#mP$9vL!2zX@7cR&4kY*1tN%6bV^3")
        assert high_ent > 4.2

    def test_extract_aws_and_jwt(self):
        sample_text = (
            "Configuration dump: aws_key=AKIAIOSFODNN7EXAMPLE\n"
            "Auth header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        intel = SecretExtractor.extract(sample_text)
        assert "AKIAIOSFODNN7EXAMPLE" in intel.api_keys
        assert len(intel.jwt_tokens) == 1
        assert intel.has_secrets is True

    def test_extract_database_credentials(self):
        sample_text = "DATABASE_URL=postgres://db_admin:SuperSecretPass123!@10.0.1.5:5432/production_db"
        intel = SecretExtractor.extract(sample_text)
        assert len(intel.credentials) >= 1
        cred = intel.credentials[0]
        assert cred["user"] == "db_admin"
        assert cred["password"] == "SuperSecretPass123!"
        assert "10.0.1.5" in intel.internal_ips

    def test_extract_internal_ips_and_domains(self):
        sample_text = "Connected to cluster: 192.168.1.100 and internal gateway auth-service.internal"
        intel = SecretExtractor.extract(sample_text)
        assert "192.168.1.100" in intel.internal_ips
        assert "auth-service.internal" in intel.internal_hostnames

    def test_extract_dev_comments_and_hidden_endpoints(self):
        sample_text = (
            "<html>\n"
            "<!-- TODO: remove admin test credentials before release -->\n"
            "<script src=\"/static/app.js\"></script>\n"
            "const url = '/api/v2/users/export';\n"
            "</html>"
        )
        intel = SecretExtractor.extract(sample_text)
        assert any("TODO" in c for c in intel.developer_comments)
        assert "/api/v2/users/export" in intel.hidden_endpoints


class TestExploitChainingEngine:
    """Tests for multi-hop attack chaining and lateral movement."""

    def test_ingest_intelligence_spawns_tot_nodes(self):
        engine = ExploitChainingEngine()
        tot = TreeOfThoughtEngine(target="http://example.com")

        intel = SecretExtractor.extract(
            "Found database config: mysql://root:P@ssw0rd999!@10.0.0.8:3306/app\n"
            "JWT: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123xyz456"
        )
        new_nodes = engine.ingest_intelligence(intel, tot_engine=tot, base_target="http://example.com")

        assert len(new_nodes) >= 2
        # Check that auth node and token node exist in ToT
        node_ids = [n.node_id for n in new_nodes]
        assert any("AUTH" in nid for nid in node_ids)
        assert any("API-TOKEN" in nid for nid in node_ids)
        assert any("SSRF" in nid for nid in node_ids)

        # Nodes must be added to TreeOfThoughtEngine
        for n in new_nodes:
            assert n.node_id in tot.nodes

    def test_enrich_tool_arguments_credentials(self):
        engine = ExploitChainingEngine()
        intel = SecretExtractor.extract("password=HarvestedSecret99!")
        engine.ingest_intelligence(intel)

        # Call with bruteforce_ssh
        initial_args = {"target": "192.168.1.50"}
        enriched = engine.enrich_tool_arguments("docker_bruteforce_ssh", initial_args)

        assert enriched["password"] == "HarvestedSecret99!"

    def test_enrich_tool_arguments_jwt_bearer(self):
        engine = ExploitChainingEngine()
        intel = SecretExtractor.extract("Token: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.token123")
        engine.ingest_intelligence(intel)

        initial_args = {"target_url": "http://example.com/api/docs"}
        enriched = engine.enrich_tool_arguments("docker_api_docs_audit", initial_args)

        assert "Authorization" in enriched["headers"]
        assert "Bearer eyJhbGciOiJIUzI1NiJ9" in enriched["headers"]

    def test_format_chain_block(self):
        engine = ExploitChainingEngine()
        intel = SecretExtractor.extract("password=SecretPass123! at 10.0.0.1")
        engine.ingest_intelligence(intel)

        block = engine.format_chain_block()
        assert "CHUỖI KHAI THÁC ĐA TẦNG" in block
        assert "SecretPass123!" in block
        assert "10.0.0.1" in block


class TestPayloadMutator:
    """Tests for genetic payload mutations and WAF bypass synthesis."""

    def test_sqli_mutations(self):
        base = "' UNION SELECT 1,2,3--"
        muts = PayloadMutator.mutate_sqli(base, dialect="mysql")

        assert any("/**/" in m for m in muts)  # comment injection
        assert any("%25" in m for m in muts)  # double encoding

    def test_sqli_time_based_substitutions(self):
        base = "' AND SLEEP(5)--"
        mysql_muts = PayloadMutator.mutate_sqli(base, dialect="mysql")
        assert any("benchmark" in m.lower() for m in mysql_muts)

        pg_muts = PayloadMutator.mutate_sqli(base, dialect="postgres")
        assert any("pg_sleep" in m.lower() for m in pg_muts)

    def test_quote_less_conversion(self):
        base = "SELECT * FROM users WHERE name = 'admin'"
        muts = PayloadMutator.mutate_sqli(base, dialect="mysql")
        # 'admin' -> CHAR(97,100,109,105,110)
        assert any("CHAR(" in m for m in muts)

    def test_xss_mutations(self):
        base = "<script>alert(1)</script>"
        muts = PayloadMutator.mutate_xss(base)
        assert any("<sCrIpt>" in m for m in muts)
        assert any("onerror" in m for m in muts)

    def test_path_traversal_mutations(self):
        base = "../../etc/passwd"
        muts = PayloadMutator.mutate_path_traversal(base)
        assert any("%2e%2e%2f" in m for m in muts)
        assert any("%00" in m for m in muts)

    def test_format_mutations_block(self):
        block = PayloadMutator.format_mutations_block("sqli", "' OR 1=1--")
        assert "BỘ ĐỘT BIẾN GEN PAYLOAD" in block
        assert "SQLI" in block


class TestCognitiveCouncil:
    """Tests for multi-persona strategic council deliberation."""

    def test_council_deliberation_with_harvested_credentials(self):
        rs = ReportState(target="http://example.com")
        delib = CognitiveCouncil.deliberate(
            report_state=rs,
            active_vector_title="Network Auth",
            detected_waf="",
            harvested_creds_count=2,
            harvested_tokens_count=1,
            iteration=3,
        )

        assert "xác thực" in delib.offensive_view.lower()
        assert delib.priority_tool == "docker_bruteforce_ssh"
        assert delib.confidence >= 0.95
        assert "HÀNH ĐỘNG KHẨN CẤP" in delib.executive_directive

    def test_council_deliberation_with_waf(self):
        rs = ReportState(target="http://example.com")
        delib = CognitiveCouncil.deliberate(
            report_state=rs,
            active_vector_title="Web Fuzzing",
            detected_waf="cloudflare",
            harvested_creds_count=0,
            harvested_tokens_count=0,
            iteration=2,
        )

        assert "cloudflare" in delib.opsec_view.lower()
        assert "ẨN MÌNH" in delib.executive_directive

    def test_format_block(self):
        rs = ReportState(target="http://example.com")
        delib = CognitiveCouncil.deliberate(report_state=rs)
        block = delib.format_block()

        assert "HỘI ĐỒNG CHIẾN LƯỢC TỐI CAO" in block
        assert "Offensive Architect" in block
        assert "Cryptographer" in block
        assert "OpSec Director" in block
        assert "EXECUTIVE DIRECTIVE" in block
