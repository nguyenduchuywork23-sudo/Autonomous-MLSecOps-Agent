"""Unit and integration tests for Enterprise-Grade VectorMemoryManager.

Validates all 4 technical checkpoints:
1. Checkpoint 1: Metadata Pre-filtering
2. Checkpoint 2: HNSW Graph parameters
3. Checkpoint 3: Cross-Encoder Re-ranking (FlashRank + Domain Heuristics)
4. Checkpoint 4: Memory Consolidation Engine
"""

import json
import os
import shutil
import tempfile
import pytest

from src.utils.vector_store import VectorMemoryManager


@pytest.fixture
def temp_vdb_dir():
    """Create a clean isolated temporary directory for Vector DB testing."""
    d = tempfile.mkdtemp(prefix="test_chroma_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def vdb(temp_vdb_dir):
    """Initialize VectorMemoryManager in ONNX mode for fast, isolated unit testing."""
    return VectorMemoryManager(
        persist_dir=temp_vdb_dir,
        use_ollama=False,  # Use built-in ONNX embedding for fast offline testing
        min_similarity=0.50,
        top_k=3,
    )


# =============================================================================
# GROUP 1: INITIALIZATION & COLLECTIONS
# =============================================================================

def test_init_onnx_fallback(vdb):
    """Test clean initialization with default ONNX fallback."""
    assert vdb is not None
    assert vdb.patterns_coll is not None
    assert vdb.recon_coll is not None


def test_init_creates_directory(temp_vdb_dir):
    """Test that persistence directory is created automatically."""
    target_path = os.path.join(temp_vdb_dir, "nested", "chroma")
    assert not os.path.exists(target_path)
    vm = VectorMemoryManager(persist_dir=target_path, use_ollama=False)
    assert os.path.exists(target_path)


def test_hnsw_params_configured(vdb):
    """Test that HNSW distance metric is configured properly."""
    meta = vdb.patterns_coll.metadata
    assert meta.get("hnsw:space") == "cosine"
    assert meta.get("hnsw:M") == 32
    assert meta.get("hnsw:construction_ef") == 200
    assert meta.get("hnsw:search_ef") == 100


# =============================================================================
# GROUP 2: STORE ATTACK PATTERNS (CONTEXT-AWARE 3-PART SCHEMA)
# =============================================================================

def test_store_full_3part_pattern(vdb):
    """Test storing a comprehensive 3-part Context-Aware Attack Pattern."""
    pattern = {
        "metadata": {
            "cwe_id": "CWE-89",
            "vuln_category": "Time-based Blind SQLi",
            "tech_stack": ["mysql", "php", "nginx"],
            "waf": "cloudflare",
            "severity": "CRITICAL",
        },
        "context": {
            "entry_point": "GET /item.php?id=1",
            "defense_behavior": "Server blocks UNION/SELECT keywords with HTTP 403",
            "agent_reasoning": "Use comment obfuscation to bypass WAF regex filter",
            "preconditions": "MySQL backend without parameterized queries",
        },
        "successful_vector": {
            "tool_used": "docker_sqlmap_scan",
            "tool_args_key": "--tamper=space2comment --technique=T",
            "raw_payload_example": "1'/**/UNION/**/SELECT/**/SLEEP(5)--",
            "outcome": "Confirmed MySQL >= 5.0.12",
        },
    }

    doc_id = vdb.store_attack_pattern(pattern)
    assert doc_id.startswith("ap::docker_sqlmap_scan::CWE-89::")
    assert vdb.patterns_coll.count() == 1


def test_store_idempotent_upsert(vdb):
    """Test that storing identical pattern updates without creating duplicate records."""
    pattern = {
        "metadata": {"cwe_id": "CWE-79", "tech_stack": ["react"]},
        "context": {
            "entry_point": "POST /comment",
            "defense_behavior": "HTML escaping missing on innerHTML",
            "agent_reasoning": "SVG payload bypasses script tag sanitization",
        },
        "successful_vector": {"tool_used": "docker_xss_scan"},
    }

    id1 = vdb.store_attack_pattern(pattern)
    id2 = vdb.store_attack_pattern(pattern)

    assert id1 == id2
    assert vdb.patterns_coll.count() == 1


def test_store_missing_fields_graceful(vdb):
    """Test resilience when metadata or vector fields are incomplete."""
    pattern = {
        "context": {
            "entry_point": "/search?q=",
            "defense_behavior": "Filter blocks standard script tags",
        }
    }
    doc_id = vdb.store_attack_pattern(pattern)
    assert doc_id != ""
    assert vdb.patterns_coll.count() == 1


def test_store_flat_schema_and_string_vector(vdb):
    """Test storing a pattern with flat schema and string vector (Cold Ingestion / Master Playbook)."""
    pattern = {
        "cwe_id": "CWE-89",
        "entry_point": "http://10.0.0.1/login.php",
        "agent_reasoning": "Tấn công SQLi bypass thành công thông qua chuỗi công cụ tự động",
        "successful_vector": "Full Kill Chain: docker_whatweb -> docker_dirb_scan -> docker_sqlmap_scan",
        "tech_stack": ["apache", "php"],
        "waf": "none",
    }
    doc_id = vdb.store_attack_pattern(pattern)
    assert doc_id != ""
    assert "killchain_playbook" in doc_id or "generic_tool" in doc_id
    assert vdb.patterns_coll.count() == 1

    # Verify that full_pattern_json was created cleanly and deserializable
    results = vdb.recall_attack_patterns("SQLi bypass", min_similarity=0.1)
    assert len(results) == 1
    raw_meta = results[0]["metadata"]
    assert raw_meta.get("cwe_id") == "CWE-89"
    full_json = json.loads(raw_meta["full_pattern_json"])
    assert full_json["context"]["entry_point"] == "http://10.0.0.1/login.php"
    assert "docker_sqlmap_scan" in full_json["successful_vector"]["raw_payload_example"]


def test_store_empty_context_skipped(vdb):
    """Test that empty or meaningless context does not pollute the Vector DB."""
    pattern = {"metadata": {"cwe_id": "CWE-89"}, "context": {}}
    doc_id = vdb.store_attack_pattern(pattern)
    assert doc_id == ""
    assert vdb.patterns_coll.count() == 0


# =============================================================================
# GROUP 3: CHECKPOINT 1 — METADATA PRE-FILTERING
# =============================================================================

def test_recall_filters_by_waf(vdb):
    """Test scalar filtering by WAF environment."""
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89", "waf": "cloudflare"},
        "context": {"entry_point": "/sqli", "defense_behavior": "Cloudflare 403"},
        "successful_vector": {"tool_used": "sqlmap"},
    })
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89", "waf": "aws_waf"},
        "context": {"entry_point": "/sqli", "defense_behavior": "AWS WAF 403"},
        "successful_vector": {"tool_used": "sqlmap"},
    })

    # Query with WAF filter = cloudflare
    results = vdb.recall_attack_patterns(
        query="SQL injection bypass",
        waf="cloudflare",
        top_k=5,
        min_similarity=0.1,
    )
    assert len(results) >= 1
    for r in results:
        assert r["metadata"].get("waf") == "cloudflare"


def test_recall_filters_by_cwe(vdb):
    """Test scalar filtering by CWE ID."""
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89"},
        "context": {"entry_point": "/api", "defense_behavior": "SQL error leak"},
    })
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-79"},
        "context": {"entry_point": "/profile", "defense_behavior": "XSS alert reflection"},
    })

    results = vdb.recall_attack_patterns(
        query="vulnerability",
        cwe_id="CWE-79",
        top_k=5,
        min_similarity=0.1,
    )
    assert len(results) == 1
    assert results[0]["metadata"].get("cwe_id") == "CWE-79"


def test_recall_empty_when_no_match(vdb):
    """Test that query returning no candidates yields empty list."""
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89", "waf": "cloudflare"},
        "context": {"entry_point": "/test", "defense_behavior": "sample defense"},
    })
    results = vdb.recall_attack_patterns(
        query="test",
        cwe_id="CWE-9999",  # Non-existent CWE
        min_similarity=0.1,
    )
    assert results == []


# =============================================================================
# GROUP 4: CHECKPOINT 3 — RE-RANKING (HEURISTIC + FLASHRANK)
# =============================================================================

def test_heuristic_score_computation():
    """Test heuristic metadata calculation logic."""
    target_tech = {"nginx", "php", "mysql"}
    target_waf = "cloudflare"
    target_cwe = "CWE-89"

    # Perfect match candidate
    perfect_meta = {
        "tech_stack": "nginx,php,mysql",
        "waf": "cloudflare",
        "cwe_id": "CWE-89",
    }
    score = VectorMemoryManager._compute_metadata_score(
        perfect_meta, target_tech, target_waf, target_cwe
    )
    assert score == pytest.approx(1.0, 0.05)

    # Mismatch candidate
    mismatch_meta = {
        "tech_stack": "iis,asp.net,mssql",
        "waf": "modsecurity",
        "cwe_id": "CWE-79",
    }
    score_mismatch = VectorMemoryManager._compute_metadata_score(
        mismatch_meta, target_tech, target_waf, target_cwe
    )
    assert score_mismatch < 0.4


def test_rerank_pipeline_ranks_closer_tech_higher(vdb):
    """Test that candidate with closer tech stack receives higher final score."""
    # Pattern A: IIS / ASP.NET
    vdb.store_attack_pattern({
        "metadata": {"tech_stack": ["iis", "asp.net"], "waf": "none", "cwe_id": "CWE-89"},
        "context": {"entry_point": "/default.aspx?id=1", "defense_behavior": "SQL error on MS SQL server"},
    })
    # Pattern B: Nginx / PHP / MySQL
    vdb.store_attack_pattern({
        "metadata": {"tech_stack": ["nginx", "php", "mysql"], "waf": "none", "cwe_id": "CWE-89"},
        "context": {"entry_point": "/index.php?id=1", "defense_behavior": "SQL error on MySQL server"},
    })

    # Query targeting Nginx / PHP / MySQL
    results = vdb.recall_attack_patterns(
        query="SQL injection exploit for MySQL backend",
        tech_stack=["nginx", "php", "mysql"],
        top_k=2,
        min_similarity=0.1,
        enable_rerank=True,
    )

    assert len(results) >= 1
    # Top result should be the Nginx / PHP pattern due to heuristic + cross-encoder boost
    assert "php" in results[0]["metadata"].get("tech_stack", "")


def test_final_score_formula(vdb):
    """Verify combined score calculation formula."""
    candidate = {
        "id": "test_1",
        "document": "SQL injection in PHP endpoint",
        "metadata": {"tech_stack": "php,mysql", "waf": "none", "cwe_id": "CWE-89"},
        "similarity": 0.8,
    }
    reranked = vdb._rerank_results(
        query="SQL injection PHP",
        candidates=[candidate],
        target_tech={"php", "mysql"},
        target_waf="none",
        target_cwe="CWE-89",
    )
    assert len(reranked) == 1
    doc = reranked[0]
    expected_score = (
        (0.5 * doc["cross_encoder_score"])
        + (0.3 * doc["heuristic_score"])
        + (0.2 * doc["similarity"])
    )
    assert doc["final_score"] == pytest.approx(round(expected_score, 4), 0.001)


# =============================================================================
# GROUP 5: CHECKPOINT 4 — MEMORY CONSOLIDATION
# =============================================================================

def test_consolidation_merges_similar(vdb):
    """Test clustering and consolidating 5 similar attack patterns into 1 Master Playbook."""
    for i in range(5):
        vdb.store_attack_pattern({
            "metadata": {
                "cwe_id": "CWE-89",
                "tech_stack": [f"site{i}.com", "mysql", "nginx"],
                "waf": "cloudflare",
            },
            "context": {
                "entry_point": f"/item_{i}.php?id=1",
                "defense_behavior": "Cloudflare WAF blocks basic quotes",
                "agent_reasoning": "Space2comment tamper script bypasses regex",
            },
            "successful_vector": {"tool_used": "docker_sqlmap_scan"},
        })

    assert vdb.patterns_coll.count() == 5

    report = vdb.consolidate_memory(min_cluster_size=5)
    assert report["clusters_found"] == 1
    assert report["records_removed"] == 5
    assert report["master_playbooks_created"] == 1
    assert vdb.patterns_coll.count() == 1

    # Verify Master Playbook record
    master_records = vdb.patterns_coll.get()
    meta = master_records["metadatas"][0]
    assert meta.get("is_master_playbook") is True
    assert meta.get("consolidated_count") == 5


def test_consolidation_preserves_unique(vdb):
    """Test that unique or below-threshold patterns are not removed."""
    # Add 2 SQLi patterns (below min_cluster_size=5) and 1 XSS pattern
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89"},
        "context": {"entry_point": "/sqli1", "defense_behavior": "403"},
    })
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-89"},
        "context": {"entry_point": "/sqli2", "defense_behavior": "403"},
    })
    vdb.store_attack_pattern({
        "metadata": {"cwe_id": "CWE-79"},
        "context": {"entry_point": "/xss", "defense_behavior": "reflection"},
    })

    report = vdb.consolidate_memory(min_cluster_size=5)
    assert report["clusters_found"] == 0
    assert report["records_removed"] == 0
    assert vdb.patterns_coll.count() == 3


# =============================================================================
# GROUP 6: TARGET RECON MEMORY
# =============================================================================

def test_store_and_recall_recon(vdb):
    """Test reconnaissance intelligence storage and recall."""
    doc_id = vdb.store_target_recon(
        target="10.0.0.5",
        port=80,
        service="http",
        summary="Apache 2.4.49 with mod_cgi enabled; open ports: 80, 22",
        metadata={"technologies": ["apache", "php"], "tool": "docker_whatweb"},
    )
    assert doc_id != ""
    assert vdb.recon_coll.count() == 1

    recalled = vdb.recall_target_recon("Apache mod_cgi path traversal", target="10.0.0.5")
    assert len(recalled) == 1
    assert "Apache 2.4.49" in recalled[0]["document"]


def test_store_recon_ignores_blank_summary(vdb):
    """Test that empty or default summaries are not stored."""
    id1 = vdb.store_target_recon("10.0.0.5", 80, "http", "")
    id2 = vdb.store_target_recon("10.0.0.5", 80, "http", "Không có dấu hiệu đặc biệt.")
    assert id1 == ""
    assert id2 == ""
    assert vdb.recon_coll.count() == 0


# =============================================================================
# GROUP 7: PROMPT FORMATTING & STATS
# =============================================================================

def test_format_past_experience_block(vdb):
    """Test formatting retrieved patterns into Past Experience prompt block."""
    pattern = {
        "metadata": {"cwe_id": "CWE-89", "tool_used": "docker_sqlmap_scan"},
        "context": {
            "entry_point": "/item.php?id=1",
            "defense_behavior": "Server blocks UNION",
            "agent_reasoning": "Use comment obfuscation",
        },
        "successful_vector": {
            "tool_used": "docker_sqlmap_scan",
            "tool_args_key": "--tamper=space2comment",
            "raw_payload_example": "1'/**/UNION/**/SELECT",
            "outcome": "Extracted DB version",
        },
    }
    vdb.store_attack_pattern(pattern)

    recalled = vdb.recall_attack_patterns("SQL injection bypass", min_similarity=0.1)
    prompt_block = vdb.format_past_experience_block(recalled)

    assert "=== BỘ NHỚ CHIẾN THUẬT QUÁ KHỨ" in prompt_block
    assert "CWE-89" in prompt_block
    assert "--tamper=space2comment" in prompt_block
    assert "CHỈ ĐẠO HÀNH ĐỘNG" in prompt_block


def test_format_past_experience_block_with_string_vector(vdb):
    """Test formatting retrieved patterns when successful_vector is a string."""
    vdb.store_attack_pattern({
        "cwe_id": "CWE-22",
        "entry_point": "GET /download?file=../../etc/passwd",
        "agent_reasoning": "Path traversal confirmed",
        "successful_vector": "Full Kill Chain: docker_nikto_scan -> manual curl probe",
    })

    recalled = vdb.recall_attack_patterns("path traversal", min_similarity=0.1)
    assert len(recalled) == 1
    prompt_block = vdb.format_past_experience_block(recalled)

    assert "=== BỘ NHỚ CHIẾN THUẬT QUÁ KHỨ" in prompt_block
    assert "CWE-22" in prompt_block
    assert "GET /download?file=../../etc/passwd" in prompt_block
    assert "Full Kill Chain" in prompt_block
    assert "CHỈ ĐẠO HÀNH ĐỘNG" in prompt_block


def test_format_respects_token_limit(vdb):
    """Test that formatting caps text when max_tokens budget is reached."""
    # Store 3 patterns
    for i in range(3):
        vdb.store_attack_pattern({
            "metadata": {"cwe_id": f"CWE-8{i}"},
            "context": {
                "entry_point": f"/long/url/endpoint/{i}" * 10,
                "defense_behavior": "Defense behavior description " * 10,
                "agent_reasoning": "Strategic reasoning detailed analysis " * 10,
            },
        })

    recalled = vdb.recall_attack_patterns("test", min_similarity=0.1, top_k=3)
    # Budget of 50 tokens ~ 200 characters
    block = vdb.format_past_experience_block(recalled, max_tokens=50)
    assert len(block) < 600


def test_get_memory_stats(vdb):
    """Test memory stats reporting counts."""
    stats = vdb.get_memory_stats()
    assert stats["attack_patterns"] == 0
    assert stats["target_recon"] == 0

    vdb.store_attack_pattern({
        "context": {"entry_point": "/a", "defense_behavior": "b"}
    })
    vdb.store_target_recon("target.com", 443, "https", "Summary info")

    stats = vdb.get_memory_stats()
    assert stats["attack_patterns"] == 1
    assert stats["target_recon"] == 1


def test_full_store_recall_rerank_cycle(vdb):
    """End-to-end integration test: store, filter, recall, re-rank, and format."""
    # 1. Store pattern
    vdb.store_attack_pattern({
        "metadata": {
            "cwe_id": "CWE-89",
            "tech_stack": ["wordpress", "mysql", "nginx"],
            "waf": "cloudflare",
            "severity": "CRITICAL",
        },
        "context": {
            "entry_point": "/wp-admin/admin-ajax.php?action=query",
            "defense_behavior": "Cloudflare WAF intercepts raw SQL syntax",
            "agent_reasoning": "Deploy sqlmap tamper space2comment with time-based delay",
        },
        "successful_vector": {
            "tool_used": "docker_sqlmap_scan",
            "tool_args_key": "--tamper=space2comment",
            "outcome": "DB admin hash dumped",
        },
    })

    # 2. Recall with matching environment
    patterns = vdb.recall_attack_patterns(
        query="Cloudflare WAF SQL injection on WordPress",
        tech_stack=["wordpress", "mysql"],
        waf="cloudflare",
        cwe_id="CWE-89",
        min_similarity=0.1,
        enable_rerank=True,
    )
    assert len(patterns) == 1
    assert patterns[0]["metadata"]["cwe_id"] == "CWE-89"

    # 3. Format prompt block
    block = vdb.format_past_experience_block(patterns)
    assert "/wp-admin/admin-ajax.php" in block


# =============================================================================
# GROUP 8: EMBEDDING CACHE & PERFORMANCE
# =============================================================================

def test_cached_embedding_function_hits_and_misses():
    """Test that CachedEmbeddingFunction avoids re-computation and tracks stats."""
    from src.utils.vector_store import CachedEmbeddingFunction

    call_count = 0

    def mock_ef(texts: list[str]) -> list[list[float]]:
        nonlocal call_count
        call_count += 1
        return [[float(len(t))] * 4 for t in texts]

    cached_ef = CachedEmbeddingFunction(base_ef=mock_ef, max_size=10)

    # First call - all misses
    res1 = cached_ef(["hello", "world"])
    assert len(res1) == 2
    assert call_count == 1
    assert cached_ef.misses == 2
    assert cached_ef.hits == 0

    # Second call with same inputs - 100% hits
    res2 = cached_ef(["hello", "world"])
    assert len(res1) == len(res2)
    for r1, r2 in zip(res1, res2):
        assert list(r1) == list(r2)
    assert call_count == 1  # mock_ef was NOT called!
    assert cached_ef.misses == 2
    assert cached_ef.hits == 2

    # Mixed call - 1 hit, 1 miss
    res3 = cached_ef(["world", "new_term"])
    assert len(res3) == 2
    assert call_count == 2
    assert cached_ef.hits == 3
    assert cached_ef.misses == 3


def test_cached_embedding_function_eviction():
    """Test FIFO/LRU eviction when exceeding max_size."""
    from src.utils.vector_store import CachedEmbeddingFunction

    def mock_ef(texts: list[str]) -> list[list[float]]:
        return [[float(len(t))] * 2 for t in texts]

    cached_ef = CachedEmbeddingFunction(base_ef=mock_ef, max_size=64)
    cached_ef.max_size = 3  # explicitly set to 3 for eviction unit test

    cached_ef(["a", "b", "c"])
    assert len(cached_ef._cache) == 3

    # Add 4th item -> "a" evicted
    cached_ef(["d"])
    assert len(cached_ef._cache) == 3
    assert "a" not in cached_ef._cache
    assert "d" in cached_ef._cache


def test_cached_embedding_clear_and_stats():
    """Test clearing cache and reporting statistics."""
    from src.utils.vector_store import CachedEmbeddingFunction

    def mock_ef(texts: list[str]) -> list[list[float]]:
        return [[1.0, 2.0] for _ in texts]

    cached_ef = CachedEmbeddingFunction(base_ef=mock_ef, max_size=100)
    cached_ef(["item1", "item2"])
    stats = cached_ef.get_stats()
    assert stats["size"] == 2
    assert stats["misses"] == 2
    assert stats["hits"] == 0

    cached_ef.clear()
    stats_cleared = cached_ef.get_stats()
    assert stats_cleared["size"] == 0
    assert stats_cleared["hits"] == 0
    assert stats_cleared["misses"] == 0


def test_vector_memory_manager_embedding_cache_stats(vdb):
    """Test VectorMemoryManager's cache stats integration."""
    stats = vdb.get_embedding_cache_stats()
    assert isinstance(stats, dict)
    assert "size" in stats
    assert "hits" in stats
    assert "misses" in stats

    vdb.clear_embedding_cache()
    cleared = vdb.get_embedding_cache_stats()
    assert cleared["size"] == 0
