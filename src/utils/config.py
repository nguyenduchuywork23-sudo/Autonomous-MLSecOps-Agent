"""Centralized Configuration Loader for MLSecOps Agent v4.0.

Reads settings from config.yaml with environment variable overrides.
Environment variables use the prefix MLSEC_ and underscore-separated paths.
Example: MLSEC_LLM_MODEL overrides llm.model in config.yaml.
"""

import os
import pathlib
import threading
from typing import Any

import yaml

# Project root: two levels up from this file (src/utils/config.py → project root)
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = pathlib.Path(os.environ.get("MLSEC_CONFIG_PATH", str(PROJECT_ROOT / "config.yaml")))


_ENV_PREFIX = "MLSEC_"

# Cached singleton & fast-path lookup cache
_config: dict | None = None
_get_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _apply_env_overrides(cfg: dict, prefix: str = _ENV_PREFIX) -> dict:
    """Override config values with environment variables.

    Env var naming: MLSEC_<SECTION>_<KEY> → cfg[section][key]
    Examples:
        MLSEC_LLM_MODEL=gemma2:9b            → cfg['llm']['model']
        MLSEC_AGENT_MAX_ITERATIONS=30        → cfg['agent']['max_iterations']
        MLSEC_TIMEOUTS_FAST_SCAN=60          → cfg['timeouts']['fast_scan']
        MLSEC_REPORTS_COMPANY_NAME="Acme"    → cfg['reports']['company_name']
    """
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        key_raw = env_key[len(prefix):].lower()
        if not key_raw:
            continue

        # Find which top-level section matches the prefix of key_raw
        matched_section = None
        for section in cfg.keys():
            if key_raw.startswith(section.lower() + "_"):
                matched_section = section
                break

        if matched_section and isinstance(cfg[matched_section], dict):
            sub_key = key_raw[len(matched_section) + 1:]
            # Match sub_key against existing keys in that section case-insensitively
            target_key = sub_key
            for existing_key in cfg[matched_section].keys():
                if existing_key.lower() == sub_key:
                    target_key = existing_key
                    break
            cfg[matched_section][target_key] = _coerce_type(env_val, cfg[matched_section].get(target_key))
        else:
            # Fallback for 1-level or generic keys
            cfg[key_raw] = _coerce_type(env_val, cfg.get(key_raw))
    return cfg


def _coerce_type(value: str, existing: Any) -> Any:
    """Coerce string env var value to match existing config type."""
    if existing is None:
        return value
    if isinstance(existing, bool):
        return value.lower() in ("true", "1", "yes")
    if isinstance(existing, int):
        try:
            return int(value)
        except ValueError:
            return value
    if isinstance(existing, float):
        try:
            return float(value)
        except ValueError:
            return value
    if isinstance(existing, list):
        return [v.strip() for v in value.split(",")]
    return value


def load_config(config_path: pathlib.Path | str | None = None) -> dict:
    """Load configuration from YAML file with env var overrides.

    Args:
        config_path: Optional override for config file path.

    Returns:
        Complete configuration dictionary.
    """
    global _config
    with _cache_lock:
        if _config is not None:
            return _config

    path = pathlib.Path(config_path) if config_path else CONFIG_PATH

    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = _default_config()

    cfg = _apply_env_overrides(cfg)
    with _cache_lock:
        _config = cfg
        _get_cache.clear()
    return _config


def reload_config(config_path: pathlib.Path | str | None = None) -> dict:
    """Force reload configuration (useful for testing)."""
    global _config
    with _cache_lock:
        _config = None
        _get_cache.clear()
    return load_config(config_path)


def get(key_path: str, default: Any = None) -> Any:
    """Get a config value by dot-separated path with fast-path memory caching.

    Example: get('llm.model') → 'huihui_ai/qwen3.5-abliterated:9b'
    """
    with _cache_lock:
        if key_path in _get_cache:
            val = _get_cache[key_path]
            return default if val is None and default is not None else val

    cfg = load_config()
    parts = key_path.split(".")
    current = cfg
    found = True
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            found = False
            break

    if found:
        with _cache_lock:
            _get_cache[key_path] = current
        return current
    return default


def _default_config() -> dict:
    """Fallback defaults if config.yaml is missing."""
    return {
        "llm": {
            "base_url": "http://localhost:11434/v1",
            "api_key": "ollama",
            "model": "huihui_ai/qwen3.5-abliterated:9b",
            "temperature": 0.1,
        },
        "agent": {
            "max_iterations": 25,
            "context_window_size": 30,
            "retry_max": 2,
            "retry_delay_seconds": 3,
            "stagnation_warning_threshold": 3,
            "stagnation_max_threshold": 5,
            "relentless_pursuit": True,
            "compound_threat_correlation": True,
            "max_guard_challenges": 10,
            "stagnation_max_rescues": 5,
        },
        "mcp": {
            "server_script": "src/servers/docker_arsenal.py",
        },
        "timeouts": {
            "fast_scan": 120,
            "deep_scan": 300,
            "nuclei": 300,
            "sqlmap": 300,
            "crawler": 60,
            "hydra": 600,
            "metasploit": 180,
            "whatweb": 60,
            "nikto": 240,
            "gobuster": 120,
            "wpscan": 300,
            "subfinder": 120,
            "ffuf": 180,
            "testssl": 300,
            "sensitive_files": 60,
            "cors": 60,
            "xss": 120,
            "httpx": 120,
            "ssl_cert": 30,
            "dns_security": 30,
            "security_txt": 30,
            "cookie_security": 30,
            "http_headers": 30,
            "api_docs": 60,
            "subdomain_takeover": 60,
            "waf_detect": 30,
        },
        "hitl": {
            "enabled": True,
            "destructive_tools": [
                "docker_sqlmap_scan", "docker_sqlmap_dump",
                "docker_bruteforce", "bruteforce_ssh",
                "bruteforce_http_form", "docker_wpscan",
                "docker_msf_search",
            ],
        },
        "reporter": {
            "model": "qwen2.5:3b",
            "temperature": 0.3,
            "timeout_seconds": 120,
            "enabled": True,
            "realtime": True,
            "realtime_timeout": 30,
            "skip_tools": ["docker_resolve_dns", "browse_webpage"],
        },
        "reports": {
            "output_dir": "reports",
            "generate_word": True,
            "generate_markdown": True,
            "generate_json": True,
            "company_name": "Security Assessment Team",
            "classification": "CONFIDENTIAL",
        },
        "wordlists": {
            "directory": "wordlists",
            "default_password": "rockyou.txt",
            "default_directory": "dirb_common.txt",
        },
        "vectordb": {
            "enabled": False,
            "path": "data/chromadb",
            "embedding_source": "ollama",
            "ollama_model": "nomic-embed-text",
            "top_k": 3,
            "min_similarity": 0.65,
            "max_rag_tokens": 800,
            "rerank": {
                "enabled": True,
                "model": "ms-marco-MiniLM-L-12-v2",
                "weights": {"cross_encoder": 0.5, "heuristic": 0.3, "vector_similarity": 0.2},
            },
            "consolidation": {
                "auto_trigger_threshold": 1000,
                "similarity_threshold": 0.85,
                "min_cluster_size": 5,
            },
        },
        "tactical_policy": {
            "enabled": True,
            "policy_file": "data/tactical_policy.json",
            "learning_rate": 0.15,
            "discount_factor": 0.85,
            "exploration_bonus": 1.2,
        },
    }


def check_environment() -> dict:
    """Perform pre-flight health checks for Docker, Ollama, Models, and Wordlists.

    Returns:
        Dict with keys: 'docker', 'ollama', 'models', 'wordlists', 'all_ok'
    """
    import subprocess
    import requests
    from urllib.parse import urlparse

    status = {
        "docker": {"ok": False, "message": ""},
        "ollama": {"ok": False, "message": ""},
        "models": {"ok": False, "message": "", "missing": []},
        "wordlists": {"ok": False, "message": "", "found": []},
        "all_ok": False,
    }

    # 1. Check Docker
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode == 0:
            status["docker"]["ok"] = True
            status["docker"]["message"] = "Docker daemon is running."
        else:
            status["docker"]["message"] = "Docker command failed. Ensure Docker Desktop is running."
    except Exception as e:
        status["docker"]["message"] = f"Docker not accessible: {e}"

    # 2. Check Ollama API
    cfg = load_config()
    base_url = cfg.get("llm", {}).get("base_url", "http://localhost:11434/v1")
    parsed = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"
    tags_url = f"{root_url}/api/tags"

    installed_models = []
    try:
        resp = requests.get(tags_url, timeout=5)
        if resp.status_code == 200:
            status["ollama"]["ok"] = True
            status["ollama"]["message"] = f"Ollama is reachable at {root_url}."
            data = resp.json()
            installed_models = [m.get("name", "") for m in data.get("models", [])]
        else:
            status["ollama"]["message"] = f"Ollama responded with status code {resp.status_code}."
    except Exception as e:
        status["ollama"]["message"] = f"Cannot connect to Ollama at {root_url}: {e}"

    # 3. Check Required Models
    required_models = [
        cfg.get("llm", {}).get("model", "huihui_ai/qwen3.5-abliterated:9b"),
        cfg.get("reporter", {}).get("model", "huihui_ai/qwen3.5-abliterated:2B"),
    ]
    missing = []
    for req in required_models:
        found = any(req == m or m.startswith(req.split(":")[0]) for m in installed_models)
        if not found:
            missing.append(req)

    status["models"]["missing"] = missing
    if status["ollama"]["ok"]:
        if not missing:
            status["models"]["ok"] = True
            status["models"]["message"] = f"All required models available: {', '.join(required_models)}"
        else:
            status["models"]["message"] = f"Missing model(s): {', '.join(missing)}. Run: ollama pull <model>"
    else:
        status["models"]["message"] = "Cannot check models because Ollama is unreachable."

    # 4. Check Wordlists
    wordlists_dir = PROJECT_ROOT / cfg.get("wordlists", {}).get("directory", "wordlists")
    expected_wordlists = ["dirb_common.txt", "rockyou.txt"]
    found_wordlists = []
    if wordlists_dir.is_dir():
        for wl in expected_wordlists:
            if (wordlists_dir / wl).is_file():
                found_wordlists.append(wl)

    status["wordlists"]["found"] = found_wordlists
    if len(found_wordlists) == len(expected_wordlists):
        status["wordlists"]["ok"] = True
        status["wordlists"]["message"] = f"Wordlists verified in {wordlists_dir}."
    else:
        missing_wl = set(expected_wordlists) - set(found_wordlists)
        status["wordlists"]["message"] = f"Missing wordlist(s): {', '.join(missing_wl)}. Run setup_wordlists.py."

    # 5. Check Vector DB (RAG) if enabled
    vectordb_cfg = cfg.get("vectordb", {})
    if vectordb_cfg.get("enabled", False) is True:
        vdb_model = vectordb_cfg.get("ollama_model", "nomic-embed-text")
        vdb_source = vectordb_cfg.get("embedding_source", "ollama")
        vdb_path = PROJECT_ROOT / vectordb_cfg.get("path", "data/chromadb")

        status["vectordb"] = {"ok": False, "message": ""}
        dir_ok = True
        try:
            vdb_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            dir_ok = False
            status["vectordb"]["message"] = f"Cannot create ChromaDB storage at {vdb_path}: {e}"

        model_ok = True
        if vdb_source == "ollama":
            if status["ollama"]["ok"]:
                model_found = any(vdb_model == m or m.startswith(vdb_model.split(":")[0]) for m in installed_models)
                if not model_found:
                    model_ok = False
                    status["vectordb"]["message"] = f"Embedding model '{vdb_model}' missing in Ollama. Run: ollama pull {vdb_model}"
            else:
                model_ok = False
                status["vectordb"]["message"] = "Cannot check embedding model because Ollama is unreachable."

        if dir_ok and model_ok:
            status["vectordb"]["ok"] = True
            status["vectordb"]["message"] = f"Vector DB operational at {vdb_path} ({vdb_model})."

        status["all_ok"] = (
            status["docker"]["ok"] and
            status["ollama"]["ok"] and
            status["models"]["ok"] and
            status["wordlists"]["ok"] and
            status["vectordb"]["ok"]
        )
    else:
        status["all_ok"] = (
            status["docker"]["ok"] and
            status["ollama"]["ok"] and
            status["models"]["ok"] and
            status["wordlists"]["ok"]
        )
    return status


def validate_config(cfg: dict | None = None) -> tuple[bool, list[str]]:
    """Validate configuration schema and values.

    Args:
        cfg: Optional config dictionary to validate (defaults to loaded config).

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    if cfg is None:
        cfg = load_config()

    errors = []

    # 1. LLM section
    llm = cfg.get("llm")
    if not isinstance(llm, dict):
        errors.append("Missing or invalid 'llm' section in config.")
    else:
        if not llm.get("base_url"):
            errors.append("llm.base_url must be specified.")
        if not llm.get("model"):
            errors.append("llm.model must be specified.")

    # 2. Agent section
    agent = cfg.get("agent")
    if not isinstance(agent, dict):
        errors.append("Missing or invalid 'agent' section in config.")
    else:
        max_iter = agent.get("max_iterations")
        if not isinstance(max_iter, int) or max_iter <= 0:
            errors.append("agent.max_iterations must be a positive integer.")
        if "relentless_pursuit" in agent and not isinstance(agent["relentless_pursuit"], bool):
            errors.append("agent.relentless_pursuit must be a boolean.")
        if "compound_threat_correlation" in agent and not isinstance(agent["compound_threat_correlation"], bool):
            errors.append("agent.compound_threat_correlation must be a boolean.")
        if "max_guard_challenges" in agent and (not isinstance(agent["max_guard_challenges"], int) or agent["max_guard_challenges"] <= 0):
            errors.append("agent.max_guard_challenges must be a positive integer.")
        if "stagnation_max_rescues" in agent and (not isinstance(agent["stagnation_max_rescues"], int) or agent["stagnation_max_rescues"] <= 0):
            errors.append("agent.stagnation_max_rescues must be a positive integer.")

    # 3. Timeouts section
    timeouts = cfg.get("timeouts")
    if not isinstance(timeouts, dict):
        errors.append("Missing or invalid 'timeouts' section in config.")
    else:
        for k, v in timeouts.items():
            if not isinstance(v, (int, float)) or v <= 0:
                errors.append(f"timeouts.{k} must be a positive number.")

    # 4. HITL section
    hitl = cfg.get("hitl")
    if not isinstance(hitl, dict):
        errors.append("Missing or invalid 'hitl' section in config.")
    else:
        if not isinstance(hitl.get("destructive_tools"), list):
            errors.append("hitl.destructive_tools must be a list.")

    # 5. Reporter section
    reporter = cfg.get("reporter")
    if reporter is not None:
        if not isinstance(reporter, dict):
            errors.append("reporter section must be a dictionary.")
        else:
            if "model" in reporter and (not isinstance(reporter["model"], str) or not reporter["model"].strip()):
                errors.append("reporter.model must be a non-empty string.")
            if "temperature" in reporter and (not isinstance(reporter["temperature"], (int, float)) or reporter["temperature"] < 0):
                errors.append("reporter.temperature must be a non-negative number.")
            if "timeout_seconds" in reporter and (not isinstance(reporter["timeout_seconds"], (int, float)) or reporter["timeout_seconds"] <= 0):
                errors.append("reporter.timeout_seconds must be a positive number.")
            if "realtime_timeout" in reporter and (not isinstance(reporter["realtime_timeout"], (int, float)) or reporter["realtime_timeout"] <= 0):
                errors.append("reporter.realtime_timeout must be a positive number.")
            if "skip_tools" in reporter and not isinstance(reporter["skip_tools"], list):
                errors.append("reporter.skip_tools must be a list.")

    # 6. Reports section
    reports = cfg.get("reports")
    if reports is not None:
        if not isinstance(reports, dict):
            errors.append("reports section must be a dictionary.")
        else:
            if "output_dir" in reports and (not isinstance(reports["output_dir"], str) or not reports["output_dir"].strip()):
                errors.append("reports.output_dir must be a non-empty string.")
            if "generate_word" in reports and not isinstance(reports["generate_word"], bool):
                errors.append("reports.generate_word must be a boolean.")
            if "generate_markdown" in reports and not isinstance(reports["generate_markdown"], bool):
                errors.append("reports.generate_markdown must be a boolean.")
            if "generate_json" in reports and not isinstance(reports["generate_json"], bool):
                errors.append("reports.generate_json must be a boolean.")

    # 7. Wordlists section
    wordlists = cfg.get("wordlists")
    if wordlists is not None:
        if not isinstance(wordlists, dict):
            errors.append("wordlists section must be a dictionary.")
        else:
            if "directory" in wordlists and (not isinstance(wordlists["directory"], str) or not wordlists["directory"].strip()):
                errors.append("wordlists.directory must be a non-empty string.")

    # 8. MCP section
    mcp_cfg = cfg.get("mcp")
    if mcp_cfg is not None:
        if not isinstance(mcp_cfg, dict):
            errors.append("mcp section must be a dictionary.")
        else:
            if "server_script" in mcp_cfg and (not isinstance(mcp_cfg["server_script"], str) or not mcp_cfg["server_script"].strip()):
                errors.append("mcp.server_script must be a non-empty string.")
            if "log_level" in mcp_cfg and mcp_cfg["log_level"] not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                errors.append("mcp.log_level must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.")

    # 9. Tactical Policy section
    tp_cfg = cfg.get("tactical_policy")
    if tp_cfg is not None:
        if not isinstance(tp_cfg, dict):
            errors.append("tactical_policy section must be a dictionary.")
        else:
            if "learning_rate" in tp_cfg and (not isinstance(tp_cfg["learning_rate"], (int, float)) or not (0.0 < tp_cfg["learning_rate"] <= 1.0)):
                errors.append("tactical_policy.learning_rate must be a float between 0 and 1.")
            if "discount_factor" in tp_cfg and (not isinstance(tp_cfg["discount_factor"], (int, float)) or not (0.0 <= tp_cfg["discount_factor"] <= 1.0)):
                errors.append("tactical_policy.discount_factor must be a float between 0 and 1.")

    return len(errors) == 0, errors
