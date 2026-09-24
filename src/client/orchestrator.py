"""Orchestrator and ReAct loop for Local Security Agent.

Key capabilities:
- Real-time Dual-Agent Collaboration: Reporter observes every tool
  result, updates findings, and injects suggestions for Red Teamer
- ReportState: shared memory accumulating findings in real-time
- DOCX report generation
- Tactical Policy Engine: Reinforcement learning & Bandit decision guidance
- Structured reporter output (JSON) for precise report rendering
- Config-driven (reads from config.yaml)
"""

import asyncio
import difflib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from openai import AsyncOpenAI
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

# Import centralized config and modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import logging
from src.utils.config import load_config, get as cfg_get
from src.client.report_state import ReportState, Finding, ToolStep
from src.utils.report_generator import generate_docx_report
from src.utils.tactical_policy import TacticalPolicyManager, AttackStateExtractor, extract_semantic_reward

console = Console()
logger = logging.getLogger("orchestrator")


# ---------------------------------------------------------------------------
# High-Performance Pre-compiled Regular Expressions
# ---------------------------------------------------------------------------

_RE_SINGLE_LINE_COMMENT = re.compile(r'(?<!")//[^\n]*')
_RE_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_RE_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')
_RE_TRAILING_COMMAS = re.compile(r',\s*([}\]])')

_RE_JSON_FENCE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)
_RE_GENERIC_FENCE = re.compile(r"```\s*(.*?)\s*```", re.DOTALL)
_RE_REGEX_BRACKET_FALLBACK = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)

_RE_CVE_PATTERN = re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', re.IGNORECASE)
_RE_TARGET_ACQUIRED = re.compile(r'TARGET ACQUIRED:\s*(\S+)')
_RE_HTTP_URL = re.compile(r'(https?://[^\s\'"<>]+)')
_RE_HOST_OR_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b')
_RE_TOOL_NAME_FIELD = re.compile(r'"tool_name":\s*"([^"]+)"')
_RE_TOOL_RESULT_MSG = re.compile(r"Tool '([^']+)' result: (.+)", re.DOTALL)
_RE_MISSION_OBJECTIVE = re.compile(r'MISSION:\s*(.+?)(?:\n\n|\n[A-Z_]+:|$)', re.DOTALL)
_RE_PORT_PATTERN = re.compile(r'(?:port\s+|open\s+port\s+)?(\d{1,5})/(?:tcp|udp)', re.IGNORECASE)
_RE_URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
_RE_SAFE_FILENAME = re.compile(r'[^a-zA-Z0-9.-]')
_RE_CLEAN_PROTOCOL = re.compile(r"^https?://")
_RE_CLEAN_DEFAULT_PORTS = re.compile(r":(80|443)(/|$)")
_RE_DOMAIN_EXTRACT = re.compile(r'(?:https?://)?([a-zA-Z0-9.-]+)')

# Strip Qwen3.5 thinking mode tags (<think>...</think> or unclosed <think>...) before JSON extraction
_RE_THINK_TAGS = re.compile(r'<think>.*?(?:</think>|$)', re.DOTALL)


def _clean_thinking_tags(text: str) -> str:
    """Clean Qwen thinking mode tags (<think>...</think> or trailing unclosed <think>...).

    If stripping leaves no text but the original text contains JSON brackets ({ ... }),
    safely strip only the delimiter tags themselves so JSON parsing can succeed.
    """
    if not text:
        return text
    cleaned = _RE_THINK_TAGS.sub("", text).strip()
    if cleaned:
        return cleaned
    # If cleaned is empty, check if original text had JSON brackets
    if "{" in text and "}" in text:
        # Strip just the delimiter tags themselves
        return re.sub(r'</?think>', '', text).strip()
    return text.strip()


# ---------------------------------------------------------------------------
# Audit Trail Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Logs every tool call and result to a JSONL file for forensic review."""

    def __init__(self, target: str):
        report_dir = cfg_get("reports.output_dir", "reports")
        os.makedirs(report_dir, exist_ok=True)
        safe = _RE_SAFE_FILENAME.sub('_', target)[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = f"{report_dir}/audit_trail_{safe}_{ts}.jsonl"
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", encoding="utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def log(self, event_type: str, data: dict) -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            **data,
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            if hasattr(self, "_fh") and not self._fh.closed:
                try:
                    self._fh.write(line)
                    self._fh.flush()
                except (IOError, OSError) as e:
                    logger.warning("Failed to write audit trail entry: %s", e)

    def close(self) -> None:
        with self._lock:
            if hasattr(self, "_fh") and not self._fh.closed:
                try:
                    self._fh.flush()
                except (IOError, OSError):
                    pass
                finally:
                    self._fh.close()

    def __del__(self) -> None:
        self.close()


# ---------------------------------------------------------------------------
# JSON Healing Utilities
# ---------------------------------------------------------------------------

def _escape_newlines_in_json_strings(s: str) -> str:
    """Escape raw unescaped newlines, carriage returns and tabs inside double-quoted JSON strings."""
    if not s or ('\n' not in s and '\r' not in s and '\t' not in s):
        return s

    result = []
    in_string = False
    escape = False
    for ch in s:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == '\\':
            escape = True
            result.append(ch)
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and ch == '\n':
            result.append('\\n')
        elif in_string and ch == '\r':
            result.append('\\r')
        elif in_string and ch == '\t':
            result.append('\\t')
        else:
            result.append(ch)
    return "".join(result)


def _sanitize_json_string(text: str) -> str:
    """Remove comments, control characters, and trailing commas from JSON-like text.

    IMPORTANT: Does NOT join lines into one — that destroys Vietnamese Unicode.
    Instead, replaces raw newlines with escaped \\n only inside JSON string values.
    """
    # Remove single-line comments (// ...) but NOT inside strings
    text = _RE_SINGLE_LINE_COMMENT.sub('', text)
    # Remove block comments (/* ... */)
    text = _RE_BLOCK_COMMENT.sub('', text)
    # Escape raw unescaped newlines/tabs inside string literals
    text = _escape_newlines_in_json_strings(text)
    # Remove dangerous control characters (keep \n, \r, \t which are valid whitespace)
    text = _RE_CONTROL_CHARS.sub('', text)
    # Remove trailing commas before } or ] (common model error)
    text = _RE_TRAILING_COMMAS.sub(r'\1', text)
    return text.strip()


def _extract_json_block(text: str) -> str | None:
    """Extract a JSON object using bracket matching (handles nested {})."""
    start = text.find('{')
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == '\\':
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _extract_json(response_content: str) -> dict:
    """Extract JSON from model response with multiple fallback strategies.

    Strategy order:
    1. Try raw parse from ```json fence (preserves Unicode perfectly)
    2. Try raw parse from any ``` fence
    3. Try bracket-matched extraction from raw text
    4. Sanitize + retry for each strategy
    """
    candidates = []

    # Collect candidate JSON strings
    # Strategy 1: ```json ... ``` fence
    match = _RE_JSON_FENCE.search(response_content)
    if match:
        candidates.append(match.group(1).strip())

    # Strategy 2: Any ``` ... ``` fence
    match = _RE_GENERIC_FENCE.search(response_content)
    if match:
        block = match.group(1).strip()
        if block.startswith("{") and block not in candidates:
            candidates.append(block)

    # Strategy 3: Bracket-matched extraction from raw text
    bracket_block = _extract_json_block(response_content)
    if bracket_block and bracket_block not in candidates:
        candidates.append(bracket_block)

    # Strategy 4: Regex fallback
    match = _RE_REGEX_BRACKET_FALLBACK.search(response_content)
    if match:
        regex_block = match.group(0).strip()
        if regex_block not in candidates:
            candidates.append(regex_block)

    # Try each candidate: first raw, then sanitized
    last_error = None
    for candidate in candidates:
        # Attempt 1: Raw parse (best for Unicode)
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            pass

        # Attempt 1b: Escape newlines inside strings while preserving exact Unicode
        try:
            escaped = _escape_newlines_in_json_strings(candidate)
            return json.loads(escaped)
        except (json.JSONDecodeError, ValueError):
            pass

        # Attempt 2: Sanitized parse
        try:
            sanitized = _sanitize_json_string(candidate)
            return json.loads(sanitized)
        except (json.JSONDecodeError, ValueError) as e:
            last_error = e

    # Strategy 5: Truncated JSON repair — model output was cut mid-JSON
    # Common case: {"thought": "long text...<truncated>
    # Attempt to extract partial fields and rebuild minimal valid JSON
    # When format=json is active, truncated output has NO fences and NO matching brackets
    # so candidates may be empty — use raw response_content as fallback
    repair_candidates = candidates if candidates else [response_content.strip()]
    for candidate in repair_candidates:
        try:
            repaired = _repair_truncated_json(candidate)
            if repaired:
                return repaired
        except Exception:
            pass

    raise ValueError(f"No valid JSON found. Last error: {last_error}")

def _repair_truncated_json(text: str) -> dict | None:
    """Attempt to repair JSON that was truncated mid-output.

    Common truncation patterns from Ollama:
    - {"thought": "long text...<cut>   (thought too long, nothing else extracted)
    - {"thought": "...", "action": "call_tool", "tool_name": "docker_<cut>
    - {"thought": "...", "action": "call_tool", "tool_name": "x", "arguments": {"key": "val<cut>

    Returns a valid dict if repair succeeds, None otherwise.
    """
    if not text or not text.strip().startswith("{"):
        return None

    # Try to extract tool_name field — fully quoted
    tool_match = _RE_TOOL_NAME_FIELD.search(text)
    tool_name = None
    if tool_match:
        tool_name = tool_match.group(1)
    else:
        # Partial tool_name: "tool_name": "docker_cors_sc<cut>
        partial = re.search(r'"tool_name"\s*:\s*"(docker_[a-z_]+)', text)
        if partial:
            tool_name = partial.group(1)

    # Fallback: extract tool name mentioned in thought text
    if not tool_name:
        # Match 'docker_xxx' pattern anywhere in text (from thought content)
        thought_tools = re.findall(r"['\"]?(docker_[a-z_]{4,})['\"]?", text)
        if thought_tools:
            # Use the LAST mentioned tool (usually the intended next action)
            tool_name = thought_tools[-1]

    if tool_name:
        # Try to extract arguments
        args_match = re.search(r'"arguments"\s*:\s*(\{[^}]*\})', text)
        args = {}
        if args_match:
            try:
                args = json.loads(args_match.group(1))
            except (json.JSONDecodeError, ValueError):
                pass
        # Auto-populate target arg if missing (extract from text)
        if not args:
            url_match = re.search(r'https?://[^\s"\']+', text)
            if url_match:
                # Guess the right arg name based on tool
                url = url_match.group(0).rstrip('.,;)')
                if "target_url" in text or tool_name in (
                    "docker_whatweb", "docker_crawl_web", "docker_nuclei_scan",
                    "docker_http_headers_audit", "docker_sensitive_files_scan",
                    "docker_security_txt_audit", "docker_api_docs_audit",
                    "docker_cors_scan", "docker_nikto_scan",
                ):
                    args = {"target_url": url}
                elif tool_name in ("docker_testssl",):
                    args = {"target_host": url}
                elif tool_name in ("docker_subfinder", "docker_subdomain_takeover_audit"):
                    # Extract domain from URL
                    domain_match = re.search(r'https?://([^/:\s]+)', url)
                    args = {"domain": domain_match.group(1) if domain_match else url}
                else:
                    args = {"target": url}

        # Extract thought (first string value after "thought":)
        thought_match = re.search(r'"thought"\s*:\s*"([^"]{0,200})', text)
        thought = thought_match.group(1) if thought_match else "Continuing reconnaissance"

        return {
            "thought": thought + " [auto-repaired]",
            "action": "call_tool",
            "tool_name": tool_name,
            "arguments": args,
        }

    return None


def _extract_reporter_fallback(content: str) -> dict:
    """Heuristic fallback extractor for Reporter when strict JSON parsing fails.

    Salvages risk_score, suggestions, comments, objective progress, and partial findings
    to ensure Red Teamer never loses guidance due to punctuation/quote glitches.
    """
    if not content:
        return {}

    result = {
        "new_findings": [],
        "risk_score": 0.0,
        "suggestion": "",
        "step_comment": "",
        "objective_assessment": "",
        "blocking_factor": "",
        "attack_pattern": {},
    }

    # 1. Extract risk_score
    risk_match = re.search(r'"risk_score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', content)
    if risk_match:
        try:
            result["risk_score"] = float(risk_match.group(1))
        except ValueError:
            pass

    # 2. Extract suggestion_for_redteam
    sug_match = re.search(r'"(?:suggestion_for_redteam|suggestion)"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
    if sug_match:
        result["suggestion"] = sug_match.group(1).replace(r'\"', '"').replace(r'\n', ' ').strip()
    else:
        # Fallback to looser line-based capture
        sug_line = re.search(r'"(?:suggestion_for_redteam|suggestion)"\s*:\s*"?([^,\n}]+)', content)
        if sug_line:
            result["suggestion"] = sug_line.group(1).strip().strip('"')

    # 3. Extract step_comment
    cmt_match = re.search(r'"step_comment"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
    if cmt_match:
        result["step_comment"] = cmt_match.group(1).replace(r'\"', '"').replace(r'\n', ' ').strip()

    # 4. Extract objective_assessment
    obj_match = re.search(r'"objective_assessment"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
    if obj_match:
        result["objective_assessment"] = obj_match.group(1).replace(r'\"', '"').replace(r'\n', ' ').strip()

    # 5. Extract blocking_factor
    blk_match = re.search(r'"blocking_factor"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
    if blk_match:
        result["blocking_factor"] = blk_match.group(1).replace(r'\"', '"').replace(r'\n', ' ').strip()

    # 6. Extract heuristic findings if present
    finding_matches = re.finditer(r'\{[^{}]*"title"\s*:\s*"([^"]+)"[^{}]*"severity"\s*:\s*"([A-Z]+)"[^{}]*\}', content)
    for fm in finding_matches:
        f_block = fm.group(0)
        title = fm.group(1)
        severity = fm.group(2)
        desc_m = re.search(r'"description"\s*:\s*"((?:[^"\\]|\\.)*)"', f_block)
        desc = desc_m.group(1) if desc_m else ""
        cve_m = re.search(r'"cve_id"\s*:\s*"([^"]+)"', f_block)
        cve = cve_m.group(1) if cve_m else ""
        result["new_findings"].append({
            "title": title,
            "severity": severity,
            "description": desc,
            "cve_id": cve,
        })

    # Return dict if at least one meaningful field was salvaged
    if result["suggestion"] or result["risk_score"] > 0 or result["step_comment"] or result["new_findings"]:
        return result
    return {}


def _truncate_tool_output_for_llm(result_str: str, max_chars: int = 6000) -> str:
    """Smartly truncate large tool output before feeding into LLM prompt.

    Preserves head (initial discovery, status, open ports) and tail (totals, summary,
    last endpoints), preventing context bloat while keeping high-value signal.
    Full output remains in ReportState and audit trail.
    """
    if not result_str or len(result_str) <= max_chars:
        return result_str
    head_len = int(max_chars * 0.6)  # e.g., 3600 chars
    tail_len = max_chars - head_len  # e.g., 2400 chars
    omitted = len(result_str) - max_chars
    return (
        f"{result_str[:head_len]}\n\n"
        f"[... Đã rút gọn {omitted} ký tự trung gian để tối ưu hóa bộ nhớ context. "
        f"Toàn bộ chi tiết kỹ thuật và bề mặt tấn công đã được cập nhật vào ReportState ...] \n\n"
        f"{result_str[-tail_len:]}"
    )


# ---------------------------------------------------------------------------
# Context Window Management
# ---------------------------------------------------------------------------

def _summarize_old_messages(messages: list, keep_last: int, report_state: Any = None) -> list:
    """Compress old messages to stay within context window.

    Keeps the system prompt (index 0), the original user prompt (index 1),
    and the last `keep_last` messages. Everything in between is condensed
    into a single summary message.

    Args:
        messages: Full message history.
        keep_last: Number of recent messages to preserve verbatim.
        report_state: Optional ReportState object to retain attack surface & goal progress.

    Returns:
        Compressed message list.
    """
    if len(messages) <= keep_last + 2:
        return messages

    # Messages to summarize: everything between [2] and [-keep_last]
    old_messages = messages[2:-keep_last]

    # Build summary from old tool calls and results
    tools_used = []
    key_findings = []
    for msg in old_messages:
        content = msg.get("content", "")
        if msg.get("role") == "assistant" and '"tool_name"' in content:
            m = _RE_TOOL_NAME_FIELD.search(content)
            if m:
                tools_used.append(m.group(1))
        if msg.get("role") == "user" and content.startswith("Tool '"):
            # Extract tool name and first 150 chars of result
            tool_match = _RE_TOOL_RESULT_MSG.match(content)
            if tool_match:
                tool_name = tool_match.group(1)
                result_snippet = tool_match.group(2)[:150]
                key_findings.append(f"- {tool_name}: {result_snippet}")

    findings_display = "\n".join(key_findings[:15]) if key_findings else "- No significant findings yet"
    user_prompt = messages[1].get("content", "") if len(messages) > 1 else ""
    m_obj = _RE_MISSION_OBJECTIVE.search(user_prompt)
    mission_str = f"Mục tiêu cốt lõi: {m_obj.group(1).strip()}\n" if m_obj else ""

    # Optional attack surface and roadmap context from report_state
    surface_str = ""
    if report_state and hasattr(report_state, "attack_surface"):
        surf_parts = []
        if report_state.attack_surface.open_ports:
            if isinstance(report_state.attack_surface.open_ports, dict):
                surf_parts.append(f"Cổng mở: {list(report_state.attack_surface.open_ports.keys())[:8]}")
            else:
                surf_parts.append(f"Cổng mở: {list(report_state.attack_surface.open_ports)[:8]}")
        if report_state.attack_surface.parameterized_endpoints:
            surf_parts.append(f"URLs tham số: {len(report_state.attack_surface.parameterized_endpoints)}")
        if report_state.attack_surface.detected_technologies:
            surf_parts.append(f"Công nghệ: {', '.join(report_state.attack_surface.detected_technologies[:3])}")

        if surf_parts:
            surface_str = f"Bề mặt tấn công tích lũy: {' | '.join(surf_parts)}\n"
        if hasattr(report_state, "calculate_goal_progress"):
            surface_str += f"Tiến độ mục tiêu hiện tại: {report_state.calculate_goal_progress()}%\n"

    summary_text = (
        f"[CONTEXT SUMMARY — {len(old_messages)} earlier messages compressed]\n"
        f"{mission_str}"
        f"{surface_str}"
        f"Tools previously called: {', '.join(tools_used) if tools_used else 'none'}\n"
        f"Key findings so far:\n"
        f"{findings_display}\n"
        f"[END SUMMARY — Continue from recent context below]"
    )

    summary_msg = {"role": "user", "content": summary_text}

    # Reconstruct: system + original prompt + summary + recent messages
    return messages[:2] + [summary_msg] + messages[-keep_last:]


# ---------------------------------------------------------------------------
# Target Extraction & Tool Argument Auto-Correction
# ---------------------------------------------------------------------------

def _extract_target_from_prompt(prompt: str) -> dict:
    """Extract target URL/hostname/IP from the mission prompt."""
    target_info = {"raw": "", "url": "", "hostname": "", "ip": ""}

    m = _RE_TARGET_ACQUIRED.search(prompt)
    if m:
        target_info["raw"] = m.group(1).strip()
    else:
        # Fallback: search for URL, domain, or IP directly in the prompt
        url_m = _RE_HTTP_URL.search(prompt)
        if url_m:
            target_info["raw"] = url_m.group(1).strip()
        else:
            host_m = _RE_HOST_OR_IP.search(prompt)
            if host_m:
                target_info["raw"] = host_m.group(0).strip()
            elif prompt.strip() and "\n" not in prompt.strip() and len(prompt.strip()) < 100:
                target_info["raw"] = prompt.strip()

    raw = target_info["raw"]
    if raw:
        from urllib.parse import urlparse
        if '://' in raw:
            parsed = urlparse(raw)
            target_info["hostname"] = parsed.hostname or ""
            target_info["url"] = raw
        else:
            clean_host = raw.split('/')[0]
            if clean_host.startswith('[') and ']' in clean_host:
                target_info["hostname"] = clean_host.split(']')[0].lstrip('[')
            elif clean_host.count(':') == 1:
                target_info["hostname"] = clean_host.split(':')[0]
            else:
                target_info["hostname"] = clean_host
            target_info["url"] = f"http://{raw}"

        # Try DNS resolution with short timeout
        import socket
        try:
            hostname = target_info["hostname"]
            if hostname:
                orig_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3.0)
                try:
                    results = socket.getaddrinfo(hostname, None, socket.AF_INET)
                    ips = sorted(set(r[4][0] for r in results))
                    if ips:
                        target_info["ip"] = ips[0]
                finally:
                    socket.setdefaulttimeout(orig_timeout)
        except (socket.gaierror, OSError, Exception):
            pass

    return target_info


def _extract_mission_objective(prompt: str) -> str:
    """Extract the specific mission objective from the prompt."""
    m = _RE_MISSION_OBJECTIVE.search(prompt)
    if m:
        return m.group(1).strip()
    lines = [ln.strip() for ln in prompt.strip().split("\n") if ln.strip()]
    if lines:
        return lines[0][:250]
    return "Toàn diện kiểm tra, trinh sát và tìm kiếm lỗ hổng trên mục tiêu."


URL_REQUIRED_TOOLS = {
    "docker_crawl_web",
    "docker_sqlmap_scan",
    "docker_sqlmap_dump",
    "docker_cors_scan",
    "docker_nikto_scan",
    "docker_nuclei_scan",
    "docker_whatweb",
    "docker_dirb_scan",
    "docker_ffuf",
    "docker_sensitive_files_scan",
    "docker_security_txt_audit",
    "docker_api_docs_audit",
    "docker_cookie_security_audit",
    "docker_http_headers_audit",
    "docker_wpscan",
    "docker_xss_scan",
    "bruteforce_http_form",
    "browse_webpage",
    "docker_waf_detect",
}

HOST_REQUIRED_TOOLS = {
    "docker_scan_ports_fast",
    "docker_scan_ports_deep",
    "docker_resolve_dns",
    "docker_subfinder",
    "docker_testssl",
    "docker_ssl_cert_audit",
    "docker_dns_security_audit",
    "docker_subdomain_takeover_audit",
    "docker_bruteforce",
    "bruteforce_ssh",
}

WAF_TAMPER_MAP = {
    "cloudflare": "between,space2comment,charencode",
    "modsecurity": "modsecurityversioned,modsecurityzeroversioned,space2hash",
    "aws": "between,randomcase,space2comment",
    "cloudfront": "between,randomcase,space2comment",
    "imperva": "appendnullbyte,between,charencode",
    "incapsula": "appendnullbyte,between,charencode",
    "akamai": "between,charencode,randomcase",
    "f5": "between,space2comment",
    "sucuri": "between,space2comment",
    "generic": "space2comment,between",
}


def _get_waf_tamper_script(waf_name: str | None) -> str | None:
    """Determine recommended sqlmap tamper script based on detected WAF."""
    if not waf_name:
        return None
    lower = waf_name.lower().strip()
    for k, script in WAF_TAMPER_MAP.items():
        if k in lower:
            return script
    return "space2comment,between"


KNOWN_TOOL_EXPECTED_PARAMS = {
    "docker_crawl_web": {"target_url", "max_depth", "max_pages"},
    "docker_scan_ports_fast": {"target"},
    "docker_scan_ports_deep": {"target", "ports"},
    "docker_resolve_dns": {"hostname"},
    "docker_subfinder": {"domain"},
    "docker_testssl": {"target_host"},
    "docker_ssl_cert_audit": {"target_host", "port"},
    "docker_dns_security_audit": {"domain"},
    "docker_security_txt_audit": {"target_url"},
    "docker_cookie_security_audit": {"target_url"},
    "docker_http_headers_audit": {"target_url"},
    "docker_api_docs_audit": {"target_url"},
    "docker_subdomain_takeover_audit": {"domain"},
    "docker_waf_detect": {"target_url"},
    "docker_sqlmap_scan": {"target_url", "form_params", "risk", "level", "tamper"},
    "docker_sqlmap_dump": {"target_url", "database", "table"},
    "docker_bruteforce": {"target_host", "service", "port", "username", "password", "wordlist"},
    "bruteforce_ssh": {"target_host", "port", "username", "wordlist"},
    "bruteforce_http_form": {"target_url", "login_path", "username", "wordlist", "failure_string"},
    "docker_wpscan": {"target_url"},
    "docker_msf_search": {"cve_or_keyword"},
    "docker_xss_scan": {"target_url"},
    "docker_nikto_scan": {"target_url"},
    "docker_nuclei_scan": {"target_url", "severity", "tags"},
    "docker_dirb_scan": {"target_url", "wordlist"},
    "docker_ffuf": {"target_url", "wordlist"},
    "docker_sensitive_files_scan": {"target_url"},
    "docker_cors_scan": {"target_url"},
    "docker_httpx_probe": {"targets"},
    "docker_whatweb": {"target_url"},
    "browse_webpage": {"url", "max_length"},
}


def _normalize_tool_args(
    tool_name: str,
    arguments: dict,
    tools_schema: list | None = None,
    detected_waf: str | None = None,
    detected_technologies: list[str] | None = None,
) -> dict:
    """Auto-correct common argument naming and formatting mistakes from the LLM.

    Capabilities:
    1. Key Alias Mapping: Maps common aliases like target_url->target, target_ip->target, domain->target, etc.
    2. URL Healing: Ensures tools in URL_REQUIRED_TOOLS receive a full URL with scheme (http:// or https://).
    3. Host/Domain Healing: Strips scheme/path from tools in HOST_REQUIRED_TOOLS and auto-extracts port if present.
    4. Targets List Healing: Converts list of targets to a comma-separated string for tools like docker_httpx_probe.
    5. Port/Ports Type Healing: Safely normalizes port types between int, string, and list.
    6. WAF Tamper Evasion: Auto-injects appropriate tamper script when WAF is active and not already provided.
    7. Technology-Aware Adaptive Wordlist: Automatically selects specialized dictionary matching detected technologies.
    """
    if not isinstance(arguments, dict):
        return arguments

    tools_schema = tools_schema or []
    tool_schema = next((t for t in tools_schema if t.get("name") == tool_name), None)
    if tool_schema and "input_schema" in tool_schema:
        schema_props = tool_schema["input_schema"].get("properties", {})
        expected_params = set(schema_props.keys())
    else:
        expected_params = set(KNOWN_TOOL_EXPECTED_PARAMS.get(tool_name, []))

    ALIASES = {
        "target": ["target_url", "url", "host", "hostname", "address", "ip", "target_ip", "target_host", "domain"],
        "target_url": ["target", "url", "host", "hostname", "address", "target_host"],
        "targets": ["target", "hosts", "domains", "subdomains", "urls", "host_list", "target_list", "target_url"],
        "url": ["target_url", "target", "host", "hostname", "address"],
        "host": ["target", "target_url", "hostname", "address", "target_host", "ip"],
        "hostname": ["target", "target_url", "host", "address", "target_host", "domain"],
        "target_host": ["target", "host", "hostname", "target_url", "address", "ip", "domain"],
        "domain": ["target", "target_url", "hostname", "host", "target_domain", "root_domain"],
        "target_domain": ["domain", "target", "hostname", "host", "root_domain"],
        "username": ["user", "login", "user_name", "account"],
        "password": ["pass", "passwd", "pwd"],
        "wordlist": ["dictionary", "word_list", "list", "wordlist_path", "passlist"],
        "ports": ["port", "port_range", "port_list", "p", "port_number"],
        "port": ["ports", "port_range", "port_list", "p", "port_number"],
        "cve_or_keyword": ["cve", "keyword", "query", "search", "term", "vuln", "vulnerability"],
        "database": ["db", "dbname", "database_name"],
        "table": ["tbl", "tablename", "table_name"],
        "form_params": ["params", "post_params", "data", "form_data", "body"],
        "login_path": ["path", "endpoint", "url_path", "uri"],
        "failure_string": ["fail_str", "failure", "fail", "error_message"],
        "severity": ["severities", "level", "sev"],
        "mode": ["fuzz_mode", "scan_mode", "type"],
        "tamper": ["tamper_script", "tamper_scripts", "evasion", "bypass_tamper", "scripts"],
        "risk": ["risk_level", "risk_score"],
        "level": ["test_level", "depth_level"],
    }

    corrected = {}
    used_expected = set()

    # First pass: preserve exact matches
    for key, value in arguments.items():
        if key in expected_params:
            corrected[key] = value
            used_expected.add(key)

    # Second pass: map unmatched parameters
    for key, value in arguments.items():
        if key in expected_params:
            continue
        mapped = False
        for expected in expected_params:
            if expected in used_expected:
                continue
            aliases = ALIASES.get(expected, [])
            clean_key = key.replace("-", "_").lower()
            if (key in aliases or
                clean_key == expected.lower() or
                clean_key in [a.lower() for a in aliases]):
                corrected[expected] = value
                used_expected.add(expected)
                console.print(f"[dim]🔄 Auto-corrected arg: '{key}' → '{expected}'[/dim]")
                mapped = True
                break
        if not mapped:
            corrected[key] = value

    # If no expected params were defined at all, preserve arguments
    if not expected_params and not corrected:
        corrected = dict(arguments)

    # -----------------------------------------------------------------------
    # Value & Type Healing
    # -----------------------------------------------------------------------

    # 1. URL Healing for web tools
    if tool_name in URL_REQUIRED_TOOLS:
        for url_key in ("target_url", "url", "target"):
            if url_key in corrected:
                val = corrected[url_key]
                if isinstance(val, str) and val.strip():
                    raw_url = val.strip()
                    clean_url = re.sub(r'^(https?://)+', r'\1', raw_url)
                    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
                        if ":443" in clean_url:
                            healed_url = f"https://{clean_url}"
                        else:
                            healed_url = f"http://{clean_url}"
                        console.print(f"[dim]🌐 URL healed for '{tool_name}': '{raw_url}' → '{healed_url}'[/dim]")
                        corrected[url_key] = healed_url
                    elif clean_url != raw_url:
                        corrected[url_key] = clean_url
                break

    # 2. Host/Domain Healing for infrastructure/network tools
    if tool_name in HOST_REQUIRED_TOOLS:
        for host_key in ("target", "hostname", "domain", "target_host", "host", "target_domain"):
            if host_key in corrected:
                val = corrected[host_key]
                if isinstance(val, str) and val.strip():
                    raw_host = val.strip()
                    if "://" in raw_host or "/" in raw_host or (":" in raw_host and not raw_host.startswith("[")):
                        parse_target = raw_host if "://" in raw_host else f"http://{raw_host}"
                        parsed = urlparse(parse_target)
                        clean_host = parsed.hostname or raw_host.split("/")[0].split(":")[0]
                        parsed_port = parsed.port
                        if clean_host and clean_host != raw_host:
                            console.print(f"[dim]🎯 Host extracted for '{tool_name}': '{raw_host}' → '{clean_host}'[/dim]")
                            corrected[host_key] = clean_host

                        if parsed_port:
                            if "port" in expected_params and "port" not in corrected:
                                corrected["port"] = parsed_port
                                console.print(f"[dim]🔌 Auto-extracted port '{parsed_port}' for '{tool_name}'[/dim]")
                            elif "ports" in expected_params and "ports" not in corrected:
                                corrected["ports"] = str(parsed_port)
                                console.print(f"[dim]🔌 Auto-extracted ports '{parsed_port}' for '{tool_name}'[/dim]")
                break

    # 3. Targets List Healing
    if tool_name == "docker_httpx_probe" or "targets" in corrected:
        if "targets" in corrected:
            t_val = corrected["targets"]
            if isinstance(t_val, list):
                healed_targets = ",".join(str(item).strip() for item in t_val if str(item).strip())
                console.print(f"[dim]📋 Targets list healed for '{tool_name}': list → '{healed_targets}'[/dim]")
                corrected["targets"] = healed_targets
            elif isinstance(t_val, str) and "\n" in t_val:
                healed_targets = ",".join(part.strip() for part in t_val.split("\n") if part.strip())
                console.print(f"[dim]📋 Targets list healed for '{tool_name}'[/dim]")
                corrected["targets"] = healed_targets

    # 4. Port/Ports Type Healing
    if "port" in corrected:
        pval = corrected["port"]
        if isinstance(pval, str) and pval.strip().isdigit():
            corrected["port"] = int(pval.strip())
        elif isinstance(pval, list) and pval and str(pval[0]).strip().isdigit():
            corrected["port"] = int(str(pval[0]).strip())

    if "ports" in corrected:
        psval = corrected["ports"]
        if isinstance(psval, list):
            corrected["ports"] = ",".join(str(p).strip() for p in psval if str(p).strip())
        elif isinstance(psval, int):
            corrected["ports"] = str(psval)

    # 5. WAF Tamper Evasion Auto-Injection for SQLMap
    if tool_name == "docker_sqlmap_scan" and detected_waf and "tamper" not in corrected:
        tamper_script = _get_waf_tamper_script(detected_waf)
        if tamper_script:
            corrected["tamper"] = tamper_script
            console.print(f"[dim magenta]🛡️ WAF Tamper script '{tamper_script}' auto-injected for '{tool_name}' (Target WAF: {detected_waf})[/dim magenta]")

    # 6. Technology-Aware Adaptive Wordlist Selection for Directory / Endpoint Fuzzers
    if tool_name in ("docker_dirb_scan", "docker_ffuf") and detected_technologies:
        current_wl = str(corrected.get("wordlist", "")).lower()
        if not current_wl or any(g in current_wl for g in ("dirb_common", "common.txt", "default")):
            try:
                from src.utils.wordlist_selector import resolve_technology_wordlist
                adaptive_wl = resolve_technology_wordlist(detected_technologies)
                if adaptive_wl:
                    corrected["wordlist"] = adaptive_wl
                    console.print(f"[dim cyan]🎯 Adaptive Wordlist: Tự động chọn từ điển chuyên biệt '{os.path.basename(adaptive_wl)}' cho '{tool_name}'[/dim cyan]")
            except Exception:
                pass

    return corrected



def _normalize_semantic_target(target: str) -> str:
    """Normalize a target string (URL, hostname, or IP) for deduplication.

    Strips schemes (http://, https://), standard ports (:80, :443), leading 'www.',
    and trailing slashes to detect equivalent targets.
    Example: 'http://www.example.com/' -> 'example.com'
    """
    if not isinstance(target, str):
        return str(target)
    cleaned = target.strip().lower()
    # Strip scheme
    cleaned = _RE_CLEAN_PROTOCOL.sub("", cleaned)
    # Strip leading www.
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    # Strip standard ports :80 and :443
    cleaned = _RE_CLEAN_DEFAULT_PORTS.sub(r"\2", cleaned)
    # Strip trailing slashes unless it's just '/'
    cleaned = cleaned.rstrip("/")
    return cleaned


def _get_semantic_signature(tool_name: str, arguments: dict) -> str:
    """Compute normalized signature for semantic anti-loop checking."""
    norm_args = {}
    for k, v in arguments.items():
        if isinstance(v, str) and k.lower() in ("target", "url", "domain", "host", "target_url"):
            norm_args[k] = _normalize_semantic_target(v)
        else:
            norm_args[k] = v
    return f"{tool_name}::{json.dumps(norm_args, sort_keys=True)}"


def _build_tool_reference(tools_schema: list) -> str:
    """Build a concise tool reference for the system prompt."""
    lines = []
    for t in tools_schema:
        params = t.get("input_schema", {}).get("properties", {})
        required = set(t.get("input_schema", {}).get("required", []))
        param_parts = []
        for pname, pinfo in params.items():
            default = pinfo.get("default")
            if pname not in required and default is not None:
                param_parts.append(f'{pname}="{default}"' if isinstance(default, str) else f'{pname}={default}')
            else:
                param_parts.append(pname)
        params_str = ", ".join(param_parts)
        tool_desc = (t.get("description", "") or "").split("\n")[0][:80]
        lines.append(f"  {t['name']}({params_str}) -- {tool_desc}")
    return "\n".join(lines)


def _display_mission_dashboard(
    report_state: ReportState,
    iteration: int,
    max_iterations: int,
    last_tool: str = "",
    last_duration: float = 0.0,
    stagnation_counter: int = 0,
) -> None:
    """Render a real-time Tactical Mission Dashboard (HUD) using Rich."""
    target = report_state.target or "N/A"
    risk_label = report_state.get_overall_risk_label()
    risk_score = report_state.risk_score
    sev_counts = report_state.get_severity_counts()

    # Risk badge color
    risk_color = "red" if "CRITICAL" in risk_label else ("yellow" if "HIGH" in risk_label else ("cyan" if "MEDIUM" in risk_label else "green"))
    risk_badge = f"[{risk_color} bold]{risk_label} ({risk_score:.1f}/10)[/{risk_color} bold]"

    # Attack surface stats
    surface = report_state.attack_surface
    ports_list = sorted(surface.open_ports.keys())
    ports_str = ", ".join(str(p) for p in ports_list[:6]) + (f" (+{len(ports_list)-6})" if len(ports_list) > 6 else "") if ports_list else "Chưa phát hiện"
    techs_str = ", ".join(surface.detected_technologies[:4]) if surface.detected_technologies else "Chưa nhận diện"
    waf_info = getattr(surface, "detected_waf", {})
    waf_name = waf_info.get("primary_waf", "None") if waf_info else "None"

    # Tactical queue preview
    tactical_queue_summary = report_state.get_tactical_queue_summary() if hasattr(report_state, "get_tactical_queue_summary") else ""

    dashboard_table = Table(
        title=f"⚡ MISSION HUD — BƯỚC [{iteration}/{max_iterations}]",
        border_style="bright_blue",
        show_header=True,
        header_style="bold cyan",
    )
    dashboard_table.add_column("Chỉ Số / Bề Mặt", style="white", min_width=22)
    dashboard_table.add_column("Dữ Liệu Trinh Sát & Chiến Thuật Thời Gian Thực", style="bold", min_width=52)

    dashboard_table.add_row("🎯 Mục tiêu & Rủi ro", f"{target} | Mức độ: {risk_badge}")
    dashboard_table.add_row(
        "🛡️ Lỗ hổng xác nhận",
        f"[red bold]🔴 CRIT: {sev_counts['CRITICAL']}[/red bold] | "
        f"[yellow bold]🟠 HIGH: {sev_counts['HIGH']}[/yellow bold] | "
        f"[cyan bold]🟡 MED: {sev_counts['MEDIUM']}[/cyan bold] | "
        f"[blue bold]🔵 LOW: {sev_counts['LOW']}[/blue bold] | "
        f"[dim]Tổng: {len(report_state.findings)}[/dim]"
    )
    dashboard_table.add_row("🌐 Cổng mở & Dịch vụ", f"{ports_str} | WAF: [magenta]{waf_name}[/magenta]")
    dashboard_table.add_row("🧩 Công nghệ / Endpoints", f"{techs_str} | Endpoints: {len(surface.parameterized_endpoints)}")

    if tactical_queue_summary:
        dashboard_table.add_row("⚔️ Hàng đợi tác chiến", f"[yellow]{tactical_queue_summary}[/yellow]")

    if last_tool:
        dashboard_table.add_row("⚙️ Vừa thực thi", f"[cyan]{last_tool}[/cyan] ({last_duration:.1f}s) | Stagnation: {stagnation_counter}")

    console.print(dashboard_table)


# ---------------------------------------------------------------------------
# Retry Logic
# ---------------------------------------------------------------------------

def _get_tool_timeout(tool_name: str) -> float:
    """Resolve configured per-tool execution timeout with safety buffer.

    Reads timeouts from config.yaml with a 15-second buffer for IPC/subprocess
    teardown, falling back to 120s default if unspecified.
    """
    clean_name = tool_name.replace("docker_", "") if tool_name.startswith("docker_") else tool_name
    timeout_map = {
        "crawl_web": cfg_get("timeouts.crawler", 60),
        "crawler": cfg_get("timeouts.crawler", 60),
        "scan_ports_fast": cfg_get("timeouts.fast_scan", 120),
        "scan_ports_deep": cfg_get("timeouts.deep_scan", 300),
        "nuclei_scan": cfg_get("timeouts.nuclei", 300),
        "nuclei": cfg_get("timeouts.nuclei", 300),
        "sqlmap_scan": cfg_get("timeouts.sqlmap", 300),
        "sqlmap_dump": cfg_get("timeouts.sqlmap", 300),
        "sqlmap": cfg_get("timeouts.sqlmap", 300),
        "bruteforce": cfg_get("timeouts.hydra", 600),
        "bruteforce_ssh": cfg_get("timeouts.hydra", 600),
        "bruteforce_http_form": cfg_get("timeouts.hydra", 600),
        "hydra": cfg_get("timeouts.hydra", 600),
        "msf_search": cfg_get("timeouts.metasploit", 180),
        "whatweb": cfg_get("timeouts.whatweb", 60),
        "nikto_scan": cfg_get("timeouts.nikto", 240),
        "nikto": cfg_get("timeouts.nikto", 240),
        "wpscan": cfg_get("timeouts.wpscan", 300),
        "subfinder": cfg_get("timeouts.subfinder", 120),
        "ffuf": cfg_get("timeouts.ffuf", 180),
        "dirb_scan": cfg_get("timeouts.gobuster", 120),
        "gobuster": cfg_get("timeouts.gobuster", 120),
        "testssl": cfg_get("timeouts.testssl", 300),
        "sensitive_files_scan": cfg_get("timeouts.sensitive_files", 60),
        "sensitive_files": cfg_get("timeouts.sensitive_files", 60),
        "cors_scan": cfg_get("timeouts.cors", 60),
        "cors": cfg_get("timeouts.cors", 60),
        "xss_scan": cfg_get("timeouts.xss", 120),
        "xss": cfg_get("timeouts.xss", 120),
        "httpx_probe": cfg_get("timeouts.httpx", 120),
        "httpx": cfg_get("timeouts.httpx", 120),
        "ssl_cert_audit": cfg_get("timeouts.ssl_cert", 30),
        "ssl_cert": cfg_get("timeouts.ssl_cert", 30),
        "dns_security_audit": cfg_get("timeouts.dns_security", 30),
        "dns_security": cfg_get("timeouts.dns_security", 30),
        "security_txt_audit": cfg_get("timeouts.security_txt", 30),
        "security_txt": cfg_get("timeouts.security_txt", 30),
        "cookie_security_audit": cfg_get("timeouts.cookie_security", 30),
        "cookie_security": cfg_get("timeouts.cookie_security", 30),
        "http_headers_audit": cfg_get("timeouts.http_headers", 30),
        "http_headers": cfg_get("timeouts.http_headers", 30),
        "api_docs_audit": cfg_get("timeouts.api_docs", 60),
        "api_docs": cfg_get("timeouts.api_docs", 60),
        "subdomain_takeover_audit": cfg_get("timeouts.subdomain_takeover", 60),
        "subdomain_takeover": cfg_get("timeouts.subdomain_takeover", 60),
        "waf_detect": cfg_get("timeouts.waf_detect", 30),
    }
    base = timeout_map.get(clean_name, timeout_map.get(tool_name, 120))
    return float(base) + 15.0


DOCKER_DAEMON_ERROR_PATTERNS = [
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "error during connect",
    "docker daemon is not running",
    "docker is not running",
    "failed to connect to docker daemon",
    "daemon is not running",
]


def _is_docker_daemon_offline_error(text: str) -> bool:
    """Check if an error message or tool output indicates Docker daemon is unreachable."""
    if not text:
        return False
    lower = str(text).lower()
    return any(p in lower for p in DOCKER_DAEMON_ERROR_PATTERNS)


async def _retry_tool_call(session, tool_name: str, arguments: dict,
                           max_retries: int = 2, delay: float = 3.0,
                           timeout: float | None = None) -> str:
    """Call an MCP tool with automatic retry on failure and client-side timeout protection.

    Args:
        session: MCP ClientSession.
        tool_name: Name of the tool to call.
        arguments: Tool arguments dict.
        max_retries: Maximum number of retry attempts.
        delay: Delay in seconds between retries (doubles each attempt).
        timeout: Optional override for per-tool timeout (in seconds).

    Returns:
        Tool result as string.
    """
    call_timeout = timeout or _get_tool_timeout(tool_name)
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            tool_result = await asyncio.wait_for(
                session.call_tool(tool_name, arguments),
                timeout=call_timeout,
            )
            result_text_parts = [
                item.text if hasattr(item, "text") else str(item)
                for item in tool_result.content
            ]
            result_str = "\n".join(result_text_parts)

            # Fast abort on Docker daemon offline in tool output
            if _is_docker_daemon_offline_error(result_str):
                console.print(
                    f"[bold red]🐳 CẢNH BÁO DOCKER DAEMON: Không thể kết nối tới Docker Daemon khi gọi '{tool_name}'! "
                    f"Vui lòng kiểm tra Docker Desktop / daemon service đã khởi động chưa.[/bold red]"
                )
                return result_str

            return result_str
        except asyncio.TimeoutError:
            last_error = f"Tool execution timed out after {call_timeout:.0f}s"
            if attempt < max_retries:
                wait_time = delay * (2 ** attempt)
                console.print(
                    f"[bold yellow]⏱️ Tool '{tool_name}' timed out after {call_timeout:.0f}s (attempt {attempt + 1}/{max_retries + 1}). "
                    f"Retrying in {wait_time:.0f}s...[/bold yellow]"
                )
                await asyncio.sleep(wait_time)
            else:
                break
        except Exception as err:
            last_error = err
            err_str = str(err)
            # Fast abort on Docker daemon offline in exception
            if _is_docker_daemon_offline_error(err_str):
                console.print(
                    f"[bold red]🐳 CẢNH BÁO DOCKER DAEMON: Không thể kết nối tới Docker Daemon ({err_str})! "
                    f"Dừng retry công cụ '{tool_name}' để tiết kiệm thời gian vận hành.[/bold red]"
                )
                return f"Error executing tool '{tool_name}': Docker daemon is offline or unreachable. Details: {err_str}"

            if attempt < max_retries:
                wait_time = delay * (2 ** attempt)
                console.print(
                    f"[bold yellow]⚡ Tool '{tool_name}' failed (attempt {attempt + 1}/{max_retries + 1}). "
                    f"Retrying in {wait_time:.0f}s...[/bold yellow]"
                )
                await asyncio.sleep(wait_time)
            else:
                break

    return f"Error executing tool '{tool_name}' after {max_retries + 1} attempts: {last_error}"



# ---------------------------------------------------------------------------
# Real-time Reporter Agent — Dual-Agent Collaboration
# ---------------------------------------------------------------------------

_REPORTER_SKIP_TOOLS: set[str] | None = None


def _get_reporter_skip_tools() -> set[str]:
    """Load the set of tools that skip real-time reporter analysis."""
    global _REPORTER_SKIP_TOOLS
    if _REPORTER_SKIP_TOOLS is None:
        skip_list = cfg_get("reporter.skip_tools", ["docker_resolve_dns", "browse_webpage"])
        _REPORTER_SKIP_TOOLS = set(skip_list) if skip_list else set()
    return _REPORTER_SKIP_TOOLS


def _distill_tool_intelligence(tool_name: str, result_str: str) -> dict:
    """Extract distilled high-signal intelligence from raw tool outputs."""
    intel = {
        "ports": [],
        "open_ports": [],
        "parameterized_urls": [],
        "urls_with_params": [],
        "params": [],
        "cves": [],
        "technologies": [],
        "credentials": [],
        "summary": "",
    }
    if not result_str or not isinstance(result_str, str):
        return intel

    # Extract CVEs
    cves = list(set(_RE_CVE_PATTERN.findall(result_str)))
    intel["cves"] = [c.upper() for c in cves][:10]

    # Extract Ports
    ports = list(set(_RE_PORT_PATTERN.findall(result_str)))
    parsed_ports = [int(p) for p in ports if int(p) <= 65535][:15]
    intel["ports"] = parsed_ports
    intel["open_ports"] = parsed_ports

    # Extract Parameterized URLs and query parameter names
    urls = _RE_URL_PATTERN.findall(result_str)
    param_urls = [u for u in urls if "?" in u and "=" in u]
    intel["parameterized_urls"] = list(set(param_urls))[:10]
    intel["urls_with_params"] = intel["parameterized_urls"]

    param_names = set()
    for u in intel["parameterized_urls"]:
        if "?" in u:
            query = u.split("?", 1)[1]
            for part in query.split("&"):
                if "=" in part:
                    param_names.add(part.split("=", 1)[0])
    intel["params"] = sorted(param_names)

    # Extract credentials if found
    for ln in result_str.splitlines():
        ln_l = ln.strip().lower()
        if ("login:" in ln_l and "password:" in ln_l) or "valid password" in ln_l:
            if "0 valid" not in ln_l:
                intel["credentials"].append(ln.strip())

    # Build concise summary
    summary_parts = []
    if intel["cves"]:
        summary_parts.append(f"CVEs: {', '.join(intel['cves'][:3])}")
    if intel["ports"]:
        summary_parts.append(f"Cổng mở: {intel['ports'][:5]}")
    if intel["parameterized_urls"]:
        summary_parts.append(f"URLs tham số: {len(intel['parameterized_urls'])}")
    if intel["credentials"]:
        summary_parts.append(f"Credentials phát hiện: {len(intel['credentials'])}")

    # Lazy single-pass JSON parser to avoid repetitive json.loads and decode exception overhead
    parsed_json: dict | None = None
    json_attempted = False

    def _get_json() -> dict:
        nonlocal parsed_json, json_attempted
        if not json_attempted:
            json_attempted = True
            stripped = result_str.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    data = json.loads(stripped)
                    if isinstance(data, dict):
                        parsed_json = data
                except Exception:
                    pass
        return parsed_json or {}

    # 4 New Security Arsenal Tools Distillation
    if "docker_sensitive_files_scan" in tool_name or "sensitive_files" in tool_name:
        d = _get_json()
        exposed = d.get("exposed_files", [])
        if exposed:
            intel["exposed_files"] = [f.get("path") or f.get("url") for f in exposed]
            summary_parts.append(f"Lộ tệp tin nhạy cảm ({len(exposed)}): {', '.join(intel['exposed_files'][:3])}")

    if "docker_cors_scan" in tool_name or "cors" in tool_name:
        d = _get_json()
        cors_issues = d.get("cors_misconfigurations", [])
        if cors_issues:
            intel["cors_issues"] = [c.get("type", "CORS issue") for c in cors_issues]
            summary_parts.append(f"Lỗ hổng CORS ({len(cors_issues)}): {', '.join(intel['cors_issues'][:2])}")

    if "docker_xss_scan" in tool_name or "xss" in tool_name:
        d = _get_json()
        vuln_params = d.get("vulnerable_parameters", [])
        if vuln_params:
            intel["xss_params"] = [p.get("parameter") for p in vuln_params if p.get("parameter")]
            summary_parts.append(f"Lỗ hổng XSS phản xạ trên tham số: {', '.join(intel['xss_params'])}")

    if "docker_httpx_probe" in tool_name or "httpx" in tool_name:
        d = _get_json()
        alive = d.get("alive_targets", [])
        if alive:
            intel["alive_hosts"] = [a.get("url") or a.get("input_target") for a in alive]
            summary_parts.append(f"Máy chủ alive ({len(alive)}): {', '.join(intel['alive_hosts'][:3])}")

    if "docker_ssl_cert_audit" in tool_name or "ssl_cert" in tool_name:
        d = _get_json()
        if d:
            days = d.get("days_until_expiry")
            sans = d.get("subject_alternative_names", [])
            issues = d.get("issues", [])
            parts = []
            if days is not None:
                parts.append(f"hết hạn sau {days} ngày")
            if sans:
                parts.append(f"{len(sans)} SANs")
            if issues:
                parts.append(f"{len(issues)} vấn đề: {', '.join(issues[:2])}")
            summary_parts.append(f"Chứng chỉ SSL/TLS ({', '.join(parts) if parts else 'hợp lệ'})")

    if "docker_dns_security_audit" in tool_name or "dns_security" in tool_name:
        d = _get_json()
        if d:
            spf = d.get("spf", {}).get("status", "unknown")
            dmarc = d.get("dmarc", {}).get("status", "unknown")
            dnssec = "bật" if d.get("dnssec", {}).get("dnssec_enabled") else "tắt"
            sec_issues = d.get("security_issues", [])
            issue_str = f" ({len(sec_issues)} rủi ro)" if sec_issues else ""
            summary_parts.append(f"DNS/Email Security: SPF={spf}, DMARC={dmarc}, DNSSEC={dnssec}{issue_str}")

    if "docker_security_txt_audit" in tool_name or "security_txt" in tool_name:
        d = _get_json()
        if d:
            sec_found = "có" if d.get("security_txt", {}).get("found") else "không"
            disallowed = d.get("robots_txt", {}).get("disallow_rules_count", 0)
            hidden = d.get("interesting_paths_found", [])
            summary_parts.append(f"RFC 9116 / Robots: security.txt={sec_found}, robots rules={disallowed}, phát hiện {len(hidden)} đường dẫn ẩn")

    if "docker_cookie_security_audit" in tool_name or "cookie_security" in tool_name:
        d = _get_json()
        if d:
            total = d.get("total_cookies_found", 0)
            issues = d.get("issues", [])
            summary_parts.append(f"Cookie Security: {total} cookie ({len(issues)} cảnh báo an toàn)")

    if "docker_http_headers_audit" in tool_name or "http_headers" in tool_name:
        d = _get_json()
        if d:
            grade = d.get("grade", "N/A")
            score = d.get("score", 0)
            missing = d.get("missing_headers", [])
            leaks = d.get("information_leaks", [])
            summary_parts.append(f"HTTP Headers: Điểm {score}/100 (Hạng {grade}), thiếu {len(missing)} headers, lộ {len(leaks)} banner")

    if "docker_api_docs_audit" in tool_name or "api_docs" in tool_name:
        d = _get_json()
        if d:
            exposed = d.get("exposed_docs", [])
            if exposed:
                endpoints_total = sum(doc.get("endpoints_count", 0) for doc in exposed)
                summary_parts.append(f"API Docs Exposed: Phát hiện {len(exposed)} tài liệu API ({endpoints_total} endpoints)")
            else:
                summary_parts.append("API Docs: Không phát hiện Swagger/OpenAPI/GraphQL public")

    if "docker_subdomain_takeover_audit" in tool_name or "subdomain_takeover" in tool_name:
        d = _get_json()
        if d:
            vulns = d.get("vulnerabilities", [])
            audited = d.get("total_subdomains_audited", 0)
            if vulns:
                summary_parts.append(f"Subdomain Takeover: NGUY HIỂM! Phát hiện {len(vulns)} tên miền phụ có nguy cơ bị chiếm đoạt")
            else:
                summary_parts.append(f"Subdomain Takeover: Đã kiểm toán {audited} CNAME, không phát hiện dangling pointer")

    if "docker_waf_detect" in tool_name or "waf_detect" in tool_name or "waf" in tool_name:
        d = _get_json()
        if d:
            if d.get("waf_detected"):
                waf = d.get("primary_waf", "WAF")
                summary_parts.append(f"WAF Detection: Mục tiêu được bảo vệ bởi {waf} (kích hoạt chế độ né tránh)")
            else:
                summary_parts.append("WAF Detection: Không phát hiện WAF/CDN bảo vệ trực tiếp")

    intel["summary"] = " | ".join(summary_parts) if summary_parts else "Không có dấu hiệu đặc biệt."
    return intel



def _filter_hallucinated_findings(findings_data: list[dict], tool_name: str, tool_result: str) -> list[dict]:
    """Post-validation guard to filter out fabricated or hallucinated findings from 3B Reporter.

    Rules:
    1. If tool is 'docker_bruteforce' or result indicates 'capability_check_only',
       NO findings can be generated (it is a health check only).
    2. If tool execution failed, timed out, or returned an error, discard all findings.
    3. If tool result states 'NO_CREDENTIALS_FOUND' or '0 valid passwords found',
       discard any finding claiming credentials, weak passwords, or login access.
    4. If tool result states 'No critical/high findings', discard CRITICAL/HIGH findings.
    5. Discard findings with empty titles or missing descriptions.
    """
    if not findings_data:
        return []

    # 1. Capability check / health check only
    if tool_name == "docker_bruteforce" or "capability_check_only" in tool_result or "health_check_only" in tool_result:
        return []

    # 2. Tool failed or errored out
    lower_res = tool_result.lower()
    if any(err_kw in lower_res for err_kw in [
        '"error":', "timed out", "timeout expired", "connection refused", "failed:"
    ]) and len(lower_res) < 300:
        return []

    valid_findings = []
    # Negative flags in tool result
    no_creds = "no_credentials_found" in lower_res or "0 valid password" in lower_res
    no_vulns = "no critical/high findings" in lower_res or "0 vulnerable" in lower_res

    for f in findings_data:
        if not isinstance(f, dict):
            continue
        title = (f.get("title") or "").strip()
        if not title:
            continue
        severity = (f.get("severity") or "INFO").upper()

        lower_title = title.lower()
        lower_desc = (f.get("description") or "").lower()

        # Guard against hallucinated credentials when bruteforce found nothing
        if no_creds and any(kw in lower_title or kw in lower_desc for kw in [
            "mật khẩu", "password", "đăng nhập thành công", "credentials", "tài khoản", "không được bảo vệ"
        ]):
            continue

        # Guard against high/critical findings when tool found nothing
        if no_vulns and severity in ("CRITICAL", "HIGH"):
            continue

        valid_findings.append(f)

    return valid_findings


async def _invoke_reporter_realtime(
    client: AsyncOpenAI,
    report_state: ReportState,
    latest_tool: str,
    latest_args: dict,
    latest_result: str,
    iteration: int,
    distilled_summary: str = "",
) -> dict:
    """Call Reporter (3B) after each tool result for real-time analysis.

    The Reporter observes the latest tool output, identifies new findings,
    assesses severity, and suggests next steps for the Red Teamer.

    Args:
        client: AsyncOpenAI client.
        report_state: Current accumulated report state.
        latest_tool: Name of the tool just executed.
        latest_args: Arguments passed to the tool.
        latest_result: Raw tool output (truncated for prompt).
        iteration: Current iteration number.
        distilled_summary: Distilled key intelligence summary.

    Returns:
        Dict with keys: new_findings, risk_score, suggestion, step_comment.
        Empty dict on failure/timeout.
    """
    reporter_model = cfg_get("reporter.model", "huihui_ai/qwen3.5-abliterated:2B")
    reporter_temp = cfg_get("reporter.temperature", 0.3)
    rt_timeout = cfg_get("reporter.realtime_timeout", 30)

    # Build the current state summary for context
    current_summary = report_state.get_current_summary()

    intel_line = f"- Tình báo then chốt: {distilled_summary}\n" if distilled_summary and distilled_summary != "Không có dấu hiệu đặc biệt." else ""

    prompt = f"""/nothink
Bạn là SOC Analyst quan sát cuộc pentest REAL-TIME, đóng vai trò CỐ VẤN CHIẾN LƯỢC TỐI CAO cùng Red Teamer nỗ lực cao nhất để hoàn thành mục tiêu.

TRẠNG THÁI HIỆN TẠI & MỤC TIÊU:
{current_summary}

BƯỚC VỪA THỰC HIỆN (Bước {iteration}):
- Tool: {latest_tool}
- Tham số: {json.dumps(latest_args, ensure_ascii=False)[:300]}
{intel_line}- Kết quả: {latest_result[:1400]}

NHIỆM VỤ CHIẾN LƯỢC:
1. Phân tích kết quả thực tế để phát hiện các lỗ hổng có bằng chứng trực tiếp.
2. Đánh giá xem bước này đã giúp tiến gần tới MỤC TIÊU CỐT LÕI hay chưa.
3. Đưa ra GỢI Ý CHIẾN THUẬT QUYẾT LIỆT NHẤT (suggestion_for_redteam): Chỉ dẫn cụ thể công cụ kế tiếp và tham số tối ưu để Red Teamer tiếp tục tấn công mạnh mẽ vào mục tiêu. Nếu Red Teamer bế tắc, hãy hướng dẫn đổi vector tấn công khả thi nhất!

Trả về JSON duy nhất (KHÔNG có text ngoài JSON):
```json
{{
  "new_findings": [
    {{
      "title": "Tên lỗ hổng/phát hiện ngắn gọn",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "Mô tả chi tiết phát hiện",
      "impact": "Tác động tiềm tàng",
      "remediation": "Cách khắc phục",
      "cve_id": "CVE-XXXX-YYYY (nếu có)",
      "cvss_score": 0.0
    }}
  ],
  "risk_score": 0.0,
  "objective_assessment": "Đánh giá tiến độ hoàn thành mục tiêu (Chưa đạt / Đang tiến triển tốt / Đã hoàn thành)",
  "blocking_factor": "Yếu tố cản trở chính hiện tại nếu chưa đạt được mục tiêu",
  "suggestion_for_redteam": "Gợi ý chiến thuật cụ thể để Red Teamer tiến gần mục tiêu nhất",
  "step_comment": "Nhận xét ngắn về kết quả bước này đối với mục tiêu",
  "attack_pattern": {{
    "should_store": true,
    "metadata": {{
      "cwe_id": "CWE-89",
      "vuln_category": "Time-based Blind SQLi",
      "tech_stack": ["mysql", "php", "nginx"],
      "waf": "cloudflare",
      "severity": "CRITICAL"
    }},
    "context": {{
      "entry_point": "Mô tả điểm vào tấn công cụ thể",
      "defense_behavior": "Server chặn các từ khóa ..., trả về HTTP 403",
      "agent_reasoning": "Lý do chiến thuật tại sao chọn cách thức hoặc tamper này",
      "preconditions": "Điều kiện tiên quyết để vector hoạt động"
    }},
    "successful_vector": {{
      "tool_used": "{latest_tool}",
      "tool_args_key": "--tamper=space2comment",
      "raw_payload_example": "payload nếu nhìn thấy trong output",
      "outcome": "Kết quả thực tế đạt được"
    }}
  }}
}}
```

QUY TẮC NGHIÊM NGẶT:
- new_findings: CHỈ thêm phát hiện MỚI có BẰNG CHỨNG TRỰC TIẾP từ kết quả tool ở trên
- TUYỆT ĐỐI KHÔNG được bịa/suy đoán lỗ hổng không có trong kết quả tool
- Nếu tool output chứa "(OK)" hoặc "not offered (OK)" → đó là AN TOÀN, KHÔNG phải lỗ hổng
- Nếu tool trả về error/unknown/empty → KHÔNG tạo finding, chỉ ghi step_comment và hướng dẫn đổi hướng
- risk_score: Đánh giá rủi ro tổng thể 0-10 (dựa trên TẤT CẢ findings đã xác nhận)
- suggestion_for_redteam: Gợi ý cụ thể tool/hành động tiếp theo (phải là tool có trong danh sách) nhằm tối đa hóa nỗ lực đạt mục tiêu
- NHIỆM VỤ SỔ TAY RED TEAM (ATTACK PATTERN MEMORY):
  Khi tool thực thi THÀNH CÔNG và phát hiện lỗ hổng/thông tin xâm nhập quan trọng hoặc kỹ thuật bypass WAF, bạn PHẢI tóm tắt kịch bản vào attack_pattern:
  * should_store: true (CHỈ đặt true khi có phát hiện đáng giá hoặc bypass thành công; đặt false nếu tool không tìm ra gì mới hoặc thất bại)
  * metadata: cwe_id, vuln_category, tech_stack (danh sách công nghệ), waf (nếu phát hiện), severity
  * context: entry_point (điểm vào), defense_behavior (phản ứng/phòng thủ của server), agent_reasoning (lý do chọn chiến thuật)
  * successful_vector: tool_used, tool_args_key, raw_payload_example, outcome
- Nếu không có phát hiện mới, trả new_findings = [] và attack_pattern.should_store = false
- Viết bằng Tiếng Việt"""

    try:
        call_kwargs = {
            "model": reporter_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": reporter_temp,
            "response_format": {"type": "json_object"},
        }
        reporter_options = {
            "num_ctx": int(cfg_get("reporter.num_ctx", 8192)),
            "num_predict": int(cfg_get("reporter.num_predict", 2048)),
        }
        num_gpu = cfg_get("reporter.num_gpu", cfg_get("llm.num_gpu"))
        if num_gpu is not None:
            reporter_options["num_gpu"] = int(num_gpu)

        call_kwargs["extra_body"] = {
            "options": reporter_options,
            "reasoning_effort": "none",
            "keep_alive": cfg_get("reporter.keep_alive", cfg_get("llm.keep_alive", "15m")),
        }

        response = await asyncio.wait_for(
            client.chat.completions.create(**call_kwargs),
            timeout=rt_timeout,
        )
        msg = response.choices[0].message
        content = msg.content or getattr(msg, "reasoning", None) or getattr(msg, "reasoning_content", None) or ""
        # Strip thinking tags from reporter output
        content_clean = _clean_thinking_tags(content)
        if content_clean:
            content = content_clean

        # Parse reporter's JSON response with heuristic fallback
        try:
            parsed = _extract_json(content)
        except Exception as json_err:
            logger.debug("Reporter JSON parse failed, trying heuristic fallback: %s", json_err)
            parsed = _extract_reporter_fallback(content)

        if not parsed:
            return {}

        return {
            "new_findings": parsed.get("new_findings", []),
            "risk_score": float(parsed.get("risk_score", 0)),
            "suggestion": parsed.get("suggestion_for_redteam", "") or parsed.get("suggestion", ""),
            "step_comment": parsed.get("step_comment", ""),
            "objective_assessment": parsed.get("objective_assessment", ""),
            "blocking_factor": parsed.get("blocking_factor", ""),
            "attack_pattern": parsed.get("attack_pattern", {}),
        }


    except asyncio.TimeoutError:
        console.print(f"[dim]⏱️ Reporter timeout ({rt_timeout}s) — bỏ qua bước này[/dim]")
        return {}
    except Exception as e:
        console.print(f"[dim]⚠️ Reporter error: {e} — bỏ qua[/dim]")
        return {}


async def _reporter_final_polish(
    client: AsyncOpenAI,
    report_state: ReportState,
) -> None:
    """Final polish pass: Reporter writes executive summary and conclusion.

    Called once after the Red Teamer finishes. Uses the accumulated
    ReportState to write cohesive summary and conclusion sections.

    Args:
        client: AsyncOpenAI client.
        report_state: Complete accumulated report state.
    """
    reporter_model = cfg_get("reporter.model", "huihui_ai/qwen3.5-abliterated:2B")
    reporter_temp = cfg_get("reporter.temperature", 0.3)
    reporter_timeout = cfg_get("reporter.timeout_seconds", 120)

    if not cfg_get("reporter.enabled", True):
        console.print("[dim]Reporter Agent disabled. Skipping final polish.[/dim]")
        return

    console.print(
        Panel.fit(
            f"[bold cyan]Agent 2 (SOC Reporter) — Final Polish[/bold cyan]\n"
            f"[dim]Model:[/dim] {reporter_model} | "
            f"[dim]Findings:[/dim] {len(report_state.findings)} | "
            f"[dim]Risk:[/dim] {report_state.risk_score}/10",
            title="[bold cyan]🔄 FINAL POLISH[/bold cyan]",
            border_style="cyan",
        )
    )

    # Build findings summary for prompt
    findings_text = ""
    if report_state.findings:
        for i, f in enumerate(report_state.findings, 1):
            findings_text += (
                f"\n{i}. [{f.severity}] {f.title}\n"
                f"   Mô tả: {f.description}\n"
                f"   Tác động: {f.impact}\n"
                f"   Tool: {f.tool_source}\n"
            )
    else:
        findings_text = "Không có lỗ hổng nào được phát hiện."

    # Methodology summary
    method_text = ""
    for s in report_state.methodology:
        status_icon = "✅" if s.status == "SUCCESS" else "❌"
        method_text += f"  {s.step_number}. {status_icon} {s.tool_name} — {s.reporter_comment[:80]}\n"

    mission_prompt_block = f"\nMỤC TIÊU SỨ MỆNH ĐÃ ĐẶT RA: {report_state.mission_objective}" if report_state.mission_objective else ""

    prompt = f"""/nothink
Bạn là Chuyên gia An toàn thông tin cấp cao. Viết phần TÓM TẮT ĐIỀU HÀNH và KẾT LUẬN cho báo cáo pentest.
{mission_prompt_block}
MỤC TIÊU ĐÁNH GIÁ: {report_state.target}
CHẾ ĐỘ: {report_state.scan_mode.upper()}
THỜI GIAN: {report_state.start_time.strftime('%d/%m/%Y %H:%M')} → {datetime.now().strftime('%H:%M')}
RISK SCORE: {report_state.risk_score}/10

CÁC BƯỚC ĐÃ THỰC HIỆN ({len(report_state.methodology)} bước):
{method_text}

CÁC PHÁT HIỆN ({len(report_state.findings)} findings):
{findings_text}

KẾT LUẬN RED TEAMER:
{report_state.red_teamer_final_answer[:1000]}

Trả về JSON (KHÔNG text ngoài JSON):
```json
{{
  "executive_summary": "Tóm tắt điều hành 3-5 câu, trang trọng, chuẩn doanh nghiệp",
  "conclusion": "Kết luận chi tiết: đánh giá tổng thể, nhận xét cuối cùng, đề xuất ưu tiên",
  "recommendations": ["Khuyến nghị 1 cụ thể", "Khuyến nghị 2", "..."]
}}
```"""

    try:
        call_kwargs = {
            "model": reporter_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": reporter_temp,
            "response_format": {"type": "json_object"},
        }
        reporter_options = {
            "num_ctx": int(cfg_get("reporter.num_ctx", 8192)),
            "num_predict": int(cfg_get("reporter.num_predict", 2048)),
        }
        num_gpu = cfg_get("reporter.num_gpu", cfg_get("llm.num_gpu"))
        if num_gpu is not None:
            reporter_options["num_gpu"] = int(num_gpu)

        call_kwargs["extra_body"] = {
            "options": reporter_options,
            "reasoning_effort": "none",
            "keep_alive": cfg_get("reporter.keep_alive", cfg_get("llm.keep_alive", "15m")),
        }

        response = await asyncio.wait_for(
            client.chat.completions.create(**call_kwargs),
            timeout=reporter_timeout,
        )
        msg = response.choices[0].message
        content = msg.content or getattr(msg, "reasoning", None) or getattr(msg, "reasoning_content", None) or ""
        # Strip thinking tags
        content_clean = _clean_thinking_tags(content)
        if content_clean:
            content = content_clean

        try:
            parsed = _extract_json(content)
        except Exception:
            parsed = {}
            ex_m = re.search(r'"executive_summary"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
            conc_m = re.search(r'"conclusion"\s*:\s*"((?:[^"\\]|\\.)*)"', content)
            if ex_m:
                parsed["executive_summary"] = ex_m.group(1).replace(r'\"', '"').replace(r'\n', ' ')
            if conc_m:
                parsed["conclusion"] = conc_m.group(1).replace(r'\"', '"').replace(r'\n', ' ')

        report_state.executive_summary = parsed.get("executive_summary", "")
        report_state.conclusion = parsed.get("conclusion", "")
        for rec in parsed.get("recommendations", []):
            report_state.add_recommendation(rec)

        console.print("[bold green]✅ Final polish hoàn tất.[/bold green]")

    except asyncio.TimeoutError:
        console.print(f"[bold yellow]⚠️ Final polish timeout ({reporter_timeout}s).[/bold yellow]")
    except Exception as e:
        console.print(f"[bold yellow]⚠️ Final polish error: {e}[/bold yellow]")




# ---------------------------------------------------------------------------
# Tool Name Fuzzy Matching — Auto-correct AI-generated tool names
# ---------------------------------------------------------------------------

def _fuzzy_match_tool_name(tool_name: str, tools_schema: list) -> str:
    """Auto-correct tool names when the AI uses a slightly wrong name.

    Handles:
    - Aliases (e.g. docker_bruteforce_http_form -> bruteforce_http_form)
    - Stripping/adding 'docker_' prefixes
    - Difflib similarity matching
    - Length-difference-aware substring matching
    """
    if not tool_name:
        return tool_name

    available_names = [t["name"] for t in tools_schema]

    # Exact match
    if tool_name in available_names:
        return tool_name

    # Static aliases for common mistakes
    TOOL_ALIASES = {
        # Brute-force aliases (critical fix)
        "docker_bruteforce_http_form": "bruteforce_http_form",
        "docker_bruteforce_ssh": "bruteforce_ssh",
        "docker_hydra_http_form": "bruteforce_http_form",
        "docker_hydra_ssh": "bruteforce_ssh",
        "hydra_http_form": "bruteforce_http_form",
        "hydra_ssh": "bruteforce_ssh",
        "bruteforce": "docker_bruteforce",
        "docker_brute_force": "docker_bruteforce",
        "docker_brute": "docker_bruteforce",
        "docker_hydra": "docker_bruteforce",
        "hydra": "docker_bruteforce",
        # Recon & Web aliases
        "docker_nikto": "docker_nikto_scan",
        "docker_nuclei": "docker_nuclei_scan",
        "docker_sublist3r": "docker_subfinder",
        "docker_sublister": "docker_subfinder",
        "docker_curl": "browse_webpage",
        "docker_wget": "browse_webpage",
        "docker_httpx": "docker_httpx_probe",
        "httpx": "docker_httpx_probe",
        "httpx_probe": "docker_httpx_probe",
        "probe_subdomains": "docker_httpx_probe",
        "sensitive_files": "docker_sensitive_files_scan",
        "docker_sensitive_files": "docker_sensitive_files_scan",
        "docker_sensitive_scan": "docker_sensitive_files_scan",
        "sensitive_scan": "docker_sensitive_files_scan",
        "cors": "docker_cors_scan",
        "cors_scan": "docker_cors_scan",
        "docker_cors": "docker_cors_scan",
        "xss": "docker_xss_scan",
        "xss_scan": "docker_xss_scan",
        "docker_xss": "docker_xss_scan",
        "docker_xss_fuzz": "docker_xss_scan",
        "docker_crawl": "docker_crawl_web",
        "crawl_web": "docker_crawl_web",
        "crawl": "docker_crawl_web",
        "docker_scan_ports": "docker_scan_ports_fast",
        "docker_nmap": "docker_scan_ports_deep",
        "docker_sqlmap": "docker_sqlmap_scan",
        "docker_wfuzz": "docker_ffuf",
        "docker_gobuster": "docker_dirb_scan",
        "docker_dirsearch": "docker_dirb_scan",
        "scan_ports": "docker_scan_ports_fast",
        "resolve_dns": "docker_resolve_dns",
        "whatweb": "docker_whatweb",
        "nikto": "docker_nikto_scan",
        "nuclei": "docker_nuclei_scan",
        "dirb": "docker_dirb_scan",
        "subfinder": "docker_subfinder",
        "ffuf": "docker_ffuf",
        "testssl": "docker_testssl",
        "wpscan": "docker_wpscan",
        "msf_search": "docker_msf_search",
        "msfconsole": "docker_msf_search",
        "metasploit": "docker_msf_search",
        # SSL / TLS cert audit aliases
        "ssl_cert": "docker_ssl_cert_audit",
        "ssl_cert_audit": "docker_ssl_cert_audit",
        "docker_ssl_cert": "docker_ssl_cert_audit",
        "ssl_audit": "docker_ssl_cert_audit",
        "cert_audit": "docker_ssl_cert_audit",
        "certificate_audit": "docker_ssl_cert_audit",
        # DNS security / email security aliases
        "dns_security": "docker_dns_security_audit",
        "dns_security_audit": "docker_dns_security_audit",
        "docker_dns_security": "docker_dns_security_audit",
        "dns_audit": "docker_dns_security_audit",
        "spf_audit": "docker_dns_security_audit",
        "dmarc_audit": "docker_dns_security_audit",
        "dnssec_audit": "docker_dns_security_audit",
        # RFC 9116 / robots.txt / sitemap aliases
        "security_txt": "docker_security_txt_audit",
        "security_txt_audit": "docker_security_txt_audit",
        "docker_security_txt": "docker_security_txt_audit",
        "robots_txt": "docker_security_txt_audit",
        "robots_scan": "docker_security_txt_audit",
        "sitemap_scan": "docker_security_txt_audit",
        "sitemap_audit": "docker_security_txt_audit",
        # Cookie security aliases
        "cookie_security": "docker_cookie_security_audit",
        "cookie_security_audit": "docker_cookie_security_audit",
        "docker_cookie_security": "docker_cookie_security_audit",
        "cookie_audit": "docker_cookie_security_audit",
        "cookies_audit": "docker_cookie_security_audit",
        "cookie_scan": "docker_cookie_security_audit",
        # HTTP Security Headers & Server Banner aliases
        "http_headers": "docker_http_headers_audit",
        "http_headers_audit": "docker_http_headers_audit",
        "headers_audit": "docker_http_headers_audit",
        "security_headers": "docker_http_headers_audit",
        "docker_http_headers": "docker_http_headers_audit",
        "docker_headers": "docker_http_headers_audit",
        "headers": "docker_http_headers_audit",
        # API Docs / OpenAPI / Swagger / GraphQL aliases
        "api_docs": "docker_api_docs_audit",
        "api_docs_audit": "docker_api_docs_audit",
        "swagger": "docker_api_docs_audit",
        "swagger_scan": "docker_api_docs_audit",
        "openapi": "docker_api_docs_audit",
        "openapi_scan": "docker_api_docs_audit",
        "graphql_audit": "docker_api_docs_audit",
        "docker_api_docs": "docker_api_docs_audit",
        "docker_swagger": "docker_api_docs_audit",
        "docker_openapi": "docker_api_docs_audit",
        # Subdomain Takeover / Dangling CNAME aliases
        "subdomain_takeover": "docker_subdomain_takeover_audit",
        "subdomain_takeover_audit": "docker_subdomain_takeover_audit",
        "takeover_audit": "docker_subdomain_takeover_audit",
        "takeover": "docker_subdomain_takeover_audit",
        "docker_subdomain_takeover": "docker_subdomain_takeover_audit",
        "cname_audit": "docker_subdomain_takeover_audit",
        # WAF / CDN Detection aliases
        "waf_detect": "docker_waf_detect",
        "waf": "docker_waf_detect",
        "waf_detection": "docker_waf_detect",
        "docker_waf": "docker_waf_detect",
        "detect_waf": "docker_waf_detect",
    }


    if tool_name in TOOL_ALIASES:
        corrected = TOOL_ALIASES[tool_name]
        if corrected in available_names:
            console.print(
                f"[dim]🔄 Auto-corrected tool: '{tool_name}' → '{corrected}'[/dim]"
            )
            return corrected

    # Try removing 'docker_' prefix if tool name without prefix exists in schema
    # (e.g. 'docker_bruteforce_http_form' -> 'bruteforce_http_form')
    if tool_name.startswith("docker_"):
        stripped = tool_name[7:]
        if stripped in available_names:
            console.print(
                f"[dim]🔄 Auto-corrected tool (stripped prefix): '{tool_name}' → '{stripped}'[/dim]"
            )
            return stripped

    # Try adding 'docker_' prefix if it exists in schema
    # (e.g. 'dirb_scan' -> 'docker_dirb_scan')
    prefixed = f"docker_{tool_name}"
    if prefixed in available_names:
        console.print(
            f"[dim]🔄 Auto-corrected tool (added prefix): '{tool_name}' → '{prefixed}'[/dim]"
        )
        return prefixed

    # Difflib close matches (best semantic closeness)
    close_matches = difflib.get_close_matches(tool_name, available_names, n=1, cutoff=0.7)
    if close_matches:
        matched = close_matches[0]
        console.print(
            f"[dim]🔄 Fuzzy-matched tool (difflib): '{tool_name}' → '{matched}'[/dim]"
        )
        return matched

    # Fallback substring match: choose candidate with lowest length difference
    candidates = [
        name for name in available_names
        if tool_name in name or name in tool_name
    ]
    if candidates:
        best_candidate = min(candidates, key=lambda c: abs(len(c) - len(tool_name)))
        console.print(
            f"[dim]🔄 Fuzzy-matched tool (substring): '{tool_name}' → '{best_candidate}'[/dim]"
        )
        return best_candidate

    # No match found — return as-is, will produce "Unknown tool" error
    return tool_name





# ---------------------------------------------------------------------------
# Cold Ingestion & Memory Consolidation Helper
# ---------------------------------------------------------------------------

def _cold_ingest_assessment_playbook(vector_memory: Any, report_state: ReportState, vectordb_cfg: dict | None = None) -> None:
    """Package and store full-assessment kill chain playbook into Vector DB and record in report_state."""
    if not vector_memory:
        return
    try:
        confirmed_cwes = [f.cve_id for f in report_state.findings if f.cve_id]
        cwe_primary = confirmed_cwes[0] if confirmed_cwes else "CWE-FULL-ASSESSMENT"
        tech_list = list(report_state.attack_surface.detected_technologies)
        waf_detected = report_state.attack_surface.detected_waf.get("primary_waf", "None") if report_state.attack_surface.detected_waf else "None"

        # Successful tool chain
        successful_tools = [s.tool_name for s in report_state.methodology if s.status == "SUCCESS"]
        tool_chain_str = " -> ".join(successful_tools[:8]) if successful_tools else "Reconnaissance & Vulnerability Assessment"

        reasoning = (
            report_state.executive_summary[:300]
            or f"Chiến dịch thẩm định an toàn thông tin trên mục tiêu {report_state.target} ghi nhận {len(report_state.findings)} phát hiện với điểm rủi ro {report_state.risk_score}/10."
        )

        playbook_data = {
            "cwe_id": cwe_primary,
            "target": report_state.target,
            "entry_point": report_state.target,
            "agent_reasoning": reasoning,
            "metadata": {
                "cwe_id": cwe_primary,
                "tech_stack": tech_list[:5],
                "waf": waf_detected,
                "findings_count": len(report_state.findings),
                "risk_score": report_state.risk_score,
                "scan_mode": report_state.scan_mode,
                "is_full_playbook": True,
            },
            "context": {
                "entry_point": report_state.target,
                "defense_behavior": f"WAF: {waf_detected} | Target Type: Web Application",
                "agent_reasoning": reasoning,
                "preconditions": f"Technologies detected: {', '.join(tech_list[:5]) or 'Standard web'}",
            },
            "successful_vector": {
                "tool_used": successful_tools[0] if successful_tools else "killchain_playbook",
                "tool_args_key": tool_chain_str,
                "raw_payload_example": f"Full Kill Chain: {tool_chain_str}",
                "outcome": f"Phát hiện {len(report_state.findings)} lỗ hổng, rủi ro {report_state.risk_score}/10",
            },
        }

        stored_id = vector_memory.store_attack_pattern(playbook_data)
        if stored_id:
            report_state.record_rag_stored_pattern(playbook_data, stored_id)
            logger.info("Cold-ingested full assessment playbook: %s", stored_id)
            console.print(f"[dim green]🧠 Đã đóng gói Sổ tay Toàn diện lưu vào Trí nhớ Dài hạn: {stored_id}[/dim green]")

        # Check auto-consolidation threshold
        auto_threshold = int(vectordb_cfg.get("auto_trigger_threshold", 1000)) if vectordb_cfg else 1000
        if hasattr(vector_memory, "patterns_coll") and vector_memory.patterns_coll:
            count = vector_memory.patterns_coll.count()
            if count >= auto_threshold:
                console.print("[dim cyan]🧠 Số lượng kịch bản đạt ngưỡng tự động gom cụm — Đang nén bộ nhớ...[/dim cyan]")
                c_stats = vector_memory.consolidate_memory(similarity_threshold=0.88)
                clusters = c_stats.get("clusters_found", 0)
                console.print(f"[dim green]🧠 Tự động nén bộ nhớ hoàn tất (đã gom {clusters} cụm)[/dim green]")
    except Exception as e:
        logger.debug("Failed to cold-ingest assessment playbook: %s", e)


# ---------------------------------------------------------------------------
# Report Export Helper (DOCX, Markdown, JSON)
# ---------------------------------------------------------------------------

def _export_all_reports(report_state: ReportState, audit_path: str, target_raw_str: str) -> str:
    """Export assessment reports in DOCX, Markdown, and JSON formats."""
    report_path = ""
    if cfg_get("reports.generate_word", True):
        try:
            console.print("[bold yellow][*] Generating DOCX Report...[/bold yellow]")
            report_path = generate_docx_report(report_state.to_dict(), audit_path)
            console.print(f"[bold green][+] DOCX Report: {report_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]⚠️ Lỗi tạo báo cáo DOCX: {e}[/bold red]")

    report_dir = cfg_get("reports.output_dir", "reports")
    os.makedirs(report_dir, exist_ok=True)
    extracted_domain = "TARGET"
    url_match = _RE_DOMAIN_EXTRACT.search(target_raw_str)
    if url_match:
        extracted_domain = url_match.group(1)
    safe_target = _RE_SAFE_FILENAME.sub('_', extracted_domain)[:50]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    md_path = os.path.normpath(os.path.join(report_dir, f"Pentest_Report_{safe_target}_{ts}.md"))
    json_path = os.path.normpath(os.path.join(report_dir, f"Pentest_Report_{safe_target}_{ts}.json"))

    if cfg_get("reports.generate_markdown", True):
        try:
            report_state.export_markdown(md_path)
            console.print(f"[bold green][+] Markdown Report: {md_path}[/bold green]")
        except Exception as exp_err:
            console.print(f"[dim]Note: Markdown export notice: {exp_err}[/dim]")

    if cfg_get("reports.generate_json", True):
        try:
            report_state.export_json(json_path)
            console.print(f"[bold green][+] JSON State: {json_path}[/bold green]")
        except Exception as exp_err:
            console.print(f"[dim]Note: JSON export notice: {exp_err}[/dim]")

    html_path = os.path.normpath(os.path.join(report_dir, f"Pentest_Report_{safe_target}_{ts}.html"))
    if cfg_get("reports.generate_html", True):
        try:
            from src.utils.html_report_generator import generate_html_report
            generate_html_report(report_state.to_dict(), html_path)
            console.print(f"[bold green][+] Interactive Cyber Dashboard (HTML): {html_path}[/bold green]")
        except Exception as html_err:
            console.print(f"[dim]Note: HTML export notice: {html_err}[/dim]")

    # Terminal Full-Spectrum Summary Table
    counts = report_state.get_severity_counts()
    progress = report_state.calculate_goal_progress()
    risk_label = report_state.get_overall_risk_label()
    risk_score = report_state.risk_score

    summary_table = Table(title="🛡️ TỔNG KẾT BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN TOÀN DIỆN", style="bold cyan")
    summary_table.add_column("Chỉ số Đánh giá", style="bold white", width=28)
    summary_table.add_column("Kết quả Ghi nhận", style="bold green", width=54)

    summary_table.add_row("Mục tiêu (Target)", target_raw_str)
    completed_milestones = sum(1 for m in report_state.milestones if m.status == 'COMPLETED')
    total_milestones = len(report_state.milestones)
    summary_table.add_row("Tiến độ Sứ mệnh (Goal Progress)", f"{progress}% [Cột mốc: {completed_milestones}/{total_milestones} hoàn tất]")
    summary_table.add_row("Chỉ số Rủi ro (Risk Score)", f"{risk_score:.1f}/10 ({risk_label})")
    summary_table.add_row("Tổng số Phát hiện (Findings)", f"{len(report_state.findings)} (CRIT: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, MED: {counts['MEDIUM']}, LOW: {counts['LOW']}, INFO: {counts['INFO']})")
    summary_table.add_row("Tổng số Bước Thực thi (Kill Chain)", f"{len(report_state.methodology)} bước công cụ")

    # Threat Modeling & Bayesian Attack Graph summary rows
    try:
        crit_path = report_state.generate_attack_graph().get_critical_path()
        if crit_path:
            summary_table.add_row("Đường dẫn Nguy hiểm nhất", crit_path.to_summary())
    except Exception:
        pass

    mitre_count = len(report_state.get_mitre_breakdown())
    if mitre_count > 0:
        summary_table.add_row("Khung MITRE ATT&CK", f"{mitre_count} kỹ thuật chiến thuật đã ánh xạ")

    if report_path:
        summary_table.add_row("Báo cáo Word (DOCX)", f"[bold link=file:///{os.path.abspath(report_path)}]{report_path}[/bold link]")
    summary_table.add_row("Báo cáo Kỹ thuật (Markdown)", f"[bold link=file:///{os.path.abspath(md_path)}]{md_path}[/bold link]")
    summary_table.add_row("Dữ liệu Máy đọc (JSON)", f"[bold link=file:///{os.path.abspath(json_path)}]{json_path}[/bold link]")
    if audit_path and os.path.exists(audit_path):
        summary_table.add_row("Nhật ký Kiểm toán (Audit Trail)", f"[bold link=file:///{os.path.abspath(audit_path)}]{audit_path}[/bold link]")

    console.print("")
    console.print(summary_table)
    console.print("")

    if not report_path:
        report_path = md_path
    return report_path


def _resolve_tactical_pivot(tool_name: str, result_str: str, report_state: "ReportState") -> Optional[dict]:
    """Analyze tool execution output to identify obstacles (WAF, 403, 0 endpoints, filtered ports)
    and dynamically prescribe an adaptive tactical pivot action.
    """
    if not result_str or not isinstance(result_str, str):
        return None

    res_lower = result_str.lower()
    tested_tools = set(s.tool_name for s in report_state.methodology)

    # 1. 403 Forbidden / WAF / Cloudflare Obstacle Detection
    if any(sig in res_lower for sig in ["403 forbidden", "access denied", "cloudflare", "waf block", "request blocked"]):
        if "docker_security_txt_audit" not in tested_tools:
            return {
                "obstacle": "Phát hiện mã 403 / Cơ chế phòng vệ WAF",
                "pivot_tool": "docker_security_txt_audit",
                "reason": "Mục tiêu chặn truy cập trực tiếp. Chuyển sang đọc RFC 9116 / robots.txt / sitemap.xml để tìm các đường dẫn nội bộ được cho phép hoặc bị bỏ quên.",
            }
        elif "docker_dns_security_audit" not in tested_tools:
            return {
                "obstacle": "Phát hiện mã 403 / Cơ chế phòng vệ WAF",
                "pivot_tool": "docker_dns_security_audit",
                "reason": "Mục tiêu chặn HTTP. Chuyển sang trinh sát hạ tầng DNS (SPF, DMARC, DNSSEC) hoàn toàn không bị ảnh hưởng bởi Web WAF.",
            }

    # 2. Web Crawling returned 0 endpoints or no query parameters
    if tool_name == "docker_crawl_web":
        param_count = len(report_state.attack_surface.parameterized_endpoints)
        if param_count == 0 or any(sig in res_lower for sig in ["0 endpoints", "endpoints found: 0", '"endpoints": []', "[]"]):
            if "docker_security_txt_audit" not in tested_tools:
                return {
                    "obstacle": "Crawler không tìm thấy endpoint có tham số",
                    "pivot_tool": "docker_security_txt_audit",
                    "reason": "Thu thập tự động thất bại. Kích hoạt chuyển hướng sang rà soát robots.txt và sitemap.xml để trích xuất danh sách URL tĩnh và đường dẫn ẩn.",
                }
            elif "docker_dirb_scan" not in tested_tools:
                return {
                    "obstacle": "Crawler không tìm thấy endpoint",
                    "pivot_tool": "docker_dirb_scan",
                    "reason": "Chuyển sang quét từ điển đường dẫn ẩn (directory fuzzing) bằng dirb.",
                }

    # 3. Fast Port Scan returned 0 open ports
    if tool_name == "docker_scan_ports_fast":
        if not report_state.attack_surface.open_ports or "0 ports open" in res_lower:
            if "docker_subfinder" not in tested_tools:
                return {
                    "obstacle": "Không phát hiện cổng mở trên host chính",
                    "pivot_tool": "docker_subfinder",
                    "reason": "Host mục tiêu có thể lọc cổng (filtered). Chuyển hướng sang mở rộng tìm kiếm tên miền phụ (subdomains) để tìm máy chủ thay thế.",
                }
            elif "docker_dns_security_audit" not in tested_tools:
                return {
                    "obstacle": "Không phát hiện cổng mở",
                    "pivot_tool": "docker_dns_security_audit",
                    "reason": "Chuyển sang kiểm toán an toàn DNS và các bản ghi thư tín điện tử.",
                }

    # 4. SQLMap did not find injectable parameters
    if tool_name == "docker_sqlmap_scan":
        if any(sig in res_lower for sig in ["not appear to be injectable", "0 vulnerabilities", "all tested parameters do not appear"]):
            untested_xss = [u for u, inf in report_state.attack_surface.parameterized_endpoints.items() if not inf.get("tested_xss")]
            if untested_xss and "docker_xss_scan" not in tested_tools:
                return {
                    "obstacle": "SQLMap không tìm thấy điểm tiêm SQL trên tham số này",
                    "pivot_tool": "docker_xss_scan",
                    "reason": "Chuyển hướng chiến thuật ngay lập tức: Fuzzing Cross-Site Scripting (XSS) trên cùng tham số để khai thác lỗ hổng thực thi script phía client.",
                }

    # 5. WPScan failed / Target is not WordPress
    if tool_name == "docker_wpscan":
        if any(sig in res_lower for sig in ["not seem to be running wordpress", "does not appear to be", "wordpress not found"]):
            if "docker_whatweb" not in tested_tools:
                return {
                    "obstacle": "Mục tiêu không sử dụng WordPress",
                    "pivot_tool": "docker_whatweb",
                    "reason": "Chuyển sang WhatWeb để nhận diện chính xác công nghệ và CMS thực tế.",
                }
            elif "docker_nuclei_scan" not in tested_tools:
                return {
                    "obstacle": "Mục tiêu không phải WordPress",
                    "pivot_tool": "docker_nuclei_scan",
                    "reason": "Chuyển sang quét mẫu lỗ hổng đa công nghệ bằng Nuclei.",
                }

    return None


def _evaluate_mission_guard(
    report_state: "ReportState",
    tools_called: set[str],
    progress_pct: int,
    untapped_actions: list[dict],
    iteration: int,
    max_iterations: int,
    guard_attempts: int,
    relentless_pursuit: bool = False,
    max_guard_attempts: int = 3,
) -> tuple[bool, list[str]]:
    """Determine if a premature final_answer should be intercepted to protect user mission objective."""
    effective_max_attempts = max(max_guard_attempts, 10) if relentless_pursuit else max_guard_attempts
    cutoff_iteration = max_iterations - 1 if relentless_pursuit else max_iterations - 2

    if guard_attempts >= effective_max_attempts or iteration >= cutoff_iteration:
        return False, []

    obj_lower = (report_state.mission_objective or report_state.target_objective or "").lower()
    unfulfilled = []

    if any(kw in obj_lower for kw in ["sql", "inject", "sqli"]):
        untested_sqli = [u for u, inf in report_state.attack_surface.parameterized_endpoints.items() if not inf.get("tested_sqli")]
        if untested_sqli and "docker_sqlmap_scan" not in tools_called:
            unfulfilled.append(f"Mục tiêu yêu cầu kiểm tra SQL Injection, phát hiện {len(untested_sqli)} endpoint nhưng chưa chạy 'docker_sqlmap_scan'")

    if any(kw in obj_lower for kw in ["xss", "cross-site", "scripting"]):
        untested_xss = [u for u, inf in report_state.attack_surface.parameterized_endpoints.items() if not inf.get("tested_xss")]
        if untested_xss and "docker_xss_scan" not in tools_called:
            unfulfilled.append(f"Mục tiêu yêu cầu kiểm tra XSS, phát hiện {len(untested_xss)} endpoint nhưng chưa chạy 'docker_xss_scan'")

    if any(kw in obj_lower for kw in ["mật khẩu", "password", "bruteforce", "hydra"]):
        if (report_state.attack_surface.login_forms or 22 in report_state.attack_surface.open_ports) and not any("bruteforce" in t for t in tools_called):
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra mật khẩu/bruteforce nhưng chưa chạy công cụ brute-force nào")

    if any(kw in obj_lower for kw in ["tệp nhạy cảm", "sensitive", ".env", "backup", "git"]):
        if "docker_sensitive_files_scan" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra tệp tin nhạy cảm nhưng chưa chạy 'docker_sensitive_files_scan'")

    if any(kw in obj_lower for kw in ["subdomain", "tên miền phụ"]):
        if report_state.attack_surface.subdomains and "docker_httpx_probe" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu trinh sát tên miền phụ nhưng chưa chạy 'docker_httpx_probe' để xác định dịch vụ alive")

    if any(kw in obj_lower for kw in ["ssl", "tls", "cert", "certificate", "chứng chỉ"]):
        if "docker_ssl_cert_audit" not in tools_called and "docker_testssl" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra SSL/TLS/chứng chỉ nhưng chưa chạy 'docker_ssl_cert_audit'")

    if any(kw in obj_lower for kw in ["dns", "spf", "dmarc", "dnssec", "mx", "mail spoofing", "email"]):
        if "docker_dns_security_audit" not in tools_called and "docker_resolve_dns" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra DNS/SPF/DMARC/Email Security nhưng chưa chạy 'docker_dns_security_audit'")

    if any(kw in obj_lower for kw in ["robots", "security.txt", "sitemap", "rfc 9116", "hidden paths"]):
        if "docker_security_txt_audit" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra robots.txt/security.txt/sitemap nhưng chưa chạy 'docker_security_txt_audit'")

    if any(kw in obj_lower for kw in ["cookie", "session", "httponly", "samesite"]):
        if "docker_cookie_security_audit" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra an toàn Cookie/Session nhưng chưa chạy 'docker_cookie_security_audit'")

    if any(kw in obj_lower for kw in ["header", "hsts", "csp", "security headers", "tiêu đề"]):
        if "docker_http_headers_audit" not in tools_called and "docker_cors_scan" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra HTTP Security Headers/HSTS/CSP nhưng chưa chạy 'docker_http_headers_audit'")

    if any(kw in obj_lower for kw in ["api", "swagger", "openapi", "graphql", "redoc"]):
        if "docker_api_docs_audit" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra API Docs/Swagger/OpenAPI/GraphQL nhưng chưa chạy 'docker_api_docs_audit'")

    if any(kw in obj_lower for kw in ["takeover", "subdomain takeover", "dangling", "cname"]):
        if "docker_subdomain_takeover_audit" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu kiểm tra Subdomain Takeover/CNAME nhưng chưa chạy 'docker_subdomain_takeover_audit'")

    if any(kw in obj_lower for kw in ["waf", "firewall", "tường lửa", "cloudflare", "akamai"]):
        if "docker_waf_detect" not in tools_called:
            unfulfilled.append("Mục tiêu yêu cầu nhận diện WAF/Tường lửa bảo vệ nhưng chưa chạy 'docker_waf_detect'")

    # In relentless pursuit mode, enforce that pending milestones or high-priority actions cannot be skipped
    if relentless_pursuit:
        pending_milestones = [m.name for m in report_state.milestones if m.status == "PENDING" and m.id != "m4_synthesis"]
        if pending_milestones:
            unfulfilled.append(f"Chế độ Cực Đoan: Cột mốc '{pending_milestones[0]}' chưa được kích hoạt (PENDING)")

        # Verify surface exhaustion when there are active attack surface elements or objective
        if untapped_actions or report_state.scan_mode == "full" or report_state.mission_objective:
            is_exhausted, surface_untested = report_state.is_surface_exhausted(tools_called=tools_called)
            if not is_exhausted and (progress_pct < 90 or untapped_actions):
                for item in surface_untested:
                    unfulfilled.append(f"Bề mặt tấn công chưa vét cạn: {item}")

        high_prio_actions = [a for a in untapped_actions if a.get("priority") in ("CRITICAL", "HIGH")]
        if high_prio_actions and progress_pct < 85:
            should_guard = True
            return should_guard, unfulfilled

    should_guard = bool((progress_pct < 60 and untapped_actions) or unfulfilled)
    return should_guard, unfulfilled


# ---------------------------------------------------------------------------
# Main Agent Runner
# ---------------------------------------------------------------------------

async def run_agent(prompt: str, server_script: str | None = None,
                    scan_mode: str = "recon",
                    resume_checkpoint: str | None = None) -> str:
    """Execute autonomous ReAct loop with real-time dual-agent collaboration.

    Architecture:
    - Red Teamer (7B) runs the ReAct loop, calls tools
    - Reporter (3B) observes EVERY tool result in real-time
    - Reporter updates ReportState with findings and injects suggestions
    - Red Teamer sees Reporter feedback before choosing next action
    - Final polish pass by Reporter after Red Teamer finishes
    - Professional DOCX generated from accumulated ReportState

    Args:
        prompt: The mission prompt for the agent.
        server_script: Path to the MCP server script (overrides config).
        scan_mode: 'recon' for reconnaissance only, 'full' for full pentest.
        resume_checkpoint: Optional path or session ID to resume from JSON checkpoint.
    """
    # 1. Load configuration
    config = load_config()
    llm_cfg = config.get("llm", {})
    agent_cfg = config.get("agent", {})

    client = AsyncOpenAI(
        base_url=llm_cfg.get("base_url", "http://localhost:11434/v1"),
        api_key=llm_cfg.get("api_key", "ollama"),
    )
    model = llm_cfg.get("model", "huihui_ai/qwen3.5-abliterated:9b")
    temperature = llm_cfg.get("temperature", 0.1)
    num_gpu = llm_cfg.get("num_gpu")
    num_ctx = int(llm_cfg.get("num_ctx", 16384))
    num_predict = int(llm_cfg.get("num_predict", 8192))
    keep_alive = llm_cfg.get("keep_alive", "15m")
    llm_options = {"num_predict": num_predict, "num_ctx": num_ctx}
    if num_gpu is not None:
        llm_options["num_gpu"] = int(num_gpu)
    extra_body = {
        "options": llm_options,
        "keep_alive": keep_alive,
        "format": "json",
    }
    max_iterations = agent_cfg.get("max_iterations", 25)
    context_window = min(agent_cfg.get("context_window_size", 30), 12)  # Cap at 12 to prevent context overflow
    retry_max = agent_cfg.get("retry_max", 2)
    retry_delay = agent_cfg.get("retry_delay_seconds", 3)

    # HITL config
    hitl_cfg = config.get("hitl", {})
    hitl_enabled = hitl_cfg.get("enabled", True)
    destructive_tools = set(hitl_cfg.get("destructive_tools", []))

    # Reporter config
    reporter_realtime = cfg_get("reporter.realtime", True)
    reporter_skip_tools = _get_reporter_skip_tools()

    # Locate the MCP server script
    if not server_script:
        server_script = config.get("mcp", {}).get("server_script", "src/servers/docker_arsenal.py")

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if not os.path.isabs(server_script):
        server_path = os.path.join(base_dir, server_script)
    else:
        server_path = server_script

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_path],
    )

    # ━━━ RAG Long-term Memory Initialization ━━━
    vectordb_cfg = config.get("vectordb", {})
    vector_memory = None
    if vectordb_cfg.get("enabled", False):
        try:
            from src.utils.vector_store import VectorMemoryManager
            db_path = vectordb_cfg.get("path", "data/chromadb")
            if not os.path.isabs(db_path):
                db_path = os.path.join(base_dir, db_path)
            ollama_url = llm_cfg.get("base_url", "http://localhost:11434/v1").replace("/v1", "")
            vector_memory = VectorMemoryManager(
                persist_dir=db_path,
                ollama_base_url=ollama_url,
                embedding_model=vectordb_cfg.get("ollama_model", "nomic-embed-text"),
                use_ollama=vectordb_cfg.get("embedding_source", "ollama") == "ollama",
                flashrank_cache_dir=os.path.join(base_dir, "models_cache"),
                min_similarity=float(vectordb_cfg.get("min_similarity", 0.65)),
                top_k=int(vectordb_cfg.get("top_k", 3)),
            )
            mem_stats = vector_memory.get_memory_stats()
            console.print(
                f"[bold green]🧠 RAG Long-term Memory: ONLINE "
                f"({mem_stats['attack_patterns']} kịch bản, {mem_stats['target_recon']} fingerprints)[/bold green]"
            )
        except Exception as e:
            console.print(f"[dim yellow]⚠️ RAG Memory không khả dụng: {e}[/dim yellow]")

    # ━━━ Tactical Policy Engine Initialization (RL & Bandit Hybrid) ━━━
    tp_cfg = config.get("tactical_policy", {})
    tactical_policy = None
    if tp_cfg.get("enabled", True):
        try:
            from src.utils.tactical_policy import TacticalPolicyManager, AttackStateExtractor
            tp_path = tp_cfg.get("policy_file", "data/tactical_policy.json")
            if not os.path.isabs(tp_path):
                tp_path = os.path.join(base_dir, tp_path)
            tactical_policy = TacticalPolicyManager(
                policy_file=tp_path,
                learning_rate=float(tp_cfg.get("learning_rate", 0.15)),
                discount_factor=float(tp_cfg.get("discount_factor", 0.85)),
                exploration_bonus=float(tp_cfg.get("exploration_bonus", 1.2)),
                enabled=True,
            )
            console.print(
                f"[bold green]🎯 Tactical Policy Engine: ONLINE "
                f"({len(tactical_policy.q_table)} states, {tactical_policy.total_updates} updates)[/bold green]"
            )
        except Exception as e:
            console.print(f"[dim yellow]⚠️ Tactical Policy không khả dụng: {e}[/dim yellow]")

    console.print(
        Panel.fit(
            f"[bold cyan]Starting Agent Orchestrator[/bold cyan]\n"
            f"[dim]Model:[/dim] {model} | [dim]Mode:[/dim] {scan_mode.upper()} | "
            f"[dim]Max Iter:[/dim] {max_iterations} | [dim]Context:[/dim] {context_window} msgs\n"
            f"[dim]Reporter:[/dim] {'🟢 Real-time' if reporter_realtime else '🔴 Disabled'} | "
            f"[dim]Policy:[/dim] {'🟢 RL-Hybrid' if tactical_policy else '⚪ Off'} | "
            f"[dim]Memory:[/dim] {'🟢 RAG' if vector_memory else '⚪ Off'} | "
            f"[dim]Skip:[/dim] {', '.join(reporter_skip_tools) if reporter_skip_tools else 'none'}",
            border_style="cyan",
        )
    )

    # Initialize Audit Logger and ReportState
    target_info = _extract_target_from_prompt(prompt)
    mission_objective = _extract_mission_objective(prompt)
    target_raw_str = target_info.get("url") or target_info.get("raw") or "unknown"
    target_log_name = target_info.get("hostname") or target_info.get("raw") or "unknown"
    audit = AuditLogger(target_log_name)
    audit.log("session_start", {"prompt": prompt, "mode": scan_mode, "model": model, "mission": mission_objective})

    report_state = None
    if resume_checkpoint:
        checkpoint_path = resume_checkpoint
        if not os.path.isabs(checkpoint_path) and not os.path.exists(checkpoint_path):
            candidate = os.path.join(base_dir, "data", "sessions", f"{resume_checkpoint}.json")
            if os.path.exists(candidate):
                checkpoint_path = candidate
            else:
                candidate2 = os.path.join(base_dir, "data", "sessions", resume_checkpoint)
                if os.path.exists(candidate2):
                    checkpoint_path = candidate2
        if os.path.exists(checkpoint_path):
            console.print(f"[bold green]♻️ KHÔI PHỤC PHIÊN QUÉT TỪ CHECKPOINT: {checkpoint_path}[/bold green]")
            try:
                report_state = ReportState.load_checkpoint(checkpoint_path)
                audit.log("session_resumed", {"checkpoint": checkpoint_path, "findings_count": len(report_state.findings)})
            except Exception as e:
                console.print(f"[bold red]❌ Lỗi tải checkpoint: {e}. Khởi tạo phiên mới.[/bold red]")

    if report_state is None:
        report_state = ReportState(target=target_raw_str, scan_mode=scan_mode, mission_objective=mission_objective)

    # 2. Connect to MCP Server via stdio
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            # 3. Retrieve available tools
            tools_list = await session.list_tools()
            tools_schema = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }
                for tool in tools_list.tools
            ]

            console.print(
                f"[dim]Connected to MCP Server. {len(tools_schema)} tools available: "
                f"{[t['name'] for t in tools_schema]}[/dim]"
            )

            # 4. Construct System Prompt
            tool_names = [t["name"] for t in tools_schema]
            target_raw = target_info.get("raw", "UNKNOWN")
            target_hostname = target_info.get("hostname", "")
            target_ip = target_info.get("ip", "")
            target_url = target_info.get("url", "")
            tool_reference = _build_tool_reference(tools_schema)

            mission_block = (
                f"=== USER MISSION OBJECTIVE (TỐI CAO) ===\n"
                f"{mission_objective}\n"
                "CRITICAL MANDATE: In every iteration, you and the SOC Analyst Reporter MUST exert MAXIMUM EFFORT to accomplish this mission objective. "
                "Do not deviate, give up, or output 'final_answer' prematurely before all relevant vectors have been exhaustively tested.\n\n"
            )

            target_block = (
                f"{mission_block}"
                f"=== YOUR TARGET ===\n"
                f"URL/Address: {target_url or target_raw}\n"
                f"Hostname: {target_hostname}\n"
            )
            if target_ip:
                target_block += f"IP: {target_ip}\n"
            target_block += (
                f"IMPORTANT: For network/port tools (nmap, dns, testssl, subfinder, ssh), use '{target_hostname or target_raw}'.\n"
                f"For web application tools (crawl, sqlmap, nuclei, browse, whatweb, nikto, dirb, ffuf, wpscan), use the full URL '{target_url or target_raw}'.\n"
                "NEVER use placeholders like 'target.com', 'example.com', or '127.0.0.1'.\n"
            )

            # Mode-specific instructions
            if scan_mode == "recon":
                mode_instruction = (
                    "\n\n# CURRENT MODE: RECONNAISSANCE ONLY\n"
                    "You are in RECON mode. Focus on intelligence gathering:\n"
                    "- Use: docker_resolve_dns, docker_scan_ports_fast, docker_scan_ports_deep, docker_crawl_web, "
                    "browse_webpage, docker_whatweb, docker_nikto_scan, docker_nuclei_scan, "
                    "docker_dirb_scan, docker_subfinder, docker_ffuf, docker_testssl, "
                    "docker_sensitive_files_scan, docker_cors_scan, docker_httpx_probe, "
                    "docker_ssl_cert_audit, docker_dns_security_audit, docker_security_txt_audit, docker_cookie_security_audit, "
                    "docker_http_headers_audit, docker_api_docs_audit, docker_subdomain_takeover_audit, docker_waf_detect\n"
                    "- DO NOT use destructive/exploit tools (sqlmap, hydra, metasploit) in this mode.\n"
                    "- Your goal: Map the ENTIRE attack surface. Find every open port, every endpoint, "
                    "every technology, every potential vulnerability.\n"
                    "- After thorough recon, output final_answer with a detailed intelligence report.\n"
                )
            else:
                mode_instruction = (
                    "\n\n# CURRENT MODE: FULL PENTEST (ALL WEAPONS HOT)\n"
                    "You are in FULL PENTEST mode. Attack the target systematically:\n"
                    "- Start with recon (ports, crawl, whatweb, subfinder, httpx probe, waf detect) then escalate to targeted exploitation.\n"
                    "- Chain tools: crawl → sqlmap & xss scan, subfinder → httpx probe → takeover audit, ports → deep scan → exploit search, browse → form brute-force.\n"
                    "- Audit web targets with docker_sensitive_files_scan (.env, .git, backups), docker_cors_scan, docker_http_headers_audit, docker_api_docs_audit, and docker_cookie_security_audit.\n"
                    "- Audit infrastructure with docker_ssl_cert_audit (TLS/SANs), docker_dns_security_audit (SPF/DMARC/DNSSEC), and docker_waf_detect (WAF evasion).\n"
                    "- Discover hidden endpoints with docker_security_txt_audit (RFC 9116 security.txt, robots.txt, sitemap.xml) and docker_api_docs_audit.\n"
                    "- Use bruteforce_ssh ONLY if port 22/SSH is confirmed open.\n"
                    "- Use bruteforce_http_form ONLY if a real login form endpoint is confirmed.\n"
                    "- Use docker_sqlmap_dump after finding injectable params and databases.\n"
                    "- Use docker_testssl on HTTPS targets to find SSL/TLS weaknesses.\n"
                    "- Focus on high-value attack vectors. When relevant tools have been executed and no further vectors remain, output final_answer.\n"
                )

            # SOC Analyst collaboration notice
            soc_notice = (
                "\n\n# SOC ANALYST COLLABORATION (TỐI ĐA HÓA NỖ LỰC ĐẠT MỤC TIÊU):\n"
                "A senior SOC Analyst observes every step in REAL-TIME as your tactical co-pilot. After each tool execution, "
                "the SOC Analyst evaluates your progress toward the USER MISSION OBJECTIVE and suggests the most impactful next action.\n"
                "You MUST read and proactively adopt the SOC Analyst's guidance to maintain maximum momentum toward the goal.\n"
            )

            # RAG Long-term Memory: Historical Past Experience Injection
            rag_experience_block = ""
            if vector_memory:
                try:
                    known_tech = list(report_state.attack_surface.detected_technologies)
                    known_waf = report_state.attack_surface.detected_waf.get("primary_waf", "")
                    target_query = f"{target_hostname} {target_url} {mission_objective}".strip()
                    recalled_patterns = vector_memory.recall_attack_patterns(
                        query=target_query,
                        tech_stack=known_tech or None,
                        waf=known_waf or None,
                        top_k=int(vectordb_cfg.get("top_k", 3)),
                        min_similarity=float(vectordb_cfg.get("min_similarity", 0.65)),
                        enable_rerank=True,
                    )
                    if recalled_patterns:
                        rag_experience_block = vector_memory.format_past_experience_block(
                            recalled_patterns,
                            max_tokens=int(vectordb_cfg.get("max_rag_tokens", 800)),
                        )
                        report_state.record_rag_applied_patterns(recalled_patterns)
                        console.print(f"[bold green]🧠 RAG: Injected {len(recalled_patterns)} past attack patterns into System Prompt[/bold green]")
                except Exception as e:
                    logger.debug("RAG prompt injection query failed: %s", e)

            # Symbiotic Neuro-Symbolic Command directive
            synergy_directive = (
                "\n\n# CHỈ ĐẠO CHỈ HUY HIỆP ĐỒNG (SYMBIOTIC NEURO-SYMBOLIC COMMAND):\n"
                "Bạn (Qwen Red Teamer) là vị TƯỚNG TỐI CAO của chiến dịch. Hệ thống trang bị cho bạn 2 cố vấn đắc lực:\n"
                "1. CỐ VẤN TOÁN HỌC (Tactical Policy Engine - Q-learning & Bandit): Tính toán xác suất thành công từ hàng trăm trận đánh trước để gợi ý công cụ và chuỗi Kill-Chain tối ưu.\n"
                "2. CỐ VẤN GIÁM SÁT (SOC Analyst Reporter): Phân tích phản hồi mục tiêu và chất lượng phát hiện theo thời gian thực.\n"
                "TRÁCH NHIỆM VƯỢT TRỘI CỦA BẠN (QWEN):\n"
                "- Nắm quyền quyết định chiến lược: Hãy tận dụng sức mạnh suy luận ngữ nghĩa của bạn để điều chỉnh tham số 'arguments' một cách tinh vi nhất (URL, endpoints, injection payloads, wordlists).\n"
                "- Khi cố vấn toán học đưa ra gợi ý, hãy kết hợp với trí tuệ ngữ cảnh của bạn để ra đòn quyết định. Nếu bạn phát hiện một sơ hở tinh tế mà công thức toán học chưa thấy, hãy chủ động khai thác ngay!\n"
            )

            system_prompt = (
                "/nothink\n"
                "You are an autonomous red team agent. Compromise the target.\n\n"
                f"{target_block}\n"
                f"TOOLS ({len(tools_schema)} available):\n{tool_reference}\n\n"
                "# STRICT RULES OF ENGAGEMENT:\n\n"
                "1. **5 Tactical Dimensions (keep each under 15 words):**\n"
                "   - [TÌNH BÁO TỔNG HỢP]: Hiện trạng bề mặt tấn công\n"
                "   - [GIẢ THUYẾT ĐỘT PHÁ]: Vector khai thác nhắm tới\n"
                "   - [ĐÒN ĐÁNH CỘT MỐC]: Mục tiêu cần hoàn thành\n"
                "   - [CHIẾN THUẬT NÉ TRÁNH PHÒNG THỦ]: WAF/firewall bypass nếu cần\n"
                "   - [DỰ PHÒNG TỨC THỜI]: Công cụ thay thế nếu thất bại\n\n"
                "2. **Recon First, Then Exploit:** Run `docker_crawl_web` first. "
                "Use recon output to guide exploitation. Do NOT run exploit tools blindly on root '/'. "
                "But after recon is done, you MUST escalate to exploitation tools.\n\n"
                "3. **Tool Chaining (The Kill Chain):**\n"
                "   - `docker_crawl_web` URLs with `?id=` → `docker_sqlmap_scan` AND `docker_xss_scan`\n"
                "   - `docker_subfinder` → `docker_httpx_probe` → `docker_subdomain_takeover_audit`\n"
                "   - `docker_scan_ports_fast` → `docker_scan_ports_deep` on open ports\n"
                "   - `docker_http_headers_audit`, `docker_cors_scan`, `docker_sensitive_files_scan` for web audit\n"
                "   - `docker_ssl_cert_audit`, `docker_dns_security_audit` for infra audit\n"
                "   - `docker_security_txt_audit` for hidden paths, `docker_api_docs_audit` for API schemas\n"
                "   - Port 22 open → `bruteforce_ssh`, Login form found → `bruteforce_http_form`\n"
                "   - Use `docker_whatweb` early to identify CMS/framework, then pick the right tool "
                "(e.g., WordPress → `docker_wpscan`).\n"
                "   - Use `docker_dirb_scan` or `docker_ffuf` to find hidden paths like /admin, /api, /backup.\n"
                "   - Use `docker_testssl` on HTTPS targets to check for SSL/TLS vulnerabilities.\n"
                "   - If `docker_nuclei_scan` finds CVEs, search them with `docker_msf_search`.\n\n"

                "4. **Relentless Persistence & Goal Focus:** If a tool times out or fails, or if an endpoint is not injectable, "
                "DO NOT STOP. You must pivot to alternative attack vectors (subdomain discovery, directory fuzzing, "
                "technological fingerprinting, nuclei CVE scanning) until the mission objective is thoroughly investigated.\n\n"
                "5. **Exhaustive Fulfillment Before Completion:** Conclude with 'final_answer' ONLY when the user's mission objective has been comprehensively accomplished and all viable attack paths have been explored. Never stop midway.\n\n"
                "6. **ANTI-LOOP & TARGET EQUIVALENCE:** NEVER call the exact same tool with the exact same "
                "arguments. Furthermore, NEVER re-scan equivalent targets (e.g., 'www.domain.com' and 'domain.com' "
                "resolve to the same server; scanning both is redundant). If a tool fails or returns no new "
                "attack vectors, move on to a DIFFERENT attack vector or tool. If viable vectors are exhausted, "
                "immediately output 'final_answer'.\n\n"
                "7. **LANGUAGE REQUIREMENT (CRITICAL):** You MUST write your 'thought' and final "
                "'text' entirely in VIETNAMESE. However, the JSON keys ('thought', 'action', "
                "'tool_name', 'arguments', 'text') MUST remain in English to avoid parsing errors.\n\n"
                "8. **NO COMMENTS IN JSON (CRITICAL):** You are strictly FORBIDDEN from adding "
                "any inline comments (such as // or /*) inside your JSON output. Your output "
                "must be 100% standard, parseable JSON.\n\n"
                + (f"\n{rag_experience_block}\n" if rag_experience_block else "")
                + mode_instruction
                + soc_notice
                + synergy_directive +
                "\n# OUTPUT FORMAT (STRICT JSON):\n"
                "You must output ONLY a single ```json``` code block. NO text before or after.\n"
                "Keep 'thought' EXTREMELY SHORT — MAX 30 words. Longer thoughts cause FATAL errors.\n\n"
                "For taking an action:\n"
                '{\n'
                '  "thought": "Brief plan (MAX 30 words)",\n'
                '  "action": "call_tool",\n'
                '  "tool_name": "name",\n'
                '  "arguments": {"key": "value"}\n'
                '}\n\n'
                "To report confirmed findings and conclude the assessment:\n"
                '{\n'
                '  "thought": "Summarize the entire kill chain in VIETNAMESE.",\n'
                '  "action": "final_answer",\n'
                '  "text": "Detailed report in VIETNAMESE."\n'
                '}'
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ]

            tools_called = []
            _call_signatures = set()  # Anti-loop: track (tool_name, args_hash) to block duplicates
            _semantic_signatures = set()  # Semantic anti-loop: track (tool_name, normalized_target)
            _consecutive_json_errors = 0  # Error budget for JSON parse failures
            _stagnation_counter = 0  # Track consecutive steps without new findings
            _stagnation_rescues = 0  # Number of times Relentless Pursuit prevented premature stagnation
            stagnation_warning_thresh = cfg_get("agent.stagnation_warning_threshold", 3)
            stagnation_max_thresh = cfg_get("agent.stagnation_max_threshold", 5)
            relentless_pursuit = cfg_get("agent.relentless_pursuit", True)
            max_guard_challenges = cfg_get("agent.max_guard_challenges", 10 if relentless_pursuit else 5)
            stagnation_max_rescues = cfg_get("agent.stagnation_max_rescues", 5 if relentless_pursuit else 2)
            step_counter = 0  # Track tool execution steps for ReportState
            _mission_guard_attempts = 0  # Mission Completeness Guard challenge counter

            # 5. ReAct Loop with Real-time Reporter
            try:
                for iteration in range(1, max_iterations + 1):
                    # Context Window Management: compress old messages
                    messages = _summarize_old_messages(messages, context_window, report_state=report_state)
    
                    console.print(
                        f"\n[bold yellow]── Iteration {iteration}/{max_iterations} "
                        f"| Tools: {len(tools_called)} "
                        f"| Findings: {len(report_state.findings)} "
                        f"| Risk: {report_state.risk_score}/10 "
                        f"| Msgs: {len(messages)} ──[/bold yellow]"
                    )
    
                    # AUTO-ESCALATION: When recon phase is done, push model to exploit
                    if report_state.scan_mode == "full" and not getattr(report_state, '_exploit_escalated', False):
                        _RECON_TOOLS = {
                            "docker_resolve_dns", "docker_scan_ports_fast", "docker_scan_ports_deep",
                            "docker_crawl_web", "docker_whatweb", "docker_subfinder", "docker_httpx_probe",
                            "docker_nuclei_scan", "docker_sensitive_files_scan", "docker_cors_scan",
                            "docker_http_headers_audit", "docker_ssl_cert_audit", "docker_dns_security_audit",
                            "docker_testssl", "docker_security_txt_audit", "docker_waf_detect",
                            "docker_nikto_scan", "docker_ffuf", "docker_dirb_scan",
                            "docker_cookie_security_audit", "docker_api_docs_audit",
                            "docker_subdomain_takeover_audit", "browse_webpage",
                        }
                        recon_done = len(set(tools_called) & _RECON_TOOLS) >= 8
                        if recon_done:
                            report_state._exploit_escalated = True
                            # Build exploit guidance based on what recon found
                            exploit_hints = []
                            if report_state.attack_surface.parameterized_urls:
                                exploit_hints.append(
                                    f"URLs with parameters found: {list(report_state.attack_surface.parameterized_urls)[:3]} "
                                    "→ RUN docker_sqlmap_scan AND docker_xss_scan on these URLs NOW."
                                )
                            if report_state.attack_surface.login_forms:
                                exploit_hints.append(
                                    f"Login forms found: {list(report_state.attack_surface.login_forms)[:2]} "
                                    "→ RUN bruteforce_http_form on these endpoints NOW."
                                )
                            if 22 in report_state.attack_surface.open_ports:
                                exploit_hints.append("SSH port 22 is open → RUN bruteforce_ssh NOW.")
                            # Always suggest trying sqlmap on root if no params found
                            if not report_state.attack_surface.parameterized_urls:
                                exploit_hints.append(
                                    f"No parameterized URLs found, but TRY docker_sqlmap_scan on "
                                    f"'{report_state.target}' anyway to test for blind SQLi."
                                )
                            exploit_hints.append(
                                "Also try: docker_xss_scan, docker_wpscan (if WordPress), docker_msf_search (if CVEs found)."
                            )
                            escalation_msg = (
                                "⚡ RECON PHASE COMPLETE. SWITCHING TO EXPLOITATION PHASE NOW. ⚡\n"
                                f"You have completed {len(set(tools_called) & _RECON_TOOLS)} recon tools. "
                                "STOP running recon tools. START using EXPLOIT tools:\n"
                                + "\n".join(f"- {h}" for h in exploit_hints)
                            )
                            messages.append({"role": "user", "content": escalation_msg})
                            console.print(f"[bold green]⚡ AUTO-ESCALATION: Recon done → Exploit phase[/bold green]")
                            logger.info("Auto-escalation triggered after %d recon tools", len(set(tools_called) & _RECON_TOOLS))
    
                    # Dynamic Per-Iteration RAG Tactical Recall (every 3 iterations when new tech/obstacles emerge)
                    if vector_memory and iteration > 1 and iteration % 3 == 0:
                        try:
                            current_suggestion = report_state.reporter_suggestions[-1] if report_state.reporter_suggestions else ""
                            known_tech = list(report_state.attack_surface.detected_technologies)
                            known_waf = report_state.attack_surface.detected_waf.get("primary_waf", "")
                            query_str = current_suggestion or f"attack {' '.join(known_tech)}"
                            tactical_recalled = vector_memory.recall_attack_patterns(
                                query=query_str,
                                tech_stack=known_tech or None,
                                waf=known_waf or None,
                                top_k=2,
                                min_similarity=float(vectordb_cfg.get("min_similarity", 0.65)),
                                enable_rerank=True,
                            )
                            if tactical_recalled:
                                tac_block = vector_memory.format_past_experience_block(tactical_recalled, max_tokens=350)
                                if not any(tac_block[:60] in str(m.get("content", "")) for m in messages[-2:]):
                                    messages.append({
                                        "role": "user",
                                        "content": f"[🧠 BỘ NHỚ CHIẾN THUẬT QUÁ KHỨ (TACTICAL RECALL)]\n{tac_block}"
                                    })
                                    report_state.record_rag_applied_patterns(tactical_recalled)
                                    console.print(f"[dim green]🧠 RAG: Nạp {len(tactical_recalled)} kịch bản chiến thuật vào ngữ cảnh bước {iteration}[/dim green]")
                        except Exception:
                            pass
    
                    # Dynamic Tactical Policy Guidance (Q-learning & UCB1 Bandit)
                    current_state_key = ""
                    if tactical_policy:
                        try:
                            current_state_key = AttackStateExtractor.extract_state_key(report_state, tools_called)
                            last_act = tools_called[-1] if tools_called else None
                            recs = tactical_policy.recommend_actions(
                                state_key=current_state_key,
                                top_k=3,
                                exclude_tools=set(tools_called) if len(tools_called) < 25 else None,
                                last_action=last_act,
                            )
                            if recs:
                                rec_lines = []
                                for r in recs:
                                    combo_str = f" [Combo: {r.combo_chain[0]} ➔ {r.combo_chain[1]}]" if len(r.combo_chain) > 1 else ""
                                    rec_lines.append(f"- `{r.tool_name}` (Q={r.q_value:.1f}, Visits={r.visits}){combo_str} → {r.rationale}")
                                rec_block = (
                                    f"[⚡ CHẾ ĐỘ HIỆP ĐỒNG CHIẾN THUẬT: QWEN CHỈ HUY x CỐ VẤN TOÁN HỌC]\n"
                                    f"Trạng thái mục tiêu: `{current_state_key}`\n"
                                    f"Cố vấn Toán học (Policy Engine & Markov Kill-Chain) đề xuất các vector tối ưu:\n"
                                    + "\n".join(rec_lines)
                                    + "\n"
                                    f"🛡️ QUYỀN HẠN CỦA RED TEAMER (QWEN):\n"
                                    f"- Bạn là CHỈ HUY TỐI CAO: Cân nhắc gợi ý toán học trên kết hợp với suy luận ngữ nghĩa của bạn.\n"
                                    f"- Tự do tùy biến tham số ('arguments') sâu sắc nhất (URL cụ thể, payload, wordlist) để công cụ đạt hiệu quả tối đa!\n"
                                    f"- Nếu bạn phát hiện một dấu hiệu ngữ nghĩa đặc biệt vượt ngoài gợi ý trên, hãy tự tin triển khai công cụ bạn đánh giá là đúng đắn nhất."
                                )
                                if not any(f"Trạng thái mục tiêu: `{current_state_key}`" in str(m.get("content", "")) for m in messages[-2:]):
                                    messages.append({
                                        "role": "user",
                                        "content": rec_block
                                    })
                                    console.print(f"[dim cyan]🎯 Policy Engine: Gợi ý {len(recs)} công cụ tối ưu cho state [{current_state_key}][/dim cyan]")
                        except Exception as e:
                            logger.debug("Tactical policy recommendation error: %s", e)
    
                    try:
                        call_kwargs = {
                            "model": model,
                            "messages": messages,
                            "temperature": temperature,
                            "response_format": {"type": "json_object"},  # OpenAI JSON mode
                        }
                        if extra_body:
                            # Disable Qwen3.5 thinking mode via Ollama OpenAI-compatible API
                            # reasoning_effort="none" is the correct parameter for /v1/ endpoint
                            # (think=false only works with native /api/ endpoint)
                            extra_body_with_think = {**extra_body, "reasoning_effort": "none"}
                            call_kwargs["extra_body"] = extra_body_with_think
    
                        with console.status("[bold cyan]🧠 Qwen đang suy luận chiến thuật...[/bold cyan]", spinner="dots"):
                            response = await asyncio.wait_for(
                                client.chat.completions.create(**call_kwargs),
                                timeout=180,
                            )
                        msg = response.choices[0].message
                        finish_reason = response.choices[0].finish_reason
                        response_content = msg.content or ""
                        # If content is empty but reasoning exists, model was in thinking mode
                        if not response_content.strip():
                            reasoning = getattr(msg, "reasoning", None) or getattr(msg, "reasoning_content", None) or ""
                            if reasoning:
                                response_content = reasoning
                        if finish_reason == "length":
                            logger.warning("LLM output truncated (finish_reason=length) at iteration %d", iteration)
    
                        # Strip Qwen3.5 thinking mode <think>...</think> tags
                        # These cause JSON extraction failures by emitting long
                        # free-text reasoning before the actual JSON output.
                        response_content_clean = _clean_thinking_tags(response_content)
                        # If after stripping think tags there is usable content, prefer it
                        if response_content_clean:
                            response_content = response_content_clean
                    except asyncio.TimeoutError:
                        console.print("[bold red]⏱️ LLM call timed out after 180s. Retrying...[/bold red]")
                        audit.log("llm_timeout", {"iteration": iteration})
                        messages.append({"role": "user", "content": "System Notification: Previous request timed out. Please proceed with next step."})
                        continue
                    except Exception as llm_err:
                        err_msg = str(llm_err).lower()
                        if ("cuda" in err_msg or "ptx" in err_msg or "0xc0000409" in err_msg or "llama-server" in err_msg) and extra_body.get("options", {}).get("num_gpu") != 0:
                            console.print("[bold yellow]⚡ Phát hiện lỗi CUDA/PTX JIT từ GPU driver — Tự động chuyển sang CPU an toàn (num_gpu=0)...[/bold yellow]")
                            extra_body = {
                                "options": {"num_gpu": 0, "num_predict": num_predict, "num_ctx": num_ctx},
                                "keep_alive": keep_alive,
                                "format": "json",
                            }
                            audit.log("gpu_fallback_cpu", {"iteration": iteration, "error": str(llm_err)})
                            await asyncio.sleep(2)
                            continue
                        console.print(f"[bold red]❌ LLM Connection Error: {llm_err}[/bold red]")
                        audit.log("llm_error", {"iteration": iteration, "error": str(llm_err)})
                        await asyncio.sleep(3)
                        messages.append({"role": "user", "content": f"System Alert: LLM connection error: {llm_err}. Please retry action."})
                        continue
                    console.print(f"[yellow]{response_content}[/yellow]")
    
                    # Append assistant response to history
                    messages.append({"role": "assistant", "content": response_content})
    
                    # 6. BULLETPROOF JSON Extraction, Parsing, Tool Matching & Execution
                    try:
                        parsed_json = _extract_json(response_content)
                        _consecutive_json_errors = 0  # Reset error budget on success
    
                        if not isinstance(parsed_json, dict):
                            raise ValueError("JSON content must be an object/dictionary.")
    
                        action = parsed_json.get("action")
                        if not action:
                            raise ValueError("Missing required key 'action' in JSON block.")
    
                        # 7. Display Chain-of-Thought reasoning
                        thought = parsed_json.get("thought")
                        if thought:
                            console.print(
                                Panel(
                                    f"[italic bright_white]{thought}[/italic bright_white]",
                                    title="[bold magenta]🧠 Agent Reasoning (CoT)[/bold magenta]",
                                    border_style="magenta",
                                )
                            )
    
                        # 8. Tool Execution or Final Answer
                        if action == "call_tool":
                            tool_name = parsed_json.get("tool_name")
                            # Auto-correct tool name typos
                            tool_name = _fuzzy_match_tool_name(tool_name, tools_schema)
                            arguments = parsed_json.get("arguments", {})
                            if not isinstance(arguments, dict):
                                arguments = {}
                            # Auto-inject target when args are empty (from truncated JSON repair)
                            if not arguments and report_state and report_state.target:
                                target_url = report_state.target.rstrip("/")
                                if tool_name in (
                                    "docker_whatweb", "docker_crawl_web", "docker_nuclei_scan",
                                    "docker_http_headers_audit", "docker_sensitive_files_scan",
                                    "docker_security_txt_audit", "docker_api_docs_audit",
                                    "docker_cors_scan", "docker_nikto_scan",
                                ):
                                    arguments = {"target_url": target_url}
                                elif tool_name in ("docker_testssl",):
                                    arguments = {"target_host": target_url}
                                elif tool_name in ("docker_httpx_probe",):
                                    arguments = {"targets": target_url}
                                elif tool_name in ("docker_subfinder", "docker_subdomain_takeover_audit"):
                                    from urllib.parse import urlparse
                                    domain = urlparse(target_url).hostname or target_url
                                    arguments = {"domain": domain}
                                elif tool_name in ("docker_resolve_dns",):
                                    from urllib.parse import urlparse
                                    domain = urlparse(target_url).hostname or target_url
                                    arguments = {"hostname": domain}
                                else:
                                    arguments = {"target": target_url}
                                logger.info("Auto-injected target into empty args for %s", tool_name)
                            # Auto-correct argument names, inject WAF evasion tamper and adaptive wordlist BEFORE anti-loop check
                            waf_info = getattr(report_state.attack_surface, "detected_waf", {}) if report_state else {}
                            detected_waf_name = waf_info.get("primary_waf", "") if waf_info else ""
                            techs = getattr(report_state.attack_surface, "detected_technologies", []) if report_state else []
                            arguments = _normalize_tool_args(
                                tool_name,
                                arguments,
                                tools_schema,
                                detected_waf=detected_waf_name,
                                detected_technologies=techs,
                            )
    
                            # ANTI-LOOP ENFORCEMENT: block duplicate tool+args calls
                            call_sig = f"{tool_name}::{json.dumps(arguments, sort_keys=True)}"
                            semantic_sig = _get_semantic_signature(tool_name, arguments)
                            if call_sig in _call_signatures or semantic_sig in _semantic_signatures:
                                dup_msg = (
                                    f"SYSTEM BLOCK: You already called '{tool_name}' with these arguments "
                                    f"(or an equivalent target like www vs non-www). "
                                    "This is a DUPLICATE/REDUNDANT call and has been BLOCKED. "
                                    "You MUST use a DIFFERENT tool or explore a DIFFERENT attack vector. "
                                    "If you have exhausted all viable attack vectors, output 'final_answer' immediately."
                                )
                                console.print(f"[bold red]🔁 DUPLICATE BLOCKED: {tool_name}[/bold red]")
                                messages.append({"role": "user", "content": dup_msg})
                                audit.log("duplicate_blocked", {"tool": tool_name, "args": arguments})
                                continue
                            _call_signatures.add(call_sig)
                            _semantic_signatures.add(semantic_sig)
    
                            # Human-in-the-Loop gate for destructive tools
                            if hitl_enabled and tool_name in destructive_tools:
                                console.print(
                                    f"\n[bold red]⚠️  CẢNH BÁO: AI Agent muốn kích hoạt: {tool_name}[/bold red]"
                                )
                                console.print(
                                    f"[dim]Mục tiêu:[/dim] {arguments}"
                                )
                                approval = Prompt.ask(
                                    "[bold red]Cho phép không?[/bold red] (Y/N)"
                                )
                                if approval.strip().lower() != "y":
                                    console.print(
                                        "[bold yellow]❌ Operator từ chối. Bỏ qua lệnh này.[/bold yellow]"
                                    )
                                    messages.append(
                                        {
                                            "role": "user",
                                            "content": (
                                                "System Alert: Operator denied permission to run "
                                                f"'{tool_name}'. Try a different approach or tool."
                                            ),
                                        }
                                    )
                                    audit.log("tool_denied", {"tool": tool_name, "args": arguments})
                                    continue
    
                            console.print(
                                f"[bold cyan]🔧 Calling Tool:[/bold cyan] [cyan]{tool_name}[/cyan] "
                                f"with args: [dim]{arguments}[/dim]"
                            )
    
                            findings_count_before = len(report_state.findings)
                            open_ports_before = len(report_state.attack_surface.open_ports)
                            endpoints_before = len(report_state.attack_surface.parameterized_endpoints)
                            pre_state_key = AttackStateExtractor.extract_state_key(report_state, tools_called) if tactical_policy else ""
                            is_duplicate_call = (tools_called.count(tool_name) > 0)
                            surface_count_before = (
                                len(report_state.attack_surface.open_ports)
                                + len(report_state.attack_surface.parameterized_endpoints)
                                + len(report_state.attack_surface.login_forms)
                                + len(report_state.attack_surface.detected_technologies)
                                + len(report_state.attack_surface.subdomains)
                                + len(report_state.attack_surface.alive_subdomains)
                                + len(report_state.attack_surface.exposed_sensitive_files)
                                + len(report_state.attack_surface.cors_issues)
                            )
    
                            # Tool call with retry logic and timing
                            tool_start = time.time()
                            with console.status(f"[bold cyan]⚙️ Đang thực thi công cụ {tool_name}...[/bold cyan]", spinner="dots"):
                                result_str = await _retry_tool_call(
                                    session, tool_name, arguments,
                                    max_retries=retry_max, delay=retry_delay,
                                )
                            tool_duration = time.time() - tool_start
    
                            console.print(f"[bold cyan]📥 Tool Output ({tool_duration:.1f}s):[/bold cyan] {result_str}")
    
                            # Determine tool status
                            is_error = any(kw in result_str.lower() for kw in [
                                "error", "failed", "timeout", "timed out",
                                "connection refused", "exception"
                            ])
                            tool_status = "FAILED" if is_error else "SUCCESS"
    
                            # Track and log
                            step_counter += 1
                            tools_called.append(tool_name)
                            audit.log("tool_call", {
                                "iteration": iteration,
                                "tool": tool_name,
                                "arguments": arguments,
                                "result_snippet": result_str[:500],
                                "duration": round(tool_duration, 2),
                                "status": tool_status,
                            })
    
                            # ★ Attack Surface Graph Update & Intelligence Distillation
                            report_state.update_attack_surface(tool_name, arguments, result_str)
                            distilled_intel = _distill_tool_intelligence(tool_name, result_str)
                            if distilled_intel.get("summary") and distilled_intel["summary"] != "Không có dấu hiệu đặc biệt.":
                                console.print(f"[bold dim yellow]⚡ Distilled Intel:[/bold dim yellow] [dim]{distilled_intel['summary']}[/dim]")
    
                            # RAG Memory: Ingest Recon Intelligence (Checkpoint 1 & 2)
                            if vector_memory and tool_status == "SUCCESS" and distilled_intel.get("summary") and distilled_intel["summary"] != "Không có dấu hiệu đặc biệt.":
                                try:
                                    port_val = distilled_intel.get("ports", [0])[0] if distilled_intel.get("ports") else 0
                                    vector_memory.store_target_recon(
                                        target=target_raw_str,
                                        port=port_val,
                                        service="discovered",
                                        summary=distilled_intel["summary"],
                                        metadata={
                                            "tool": tool_name,
                                            "technologies": distilled_intel.get("technologies", []),
                                            "cves": distilled_intel.get("cves", []),
                                        }
                                    )
                                except Exception:
                                    pass
    
                            # ★ REAL-TIME REPORTER: Observe this tool result
                            reporter_comment = ""
                            feedback_block = ""
                            if reporter_realtime and tool_name not in reporter_skip_tools:
                                with console.status(f"[bold cyan]🔍 Reporter đang phân tích kết quả {tool_name}...[/bold cyan]", spinner="dots"):
                                    reporter_result = await _invoke_reporter_realtime(
                                        client, report_state,
                                        tool_name, arguments, result_str, iteration,
                                        distilled_summary=distilled_intel.get("summary", ""),
                                    )
    
                                if reporter_result:
                                    raw_findings = reporter_result.get("new_findings", [])
                                    filtered_findings = _filter_hallucinated_findings(
                                        raw_findings, tool_name, result_str
                                    )
                                    # Process new findings
                                    new_findings = []
                                    for f_data in filtered_findings:
                                        cve = (f_data.get("cve_id") or "").strip()
                                        if not cve:
                                            cve_match = _RE_CVE_PATTERN.search(f"{f_data.get('title', '')} {f_data.get('description', '')} {result_str}")
                                            if cve_match:
                                                cve = cve_match.group(1).upper()
    
                                        finding = Finding(
                                            title=f_data.get("title", "Untitled"),
                                            severity=f_data.get("severity", "INFO"),
                                            description=f_data.get("description", ""),
                                            impact=f_data.get("impact", ""),
                                            remediation=f_data.get("remediation", ""),
                                            tool_source=tool_name,
                                            raw_evidence=result_str[:1000],
                                            cve_id=cve,
                                            cvss_score=f_data.get("cvss_score"),
                                        )
                                        report_state.add_finding(finding)
                                        new_findings.append(finding)
    
                                    # Update risk score (only on non-capability check)
                                    new_risk = reporter_result.get("risk_score", 0)
                                    if new_risk and (tool_name != "docker_bruteforce" and "capability_check_only" not in result_str):
                                        report_state.update_risk_score(new_risk)
    
                                    # Get suggestion and comment
                                    suggestion = reporter_result.get("suggestion", "")
                                    reporter_comment = reporter_result.get("step_comment", "")
                                    obj_assessment = reporter_result.get("objective_assessment", "")
                                    blk_factor = reporter_result.get("blocking_factor", "")
    
                                    if suggestion:
                                        report_state.add_suggestion(suggestion)
    
                                    # RAG Checkpoint: Store Context-Aware Attack Pattern if Reporter generated one
                                    if vector_memory:
                                        pattern_data = reporter_result.get("attack_pattern", {})
                                        if pattern_data and pattern_data.get("should_store"):
                                            try:
                                                p_meta = pattern_data.setdefault("metadata", {})
                                                if not p_meta.get("tech_stack"):
                                                    p_meta["tech_stack"] = list(report_state.attack_surface.detected_technologies)[:5]
                                                if not p_meta.get("waf"):
                                                    p_meta["waf"] = report_state.attack_surface.detected_waf.get("primary_waf", "")
                                                stored_id = vector_memory.store_attack_pattern(pattern_data)
                                                if stored_id:
                                                    report_state.record_rag_stored_pattern(pattern_data, stored_id)
                                                    console.print(f"[dim green]🧠 Sổ tay Red Team đã ghi nhớ kịch bản: {stored_id}[/dim green]")
                                                    audit.log("rag_attack_pattern_stored", {"id": stored_id, "tool": tool_name})
                                            except Exception as e:
                                                logger.debug("RAG attack pattern storage failed: %s", e)
    
                                    # Build and inject feedback into Red Teamer context
                                    feedback_block = report_state.get_reporter_feedback_block(
                                        latest_suggestion=suggestion,
                                        latest_comment=reporter_comment,
                                        latest_findings=new_findings,
                                        objective_assessment=obj_assessment,
                                        blocking_factor=blk_factor,
                                    )
    
                                    console.print(
                                        Panel(
                                            f"[italic cyan]{feedback_block}[/italic cyan]",
                                            title="[bold cyan]📊 SOC Analyst Feedback[/bold cyan]",
                                            border_style="cyan",
                                        )
                                    )
    
                                    audit.log("reporter_realtime", {
                                        "iteration": iteration,
                                        "new_findings": len(new_findings),
                                        "risk_score": report_state.risk_score,
                                        "suggestion": suggestion[:200],
                                    })
    
                            # Record step in ReportState
                            step = ToolStep(
                                step_number=step_counter,
                                tool_name=tool_name,
                                arguments=arguments,
                                result_snippet=result_str[:1000],
                                status=tool_status,
                                duration_seconds=round(tool_duration, 2),
                                reporter_comment=reporter_comment,
                            )
                            report_state.add_step(step)
    
                            # Tactical Policy Engine: Reinforcement Learning Reward & Q-update
                            if tactical_policy and pre_state_key:
                                try:
                                    diff_findings = max(0, len(report_state.findings) - findings_count_before)
                                    new_sevs = [f.severity for f in report_state.findings[-diff_findings:]] if diff_findings > 0 else []
                                    new_ports = max(0, len(report_state.attack_surface.open_ports) - open_ports_before)
                                    new_endpoints = max(0, len(report_state.attack_surface.parameterized_endpoints) - endpoints_before)
    
                                    # Extract qualitative semantic reward from Qwen Reporter's assessment
                                    semantic_rew = extract_semantic_reward(
                                        reporter_result=reporter_result if reporter_realtime else None,
                                        distilled_summary=distilled_intel.get("summary", ""),
                                    )
    
                                    reward = tactical_policy.reward_engine.compute_reward(
                                        tool_name=tool_name,
                                        pre_findings_count=findings_count_before,
                                        post_findings_count=len(report_state.findings),
                                        new_severities=new_sevs,
                                        new_ports_discovered=new_ports,
                                        new_endpoints_discovered=new_endpoints,
                                        tool_status=tool_status,
                                        is_duplicate_call=is_duplicate_call,
                                        semantic_boost=semantic_rew,
                                    )
                                    post_state_key = AttackStateExtractor.extract_state_key(report_state, tools_called)
                                    prev_tool = tools_called[-2] if len(tools_called) >= 2 else None
                                    new_q = tactical_policy.record_outcome(
                                        state_key=pre_state_key,
                                        action=tool_name,
                                        reward=reward,
                                        next_state_key=post_state_key,
                                        previous_action=prev_tool,
                                    )
                                    color = "green" if reward > 0 else ("red" if reward < 0 else "dim")
                                    console.print(
                                        f"[dim {color}]🎯 Policy Q-Update: {tool_name} → R={reward:+.1f} | Q={new_q:.2f} (Updates: {tactical_policy.total_updates})[/dim {color}]"
                                    )
                                    audit.log("tactical_policy_update", {
                                        "state": pre_state_key,
                                        "action": tool_name,
                                        "reward": reward,
                                        "q_value": new_q,
                                        "next_state": post_state_key,
                                    })
                                except Exception as e:
                                    logger.debug("Tactical policy update error: %s", e)
    
                            # Check for adaptive tactical pivot
                            pivot_info = _resolve_tactical_pivot(tool_name, result_str, report_state)
                            if pivot_info:
                                console.print(f"[bold magenta]🔄 Adaptive Tactical Pivot: {pivot_info['obstacle']} → Đề xuất '{pivot_info['pivot_tool']}'[/bold magenta]")
                                audit.log("tactical_pivot_triggered", {
                                    "iteration": iteration,
                                    "obstacle": pivot_info["obstacle"],
                                    "pivot_tool": pivot_info["pivot_tool"],
                                    "reason": pivot_info["reason"],
                                })
                                report_state.add_suggestion(f"Chuyển hướng chiến thuật sang '{pivot_info['pivot_tool']}': {pivot_info['reason']}")
    
                            # Stagnation tracking & convergence check (Surface Expansion Aware)
                            findings_count_after = len(report_state.findings)
                            surface_count_after = (
                                len(report_state.attack_surface.open_ports)
                                + len(report_state.attack_surface.parameterized_endpoints)
                                + len(report_state.attack_surface.login_forms)
                                + len(report_state.attack_surface.detected_technologies)
                                + len(report_state.attack_surface.subdomains)
                                + len(report_state.attack_surface.alive_subdomains)
                                + len(report_state.attack_surface.exposed_sensitive_files)
                                + len(report_state.attack_surface.cors_issues)
                                + len(report_state.attack_surface.hidden_discovered_paths)
                                + len(report_state.attack_surface.cookie_issues)
                            )
    
                            if findings_count_after > findings_count_before or surface_count_after > surface_count_before:
                                _stagnation_counter = 0
                            else:
                                _stagnation_counter += 1
                                console.print(
                                    f"[dim]⚡ Stagnation counter: {_stagnation_counter}/{stagnation_max_thresh}[/dim]"
                                )
    
                            # Forced convergence if stagnation limit reached
                            if _stagnation_counter >= stagnation_max_thresh:
                                roadmap = report_state.get_tactical_roadmap()
                                high_priority_untried = [a for a in roadmap.get("top_actions", []) if a.get("priority") in ("CRITICAL", "HIGH")]
                                if relentless_pursuit and high_priority_untried and _stagnation_rescues < stagnation_max_rescues and iteration < max_iterations - 2:
                                    _stagnation_rescues += 1
                                    _stagnation_counter = 0
                                    best_rescue_action = high_priority_untried[0]
                                    console.print(
                                        f"[bold red]🔥 Relentless Pursuit Active ({_stagnation_rescues}/{stagnation_max_rescues}): Ngăn chặn dừng sớm khi còn hành động {best_rescue_action['priority']}. Ép buộc thử '{best_rescue_action['action']}'.[/bold red]"
                                    )
                                    audit.log("relentless_stagnation_rescue", {
                                        "iteration": iteration,
                                        "rescue_attempt": _stagnation_rescues,
                                        "enforced_action": best_rescue_action,
                                    })
                                    rescue_notice = (
                                        f"\n\n[🔥 CHẾ ĐỘ NỖ LỰC CỰC ĐOAN (RELENTLESS PURSUIT) — TỪ CHỐI ĐẦU HÀNG]\n"
                                        f"Cảnh báo: Đã có {stagnation_max_thresh} bước không mở rộng thêm bề mặt. "
                                        f"TUY NHIÊN, lộ trình chiến thuật vẫn còn hành động mức ưu tiên {best_rescue_action['priority']}:\n"
                                        f"  → Công cụ: '{best_rescue_action['action']}'\n"
                                        f"  → Lý do: {best_rescue_action['recommendation']}\n"
                                        f"Hội đồng Chiến thuật YÊU CẦU Red Teamer thực thi ngay công cụ trên để vét cạn bề mặt trước khi kết thúc!"
                                    )
    
                                    # RAG Checkpoint: Recall past breakthroughs for stagnation rescue
                                    if vector_memory:
                                        try:
                                            rescue_query = f"bypass alternative vector stagnation {' '.join(report_state.attack_surface.detected_technologies)}"
                                            rescue_patterns = vector_memory.recall_attack_patterns(
                                                query=rescue_query,
                                                tech_stack=list(report_state.attack_surface.detected_technologies) or None,
                                                top_k=2,
                                                min_similarity=0.55,
                                                enable_rerank=True,
                                            )
                                            if rescue_patterns:
                                                rag_rescue_block = vector_memory.format_past_experience_block(rescue_patterns, max_tokens=400)
                                                rescue_notice += f"\n\n{rag_rescue_block}"
                                                report_state.record_rag_applied_patterns(rescue_patterns)
                                        except Exception:
                                            pass
                                    truncated_result = _truncate_tool_output_for_llm(result_str)
                                    tool_msg = f"Tool '{tool_name}' result: {truncated_result}"
                                    if feedback_block:
                                        tool_msg += f"\n\n{feedback_block}"
                                    if pivot_info:
                                        tool_msg += (
                                            f"\n\n[🔄 TỰ ĐỘNG CHUYỂN HƯỚNG CHIẾN THUẬT (ADAPTIVE PIVOT)]\n"
                                            f"Phát hiện vật cản: {pivot_info['obstacle']}.\n"
                                            f"Lệnh chuyển hướng: Gọi ngay công cụ '{pivot_info['pivot_tool']}'.\n"
                                            f"Lý do: {pivot_info['reason']}\n"
                                            f"HÃY THI HÀNH CÔNG CỤ NÀY Ở BƯỚC KẾ TIẾP!"
                                        )
                                    tool_msg += rescue_notice
                                    messages.append({"role": "user", "content": tool_msg})
                                    continue
    
                                console.print(
                                    f"\n[bold red]🛑 STAGNATION LIMIT REACHED ({_stagnation_counter} consecutive steps without new findings).[/bold red]"
                                )
                                console.print(
                                    "[bold yellow]Auto-converging assessment to generate final report...[/bold yellow]"
                                )
                                audit.log("stagnation_forced_finalize", {
                                    "iteration": iteration,
                                    "stagnation_steps": _stagnation_counter,
                                    "tools_called": len(tools_called),
                                    "findings_count": len(report_state.findings),
                                })
                                forced_summary = (
                                    f"Đánh giá an ninh đã hoàn thành sau {iteration} bước thực thi. "
                                    f"Mục tiêu đã được rà soát qua {len(set(tools_called))} công cụ khác nhau. "
                                    f"Trong {_stagnation_counter} bước gần nhất không phát hiện thêm bề mặt tấn công hoặc lỗ hổng mới. "
                                    f"Tổng cộng đã xác nhận {len(report_state.findings)} phát hiện với điểm rủi ro {report_state.risk_score}/10."
                                )
                                report_state.total_iterations = iteration
                                report_state.finalize(red_teamer_answer=forced_summary)
    
                                # Final polish pass by Reporter
                                console.print("\n[bold yellow][*] Reporter — Final Polish...[/bold yellow]")
                                await _reporter_final_polish(client, report_state)
    
                                audit.log("reporter_final_polish", {
                                    "findings_count": len(report_state.findings),
                                    "risk_score": report_state.risk_score,
                                })
    
                                # Cold Ingest Full Assessment Playbook into Vector DB
                                _cold_ingest_assessment_playbook(vector_memory, report_state, vectordb_cfg)
    
                                # Persist Tactical Policy learned knowledge
                                if tactical_policy:
                                    tactical_policy.save_policy()
                                    console.print(
                                        f"[dim green]💾 Tactical Policy: Đã lưu {len(tactical_policy.q_table)} trạng thái "
                                        f"và {tactical_policy.total_updates} cập nhật vào đĩa.[/dim green]"
                                    )
    
                                # Generate Multi-Format Reports (DOCX, Markdown, JSON)
                                report_path = _export_all_reports(report_state, audit.path, target_raw_str)
                                console.print(f"[bold green][+] Audit Trail: {audit.path}[/bold green]\n")
    
                                # Display final summary
                                severity_counts = report_state.get_severity_counts()
                                summary_table = Table(
                                    title="📊 Assessment Summary (Stagnation Converged)",
                                    border_style="cyan",
                                )
                                summary_table.add_column("Metric", style="cyan")
                                summary_table.add_column("Value", style="bold")
                                summary_table.add_row("Target", target_raw)
                                summary_table.add_row("Risk Score", f"{report_state.risk_score}/10 ({report_state.get_overall_risk_label()})")
                                summary_table.add_row("Total Findings", str(len(report_state.findings)))
                                summary_table.add_row("CRITICAL", str(severity_counts["CRITICAL"]))
                                summary_table.add_row("HIGH", str(severity_counts["HIGH"]))
                                summary_table.add_row("MEDIUM", str(severity_counts["MEDIUM"]))
                                summary_table.add_row("LOW", str(severity_counts["LOW"]))
                                summary_table.add_row("Tools Used", str(len(tools_called)))
                                summary_table.add_row("Iterations", str(iteration))
                                try:
                                    crit = report_state.generate_attack_graph().get_critical_path()
                                    if crit:
                                        summary_table.add_row("Critical Path", crit.to_summary())
                                except Exception:
                                    pass
                                console.print(summary_table)
    
                                audit.log("session_end", {
                                    "total_iterations": iteration,
                                    "tools_called": tools_called,
                                    "findings_count": len(report_state.findings),
                                    "risk_score": report_state.risk_score,
                                    "forced_stagnation": True,
                                })
                                audit.close()
                                return report_state.executive_summary or forced_summary
    
                            # Build message for Red Teamer (tool result + optional reporter feedback)
                            truncated_result = _truncate_tool_output_for_llm(result_str)
                            tool_msg = f"Tool '{tool_name}' result: {truncated_result}"
                            if feedback_block:
                                tool_msg += f"\n\n{feedback_block}"
                            if pivot_info:
                                tool_msg += (
                                    f"\n\n[🔄 TỰ ĐỘNG CHUYỂN HƯỚNG CHIẾN THUẬT (ADAPTIVE PIVOT)]\n"
                                    f"Phát hiện vật cản: {pivot_info['obstacle']}.\n"
                                    f"Lệnh chuyển hướng: Gọi ngay công cụ '{pivot_info['pivot_tool']}'.\n"
                                    f"Lý do: {pivot_info['reason']}\n"
                                    f"HÃY THI HÀNH CÔNG CỤ NÀY Ở BƯỚC KẾ TIẾP!"
                                )
                            if _stagnation_counter >= stagnation_warning_thresh:
                                roadmap = report_state.get_tactical_roadmap()
                                top_untried = [a for a in roadmap.get("top_actions", []) if a.get("priority") in ("CRITICAL", "HIGH")]
                                pivot_advice = ""
                                if top_untried:
                                    pivot_advice = f"\n🎯 ĐỔI HƯỚNG CHIẾN THUẬT NGAY: Chuyển sang công cụ '{top_untried[0]['action']}' ({top_untried[0]['recommendation']})."
                                tool_msg += (
                                    f"\n\n[⚠️ SYSTEM ALERT — STAGNATION DETECTED ({_stagnation_counter}/{stagnation_max_thresh})]\n"
                                    "Các bước vừa qua không phát hiện thêm bề mặt tấn công hay lỗ hổng mới. "
                                    "TUYỆT ĐỐI KHÔNG lặp lại công cụ hoặc quét lại mục tiêu cũ. "
                                    f"{pivot_advice}\n"
                                    "Nếu toàn bộ bề mặt tấn công và các vector chiến thuật khả thi đã được thử nghiệm hết, hãy xuất 'final_answer'."
                                )
                                console.print(
                                    f"[bold yellow]⚠️ Stagnation Warning ({_stagnation_counter}/{stagnation_max_thresh}): Cung cấp gợi ý đổi hướng chiến thuật[/bold yellow]"
                                )
    
                            messages.append({"role": "user", "content": tool_msg})

                            # Auto-save session checkpoint after each successful step
                            if hasattr(report_state, "save_checkpoint"):
                                try:
                                    sess_id = getattr(report_state, "session_id", "") or "default_session"
                                    session_dir = os.path.join(base_dir, "data", "sessions")
                                    os.makedirs(session_dir, exist_ok=True)
                                    checkpoint_file = os.path.join(session_dir, f"{sess_id}.json")
                                    report_state.save_checkpoint(checkpoint_file)
                                except Exception as e:
                                    logger.debug("Auto-checkpoint failed: %s", e)

                            # Display Real-time Tactical Mission HUD
                            _display_mission_dashboard(
                                report_state=report_state,
                                iteration=iteration,
                                max_iterations=max_iterations,
                                last_tool=tool_name,
                                last_duration=tool_duration,
                                stagnation_counter=_stagnation_counter,
                            )

                            continue
    
                        elif action == "final_answer":
                            final_text = parsed_json.get("text", "No final answer provided.")
    
                            # ★ MISSION COMPLETENESS GUARD & TARGETED OBJECTIVE VERIFICATION:
                            # Prevent premature final_answer if critical mission vectors remain untested
                            roadmap = report_state.get_tactical_roadmap()
                            progress_pct = roadmap.get("progress_percentage", 100)
                            untapped_actions = [a for a in roadmap.get("top_actions", []) if a.get("priority") in ("CRITICAL", "HIGH")]
    
                            # Check if user's explicit objective has unfulfilled direct requirements
                            should_guard, unfulfilled_objective_vectors = _evaluate_mission_guard(
                                report_state=report_state,
                                tools_called=tools_called,
                                progress_pct=progress_pct,
                                untapped_actions=untapped_actions,
                                iteration=iteration,
                                max_iterations=max_iterations,
                                guard_attempts=_mission_guard_attempts,
                                relentless_pursuit=relentless_pursuit,
                                max_guard_attempts=max_guard_challenges,
                            )
    
                            if should_guard:
                                _mission_guard_attempts += 1
                                reasons = []
                                if unfulfilled_objective_vectors:
                                    reasons.extend([f"  - 🎯 {v}" for v in unfulfilled_objective_vectors])
                                if untapped_actions:
                                    reasons.extend([
                                        f"  - [Ưu tiên {a['priority']}] {a['recommendation']} (Ví dụ công cụ: '{a['action']}')"
                                        for a in untapped_actions[:2]
                                    ])
                                reasons_str = "\n".join(reasons)
                                guard_prompt = (
                                    f"[⚠️ HỘI ĐỒNG CHIẾN THUẬT CẢNH BÁO — CHƯA ĐẠT MỤC TIÊU TỐI TÂN]\n"
                                    f"Mục tiêu của người dùng: '{report_state.mission_objective or report_state.target_objective}'.\n"
                                    f"Tiến độ hoàn thành mục tiêu ước tính: {progress_pct}%.\n"
                                    f"Vẫn còn các nhiệm vụ trọng tâm của sứ mệnh CHƯA ĐƯỢC THỰC HIỆN:\n"
                                    f"{reasons_str}\n\n"
                                    f"HÃY DỐC TOÀN LỰC kiểm tra các hướng trên nhằm hoàn thành triệt để mục tiêu của người dùng trước khi kết thúc!\n"
                                    f"Sau khi đã kiểm tra hoặc chắc chắn không thể khai thác thêm, bạn mới xuất 'final_answer'."
                                )
                                max_attempts_display = max(max_guard_challenges, 10) if relentless_pursuit else max_guard_challenges
                                console.print(
                                    f"[bold yellow]🛡️ Mission Guard Triggered ({_mission_guard_attempts}/{max_attempts_display}): Tiến độ {progress_pct}%, còn {len(untapped_actions) + len(unfulfilled_objective_vectors)} hướng trọng yếu. Thúc đẩy Red Teamer tiếp tục.[/bold yellow]"
                                )
                                audit.log("mission_guard_challenge", {
                                    "attempt": _mission_guard_attempts,
                                    "progress_pct": progress_pct,
                                    "untapped_actions": untapped_actions[:3],
                                    "unfulfilled_vectors": unfulfilled_objective_vectors,
                                })
                                messages.append({
                                    "role": "user",
                                    "content": guard_prompt,
                                })
                                continue
    
    
                            console.print(
                                Panel(
                                    f"[bold green]{final_text}[/bold green]",
                                    title="[bold magenta]🎯 Final Answer (Red Teamer)[/bold magenta]",
                                    border_style="magenta",
                                )
                            )
    
                            # ============================================================
                            # FINALIZE: Reporter final polish + DOCX generation
                            # ============================================================
                            report_state.total_iterations = iteration
                            report_state.finalize(red_teamer_answer=final_text)
    
                            # Final polish pass by Reporter
                            console.print("\n[bold yellow][*] Reporter — Final Polish...[/bold yellow]")
                            await _reporter_final_polish(client, report_state)
    
                            audit.log("reporter_final_polish", {
                                "findings_count": len(report_state.findings),
                                "risk_score": report_state.risk_score,
                            })
    
                            # Cold Ingest Full Assessment Playbook into Vector DB
                            _cold_ingest_assessment_playbook(vector_memory, report_state, vectordb_cfg)
    
                            # Persist Tactical Policy learned knowledge
                            if tactical_policy:
                                tactical_policy.save_policy()
                                console.print(
                                    f"[dim green]💾 Tactical Policy: Đã lưu {len(tactical_policy.q_table)} trạng thái "
                                    f"và {tactical_policy.total_updates} cập nhật vào đĩa.[/dim green]"
                                )
    
                            # Generate Multi-Format Reports (DOCX, Markdown, JSON)
                            report_path = _export_all_reports(report_state, audit.path, target_raw_str)
                            console.print(f"[bold green][+] Audit Trail: {audit.path}[/bold green]\n")
    
                            # Display final summary
                            severity_counts = report_state.get_severity_counts()
                            summary_table = Table(
                                title="📊 Assessment Summary",
                                border_style="cyan",
                            )
                            summary_table.add_column("Metric", style="cyan")
                            summary_table.add_column("Value", style="bold")
                            summary_table.add_row("Target", target_raw)
                            summary_table.add_row("Risk Score", f"{report_state.risk_score}/10 ({report_state.get_overall_risk_label()})")
                            summary_table.add_row("Total Findings", str(len(report_state.findings)))
                            summary_table.add_row("CRITICAL", str(severity_counts["CRITICAL"]))
                            summary_table.add_row("HIGH", str(severity_counts["HIGH"]))
                            summary_table.add_row("MEDIUM", str(severity_counts["MEDIUM"]))
                            summary_table.add_row("LOW", str(severity_counts["LOW"]))
                            summary_table.add_row("Tools Used", str(len(tools_called)))
                            summary_table.add_row("Iterations", str(iteration))
                            try:
                                crit = report_state.generate_attack_graph().get_critical_path()
                                if crit:
                                    summary_table.add_row("Critical Path", crit.to_summary())
                            except Exception:
                                pass
                            console.print(summary_table)
    
                            audit.log("session_end", {
                                "total_iterations": iteration,
                                "tools_called": tools_called,
                                "findings_count": len(report_state.findings),
                                "risk_score": report_state.risk_score,
                            })
                            audit.close()
    
                            return report_state.executive_summary or final_text
    
                        else:
                            invalid_action_msg = (
                                f"System Error: Unsupported action '{action}'. "
                                "Action must be either 'call_tool' or 'final_answer'."
                            )
                            console.print(f"[bold red]❌ {invalid_action_msg}[/bold red]")
                            messages.append({"role": "user", "content": invalid_action_msg})
                            continue
    
                    except Exception as e:
                        _consecutive_json_errors += 1
                        console.print(
                            f"[bold red]System Recovered from Error ({_consecutive_json_errors}): {e}[/bold red]"
                        )
    
                        # Escalating error recovery:
                        # - First 2 failures: gentle reminder
                        # - 3+ failures: inject concrete example to break the loop
                        if _consecutive_json_errors >= 3:
                            # Nuclear option: purge all error messages and inject a working example
                            # This breaks the 7B model out of infinite error loops
                            messages = [m for m in messages if not (
                                m.get("role") == "user" and m.get("content", "").startswith("ERROR:")
                            )]
                            # Pick next untried tool dynamically to avoid DUPLICATE BLOCKED
                            _recovery_tools = [
                                ("docker_whatweb", '{"url": "TARGET_HERE"}'),
                                ("docker_crawl_web", '{"url": "TARGET_HERE"}'),
                                ("docker_nuclei_scan", '{"target": "TARGET_HERE"}'),
                                ("docker_nikto_scan", '{"url": "TARGET_HERE"}'),
                                ("docker_subfinder", '{"domain": "TARGET_HERE"}'),
                                ("docker_dirb_scan", '{"url": "TARGET_HERE"}'),
                                ("docker_sensitive_files_scan", '{"url": "TARGET_HERE"}'),
                                ("docker_http_headers_audit", '{"url": "TARGET_HERE"}'),
                            ]
                            _next_tool = "docker_whatweb"
                            _next_args = '{"url": "TARGET_HERE"}'
                            for _rt_name, _rt_args in _recovery_tools:
                                if _rt_name not in tools_called:
                                    _next_tool = _rt_name
                                    _next_args = _rt_args
                                    break
                            recovery_msg = (
                                "SYSTEM RESET: Previous errors cleared. "
                                "Output ONLY a ```json``` block. Keep thought under 50 words. "
                                "NO text outside the json block.\n\n"
                                '```json\n'
                                '{\n'
                                '  "thought": "Next step reconnaissance",\n'
                                '  "action": "call_tool",\n'
                                f'  "tool_name": "{_next_tool}",\n'
                                f'  "arguments": {_next_args}\n'
                                '}\n'
                                '```\n\n'
                                "Replace TARGET_HERE with the actual target URL or domain."
                            )
                            messages.append({"role": "user", "content": recovery_msg})
                            _consecutive_json_errors = 0  # Reset after nuclear recovery
                            console.print("[bold yellow]🔄 NUCLEAR RECOVERY: Injected concrete example[/bold yellow]")
                        else:
                            error_msg = (
                                f"ERROR: JSON parse failed: {e}. "
                                "Reply with ONLY a ```json``` code block. No extra text outside the block. "
                                "Use simple ASCII text in the thought field to avoid encoding issues."
                            )
                            messages.append({"role": "user", "content": error_msg})
    
                        audit.log("json_error", {
                            "error": str(e),
                            "iteration": iteration,
                            "consecutive": _consecutive_json_errors,
                        })
                        continue
    
            except (KeyboardInterrupt, asyncio.CancelledError):
                console.print(
                    "\n[bold yellow]⚠️ Phát hiện lệnh ngắt từ người vận hành (Ctrl+C). "
                    "Đang tự động kết xuất báo cáo an toàn từ các phát hiện đã tích lũy...[/bold yellow]"
                )
                audit.log("user_interrupted", {
                    "iteration": iteration if 'iteration' in locals() else 0,
                    "findings_count": len(report_state.findings),
                    "tools_called": tools_called if 'tools_called' in locals() else [],
                })
                interrupt_summary = (
                    f"Đánh giá bị dừng bởi người vận hành sau {len(tools_called) if 'tools_called' in locals() else 0} công cụ. "
                    f"Đã xác nhận {len(report_state.findings)} phát hiện với điểm rủi ro {report_state.risk_score}/10."
                )
                report_state.total_iterations = iteration if 'iteration' in locals() else (len(tools_called) if 'tools_called' in locals() else 0)
                report_state.finalize(red_teamer_answer=interrupt_summary)
                try:
                    await _reporter_final_polish(client, report_state)
                except Exception:
                    pass
                if tactical_policy:
                    try:
                        tactical_policy.save_policy()
                    except Exception:
                        pass
                report_path = _export_all_reports(report_state, audit.path, target_raw_str)
                console.print(f"[bold green][+] Audit Trail: {audit.path}[/bold green]\n")
                audit.close()
                return report_state.executive_summary or interrupt_summary

            # Fallback if iterations exhausted
            report_state.total_iterations = max_iterations
            report_state.finalize(red_teamer_answer="Max iterations reached.")
            audit.log("session_timeout", {"total_iterations": max_iterations, "tools_called": tools_called})

            timeout_msg = "Max iterations reached without achieving final answer."
            console.print(f"[bold red]⚠️ {timeout_msg}[/bold red]")

            # Still run final polish and generate Multi-Format Reports (DOCX, Markdown, JSON)
            console.print("\n[bold yellow][*] Generating reports despite timeout...[/bold yellow]")
            await _reporter_final_polish(client, report_state)

            # Cold Ingest Full Assessment Playbook into Vector DB
            _cold_ingest_assessment_playbook(vector_memory, report_state, vectordb_cfg)

            # Persist Tactical Policy learned knowledge
            if tactical_policy:
                tactical_policy.save_policy()
                console.print(
                    f"[dim green]💾 Tactical Policy: Đã lưu {len(tactical_policy.q_table)} trạng thái "
                    f"và {tactical_policy.total_updates} cập nhật vào đĩa.[/dim green]"
                )

            report_path = _export_all_reports(report_state, audit.path, target_raw_str)
            console.print(f"[bold green][+] Audit Trail: {audit.path}[/bold green]\n")

            audit.close()
            return report_state.executive_summary or timeout_msg

