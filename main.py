"""Interactive CLI entrypoint for Autonomous Local MLSecOps Agent.

Supports both interactive mode and single-shot command-line mode.

Usage:
    Interactive:  python main.py
    Single-shot:  python main.py --target 192.168.1.1 --mode recon
    Full pentest:  python main.py --target 192.168.1.1 --mode full
"""

import argparse
import asyncio
import sys

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from src.client.orchestrator import run_agent

console = Console()

BANNER = r"""[bold green]
  __  __ _      ____               ___             
 |  \/  | |    / ___| ___  ___   / _ \ _ __  ___  
 | |\/| | |    \___ \/ _ \/ __| | | | | '_ \/ __| 
 | |  | | |___  ___) |  __/ (__  | |_| | |_) \__ \ 
 |_|  |_|_____||____/ \___|\___|\___/| .__/|___/ 
                                      |_|          
[/bold green]"""

RECON_TOOLS = [
    "docker_resolve_dns", "docker_scan_ports_fast", "docker_scan_ports_deep", "docker_crawl_web",
    "browse_webpage", "docker_whatweb", "docker_nikto_scan",
    "docker_nuclei_scan", "docker_dirb_scan",
    "docker_subfinder", "docker_ffuf", "docker_testssl",
    "docker_sensitive_files_scan", "docker_cors_scan", "docker_httpx_probe",
    "docker_ssl_cert_audit", "docker_dns_security_audit", "docker_security_txt_audit", "docker_cookie_security_audit",
    "docker_http_headers_audit", "docker_api_docs_audit", "docker_subdomain_takeover_audit", "docker_waf_detect",
]

EXPLOIT_TOOLS = [
    "docker_sqlmap_scan", "docker_sqlmap_dump", "bruteforce_ssh",
    "bruteforce_http_form", "docker_wpscan", "docker_msf_search",
    "docker_bruteforce", "docker_xss_scan",
]



def _print_system_info():
    """Display the system initialization panel with tool lists."""
    recon_str = " | ".join(RECON_TOOLS)
    exploit_str = " | ".join(EXPLOIT_TOOLS)

    console.print(
        Panel.fit(
            "[bold green]Local MLSecOps Agent[/bold green] "
            "[dim]| Goal-Driven Autonomous Red Team & SOC Platform[/dim]\n\n"
            f"[bold cyan]🔍 Recon Tools ({len(RECON_TOOLS)}):[/bold cyan]\n"
            f"[dim]{recon_str}[/dim]\n\n"
            f"[bold red]💀 Exploit Tools ({len(EXPLOIT_TOOLS)}):[/bold red]\n"
            f"[dim]{exploit_str}[/dim]\n\n"
            "[bold yellow]⚡ Workflow:[/bold yellow] [dim]Recon First → Review → Full Pentest (Optional)[/dim]\n"
            "[bold red]🔒 HITL Required:[/bold red] [dim]sqlmap, sqlmap_dump, hydra, wpscan, msf[/dim]\n"
            "[bold magenta]Features:[/bold magenta] [dim]Dual-AI Goal Pursuit | Multi-Format Reports (DOCX/MD/JSON) | Real-time SOC Advisor[/dim]",
            title=f"[bold cyan]SYSTEM INITIALIZED — {len(RECON_TOOLS) + len(EXPLOIT_TOOLS)} TOOLS ONLINE[/bold cyan]",
            border_style="green",
        )
    )


def _print_health_check() -> bool:
    """Run and display pre-flight health checks with rich formatting."""
    from src.utils.config import check_environment
    console.print("\n[bold cyan]🔍 Running Pre-flight Health Check...[/bold cyan]")
    status = check_environment()

    table = Table(title="🛠️ System Environment Health Check", border_style="cyan")
    table.add_column("Component", style="cyan", width=18)
    table.add_column("Status", width=10)
    table.add_column("Details", style="dim")

    check_items = [
        ("docker", "Docker Daemon"),
        ("ollama", "Ollama API"),
        ("models", "AI Models"),
        ("wordlists", "Wordlists"),
    ]
    if "vectordb" in status:
        check_items.append(("vectordb", "Vector DB (RAG)"))

    for key, name in check_items:
        item = status.get(key, {})
        is_ok = item.get("ok", False)
        status_str = "[bold green]PASS[/bold green]" if is_ok else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_str, item.get("message", ""))

    console.print(table)
    if status["all_ok"]:
        console.print("[bold green]✅ All systems operational and ready for mission.[/bold green]\n")
    else:
        console.print("[bold red]⚠️ Some system components require attention before scanning.[/bold red]\n")
    return status["all_ok"]


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for single-shot mode."""
    parser = argparse.ArgumentParser(
        description="MLSecOps Agent — Autonomous Red Team Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                               # Interactive mode\n"
            "  python main.py --target 192.168.1.1           # Single target, recon mode\n"
            "  python main.py --target 192.168.1.1 --mode full  # Full pentest\n"
            "  python main.py --target site1.com,site2.com   # Multiple targets\n"
        ),
    )
    parser.add_argument("--version", "-v", action="version", version="MLSecOps Agent",
                        help="Show program version and exit.")
    parser.add_argument("--target", "-t", type=str, default=None,
                        help="Target IP/URL (comma-separated for multiple). Omit for interactive mode.")
    parser.add_argument("--mode", "-m", type=str, choices=["recon", "full"], default="recon",
                        help="Scan mode: 'recon' (default) or 'full' pentest.")
    parser.add_argument("--output-dir", "-o", type=str, default=None,
                        help="Custom output directory for generated reports and audit trails.")
    parser.add_argument("--no-hitl", action="store_true",
                        help="Disable Human-in-the-Loop approval for destructive tools (DANGEROUS).")
    parser.add_argument("--check", "--health", action="store_true", dest="check",
                        help="Run pre-flight health checks (Docker, Ollama, Models, Wordlists) and exit.")
    parser.add_argument("--list-tools", action="store_true",
                        help="List all registered security tools and exit.")
    parser.add_argument("--validate-config", action="store_true",
                        help="Validate config.yaml schema and exit.")
    parser.add_argument("--relentless", action="store_true", default=False,
                        help="Enable Relentless Pursuit Mode (extreme effort, zero premature surrender, maximum vector exhaustion).")
    parser.add_argument("--consolidate-memory", action="store_true", default=False,
                        help="Run Memory Consolidation Engine (cluster & merge similar attack patterns into Master Playbooks).")
    parser.add_argument("--resume", type=str, default=None,
                        help="Resume assessment session from a checkpoint JSON file or session ID.")
    return parser.parse_args()


async def _run_single_target(target: str, mode: str, resume_checkpoint: str | None = None) -> dict:
    """Run agent against a single target and return result dict."""
    console.print(
        f"\n[bold cyan]{'='*60}[/bold cyan]\n"
        f"[bold cyan]  TARGET: {target}[/bold cyan]\n"
        f"[bold cyan]{'='*60}[/bold cyan]"
    )

    prompt = (
        f"TARGET ACQUIRED: {target}\n"
        "MISSION: Perform comprehensive reconnaissance on this target. "
        "Map the entire attack surface: open ports, services, technologies, "
        "hidden paths, subdomains, SSL/TLS config, vulnerabilities. Be thorough and methodical. "
        "Report your findings in Vietnamese."
    )

    if mode == "full":
        prompt = (
            f"TARGET ACQUIRED: {target}\n"
            "MISSION: Perform a FULL penetration test on this target. "
            "Start with comprehensive recon, then escalate to exploitation. "
            "Use SQLmap on injectable endpoints, brute-force login forms, "
            "search for exploits for discovered CVEs. Use ALL offensive tools. "
            "Report in Vietnamese."
        )

    phase_label = "📡 RECONNAISSANCE" if mode == "recon" else "💀 FULL PENTEST"
    console.print(f"\n[bold {'green' if mode == 'recon' else 'red'}]{phase_label}[/bold {'green' if mode == 'recon' else 'red'}]")

    try:
        if resume_checkpoint and isinstance(resume_checkpoint, str):
            result = await run_agent(prompt, scan_mode=mode, resume_checkpoint=resume_checkpoint)
        else:
            result = await run_agent(prompt, scan_mode=mode)
        return {"target": target, "mode": mode.upper(), "result": result[:80] if result else "N/A"}
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        return {"target": target, "mode": "Interrupted", "result": "User cancelled"}
    except Exception as e:
        console.print(f"\n[bold red]Error running scan for {target}: {e}[/bold red]")
        return {"target": target, "mode": "Error", "result": str(e)[:80]}


async def _interactive_mode() -> None:
    """Main interactive loop."""
    console.print(BANNER)
    _print_system_info()

    session_results = []

    while True:
        try:
            target_input = Prompt.ask(
                "\n[bold cyan]Target(s)[/bold cyan] [dim](comma-separated, or 'exit' to quit)[/dim]"
            ).strip()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Session terminated by user. Exiting gracefully...[/bold yellow]")
            break

        if not target_input:
            continue

        cmd_lower = target_input.lower()
        if cmd_lower in ("exit", "quit", "q"):
            break

        if cmd_lower in ("help", "h", "?"):
            console.print(
                Panel.fit(
                    "[bold cyan]Available Commands:[/bold cyan]\n"
                    "  [bold green]<target>[/bold green]        - IP, URL, or domain (e.g., 192.168.1.1, testphp.vulnweb.com)\n"
                    "  [bold green]status / check[/bold green]  - Run system health check\n"
                    "  [bold green]tools[/bold green]           - Display registered recon and exploit tools\n"
                    "  [bold green]clear / cls[/bold green]     - Clear the console screen\n"
                    "  [bold green]exit / quit / q[/bold green] - Exit the console",
                    title="[bold yellow]Help Menu[/bold yellow]",
                    border_style="yellow",
                )
            )
            continue

        if cmd_lower in ("clear", "cls"):
            console.clear()
            console.print(BANNER)
            _print_system_info()
            continue

        if cmd_lower in ("status", "check", "health"):
            _print_health_check()
            continue

        if cmd_lower == "tools":
            _print_system_info()
            continue

        targets = [t.strip() for t in target_input.split(",") if t.strip()]

        for target in targets:
            # Phase 1: Recon
            result = await _run_single_target(target, "recon")
            session_results.append(result)

            # Ask for escalation
            if result["mode"] != "Interrupted":
                console.print(
                    Panel(
                        "[bold yellow]Trinh sát hoàn tất. Bạn muốn tiếp tục với Full Pentest?[/bold yellow]\n"
                        "[dim]Full Pentest sẽ sử dụng SQLmap, Hydra, Metasploit... (cần phê duyệt HITL)[/dim]",
                        border_style="yellow",
                    )
                )
                escalate = Prompt.ask(
                    "[bold yellow]Chọn chế độ[/bold yellow]",
                    choices=["full", "skip"],
                    default="skip",
                )

                if escalate == "full":
                    full_result = await _run_single_target(target, "full")
                    session_results.append(full_result)
                else:
                    console.print("[bold green]✓ Chỉ giữ kết quả Recon. Chuyển target tiếp.[/bold green]")

        if session_results:
            _print_session_summary(session_results)

    if session_results:
        console.print("\n[bold cyan]Final Session Summary:[/bold cyan]")
        _print_session_summary(session_results)

    console.print("[bold yellow]Exiting Local MLSecOps Agent v4.0. Goodbye![/bold yellow]")


async def _single_shot_mode(targets: list[str], mode: str, resume_checkpoint: str | None = None) -> None:
    """Run targets in single-shot mode (no interactive prompts)."""
    console.print(BANNER)
    _print_system_info()

    session_results = []
    for target in targets:
        if resume_checkpoint and isinstance(resume_checkpoint, str):
            result = await _run_single_target(target, mode, resume_checkpoint=resume_checkpoint)
        else:
            result = await _run_single_target(target, mode)
        session_results.append(result)

    if session_results:
        _print_session_summary(session_results)

    console.print("[bold yellow]Scan complete. Goodbye![/bold yellow]")


def _print_session_summary(results: list):
    """Display a summary table of all scanned targets."""
    table = Table(title="📊 Session Summary", border_style="cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Target", style="cyan")
    table.add_column("Mode", style="yellow")
    table.add_column("Result Preview", style="green", max_width=60)

    for i, r in enumerate(results, 1):
        table.add_row(str(i), r["target"], r["mode"], r["result"])

    console.print(table)


async def main() -> None:
    """Entry point: dispatch to interactive or single-shot mode."""
    args = _parse_args()

    # Apply HITL override
    if args.no_hitl:
        import os
        os.environ["MLSEC_HITL_ENABLED"] = "false"
        from src.utils.config import reload_config
        reload_config()
        console.print("[bold red]⚠️ HITL DISABLED — All destructive tools will execute without approval![/bold red]")

    # Apply Relentless Pursuit override
    if getattr(args, "relentless", False) is True:
        import os
        os.environ["MLSEC_AGENT_RELENTLESS_PURSUIT"] = "true"
        from src.utils.config import reload_config
        reload_config()
        console.print("[bold red]🔥 RELENTLESS PURSUIT MODE ACTIVATED — Maximum effort & vector exhaustion enabled![/bold red]")

    # Apply custom output directory override
    output_dir = getattr(args, "output_dir", None)
    if output_dir and isinstance(output_dir, str):
        import os
        os.environ["MLSEC_REPORTS_OUTPUT_DIR"] = output_dir
        from src.utils.config import reload_config
        reload_config()
        console.print(f"[bold cyan]📁 Custom reports directory:[/bold cyan] {output_dir}")

    if args.list_tools:
        _print_system_info()
        return

    if args.validate_config:
        from src.utils.config import validate_config
        is_valid, errors = validate_config()
        if is_valid:
            console.print("[bold green]✅ Configuration in config.yaml is valid![/bold green]")
        else:
            console.print("[bold red]❌ Configuration errors detected:[/bold red]")
            for err in errors:
                console.print(f"  - [red]{err}[/red]")
        return

    if getattr(args, "consolidate_memory", False) is True:
        import os
        from src.utils.config import load_config
        from src.utils.vector_store import VectorMemoryManager
        cfg = load_config()
        v_cfg = cfg.get("vectordb", {})
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = v_cfg.get("path", "data/chromadb")
        if not os.path.isabs(db_path):
            db_path = os.path.join(base_dir, db_path)
        vm = VectorMemoryManager(
            persist_dir=db_path,
            ollama_base_url=cfg.get("llm", {}).get("base_url", "http://localhost:11434/v1").replace("/v1", ""),
            embedding_model=v_cfg.get("ollama_model", "nomic-embed-text"),
            use_ollama=v_cfg.get("embedding_source", "ollama") == "ollama",
            flashrank_cache_dir=os.path.join(base_dir, "models_cache"),
        )
        console.print("[bold cyan]🔄 Running Memory Consolidation Engine (Checkpoint 4)...[/bold cyan]")
        report = vm.consolidate_memory(
            threshold=float(v_cfg.get("consolidation", {}).get("similarity_threshold", 0.85)),
            min_cluster_size=int(v_cfg.get("consolidation", {}).get("min_cluster_size", 5)),
        )
        console.print(
            f"[bold green]✅ Consolidation Complete:[/bold green]\n"
            f"  - Total records inspected: {report['total_records_inspected']}\n"
            f"  - Clusters identified: {report['clusters_found']}\n"
            f"  - Redundant records removed: {report['records_removed']}\n"
            f"  - Master Playbooks created: {report['master_playbooks_created']}"
        )
        return

    if args.check:
        _print_health_check()
        return

    # Quick pre-flight check at startup
    if not _print_health_check():
        console.print("[bold yellow]Proceeding anyway, but some tools may fail if prerequisites are missing.[/bold yellow]\n")

    if args.resume and not args.target:
        import os
        import json
        checkpoint_path = args.resume
        if not os.path.exists(checkpoint_path):
            candidate = os.path.join("data", "sessions", f"{args.resume}.json")
            if os.path.exists(candidate):
                checkpoint_path = candidate
            else:
                candidate2 = os.path.join("data", "sessions", args.resume)
                if os.path.exists(candidate2):
                    checkpoint_path = candidate2
        if os.path.exists(checkpoint_path):
            try:
                with open(checkpoint_path, "r", encoding="utf-8") as f:
                    cp_data = json.load(f)
                extracted_target = cp_data.get("target")
                if extracted_target:
                    console.print(f"[bold green]🎯 Tự động phát hiện mục tiêu từ Checkpoint: {extracted_target}[/bold green]")
                    await _single_shot_mode([extracted_target], cp_data.get("scan_mode", args.mode), resume_checkpoint=checkpoint_path)
                    return
            except Exception as e:
                console.print(f"[bold red]Lỗi đọc checkpoint: {e}[/bold red]")

    if args.target:
        targets = [t.strip() for t in args.target.split(",") if t.strip()]
        resume_cp = getattr(args, "resume", None)
        if resume_cp and isinstance(resume_cp, str) and resume_cp.strip():
            await _single_shot_mode(targets, args.mode, resume_checkpoint=resume_cp.strip())
        else:
            await _single_shot_mode(targets, args.mode)
    else:
        await _interactive_mode()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
