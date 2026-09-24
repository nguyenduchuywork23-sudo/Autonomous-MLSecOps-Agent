"""Autonomous Threat Actor Attribution & MITRE ATT&CK Matrix Profiler.

Maps discovered vulnerabilities, tool actions, and exploit telemetry to the
MITRE ATT&CK Enterprise Matrix v14, computes behavioral similarity against known
Advanced Persistent Threat (APT) groups, and predicts adversary next steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class MitreTechnique:
    tactic: str
    technique_id: str
    name: str
    description: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
        }


@dataclass
class ThreatActorProfile:
    name: str
    aliases: List[str]
    origin: str
    primary_motivation: str  # e.g., Espionage, Financial, Sabotage
    signature_ttps: Set[str]  # Technique IDs like "T1190", "T1059"
    predicted_next_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "aliases": self.aliases,
            "origin": self.origin,
            "primary_motivation": self.primary_motivation,
            "signature_ttps": sorted(list(self.signature_ttps)),
            "predicted_next_steps": self.predicted_next_steps,
        }


@dataclass
class ThreatAttributionMatch:
    actor_name: str
    aliases: List[str]
    origin: str
    motivation: str
    similarity_score: float  # 0.00 to 1.00
    matched_ttps: List[str]
    predicted_next_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_name": self.actor_name,
            "aliases": self.aliases,
            "origin": self.origin,
            "motivation": self.motivation,
            "similarity_score": round(self.similarity_score, 3),
            "matched_ttps": self.matched_ttps,
            "predicted_next_steps": self.predicted_next_steps,
        }


@dataclass
class CampaignAttributionReport:
    observed_techniques: List[MitreTechnique]
    top_matched_actors: List[ThreatAttributionMatch]
    primary_adversary_archetype: str
    ciso_briefing: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observed_techniques": [t.to_dict() for t in self.observed_techniques],
            "top_matched_actors": [a.to_dict() for a in self.top_matched_actors],
            "primary_adversary_archetype": self.primary_adversary_archetype,
            "ciso_briefing": self.ciso_briefing,
        }


class ThreatActorProfiler:
    """Profiles observed campaign TTPs against MITRE ATT&CK v14 and known APT actors."""

    # Curated MITRE ATT&CK mapping from vulnerability/tool keywords
    VULN_TO_MITRE: Dict[str, List[MitreTechnique]] = {
        "SQL": [
            MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "SQL injection through public web interface"),
            MitreTechnique("Collection", "T1005", "Data from Local System", "Direct database extraction via SQL injection"),
        ],
        "COMMAND": [
            MitreTechnique("Execution", "T1059", "Command and Scripting Interpreter", "Arbitrary command execution via shell injection"),
            MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "Web-based command injection"),
        ],
        "RCE": [
            MitreTechnique("Execution", "T1059", "Command and Scripting Interpreter", "Remote code execution"),
            MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "Exploitation of web framework RCE"),
        ],
        "SSRF": [
            MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "Server-Side Request Forgery"),
            MitreTechnique("Credential Access", "T1552", "Unsecured Credentials", "Harvesting cloud instance metadata credentials"),
        ],
        "TRAVERSAL": [
            MitreTechnique("Discovery", "T1083", "File and Directory Discovery", "Path traversal reading sensitive system files"),
            MitreTechnique("Credential Access", "T1552.001", "Credentials In Files", "Exfiltration of /etc/passwd or config files"),
        ],
        "SECRET": [
            MitreTechnique("Credential Access", "T1552.001", "Credentials In Files", "Exposed API keys, tokens, or environment files"),
        ],
        "BRUTE": [
            MitreTechnique("Credential Access", "T1110", "Brute Force", "Password guessing against SSH or HTTP login services"),
        ],
        "NMAP": [
            MitreTechnique("Reconnaissance", "T1595", "Active Scanning", "Port and vulnerability scanning across target network"),
        ],
        "SUBFINDER": [
            MitreTechnique("Reconnaissance", "T1590", "Gather Victim Network Information", "DNS and subdomain OSINT enumeration"),
        ],
        "METASPLOIT": [
            MitreTechnique("Execution", "T1203", "Exploitation for Client Execution", "Automated weaponized exploit dispatch"),
            MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "Public exploit delivery"),
        ],
        "SPA": [
            MitreTechnique("Discovery", "T1083", "File and Directory Discovery", "Client-side bundle endpoint route discovery"),
        ],
    }

    # Curated APT Threat Actor Profiles
    KNOWN_ACTORS: List[ThreatActorProfile] = [
        ThreatActorProfile(
            name="APT28",
            aliases=["Fancy Bear", "STRONTIUM", "Sofacy", "Sednit"],
            origin="Russian Federation (GRU)",
            primary_motivation="State-Sponsored Cyber Espionage",
            signature_ttps={"T1595", "T1590", "T1190", "T1059", "T1110", "T1552.001"},
            predicted_next_steps=[
                "Deploy custom X-Agent / Zebrocy implants for persistence",
                "Execute credential dumping via LSASS / Mimikatz",
                "Establish lateral movement via Pass-the-Hash / SMB",
            ],
        ),
        ThreatActorProfile(
            name="APT29",
            aliases=["Cozy Bear", "NOBELIUM", "Midnight Blizzard"],
            origin="Russian Federation (SVR)",
            primary_motivation="Strategic Intelligence & Cloud Espionage",
            signature_ttps={"T1190", "T1552", "T1552.001", "T1059", "T1083"},
            predicted_next_steps=[
                "Abuse harvested cloud tokens against Microsoft 365 / AWS APIs",
                "Maintain stealth persistence via OAuth application consent grants",
                "Exfiltrate sensitive corporate communications via encrypted webhooks",
            ],
        ),
        ThreatActorProfile(
            name="Lazarus Group",
            aliases=["HIDDEN COBRA", "Zinc", "Labyrinth Chollima"],
            origin="Democratic People's Republic of Korea (RGB)",
            primary_motivation="Financial Theft & State Destabilization",
            signature_ttps={"T1190", "T1005", "T1059", "T1110", "T1552", "T1203"},
            predicted_next_steps=[
                "Manipulate database balances / transaction ledgers",
                "Deploy destructive wiper (HermeticWiper class) upon detection",
                "Exfiltrate cryptocurrency wallet private keys via external relays",
            ],
        ),
        ThreatActorProfile(
            name="Volt Typhoon",
            aliases=["BRONZE SILHOUETTE", "Vanguard Panda"],
            origin="People's Republic of China (State-Sponsored)",
            primary_motivation="Critical Infrastructure Pre-positioning",
            signature_ttps={"T1190", "T1059", "T1083", "T1552.001", "T1595"},
            predicted_next_steps=[
                "Living-off-the-land execution via WMI, PowerShell, and native binaries",
                "Pivot through edge routers and firewalls without external malware",
                "Establish dormant covert persistence for future kinetic disruption",
            ],
        ),
        ThreatActorProfile(
            name="FIN7",
            aliases=["Carbanak", "Sang炭ite Tempest", "ELBRUS"],
            origin="Eastern European Cybercrime Syndicate",
            primary_motivation="Financial Extortion & Web Skimming",
            signature_ttps={"T1190", "T1005", "T1059", "T1552.001", "T1083"},
            predicted_next_steps=[
                "Inject web skimmer into payment gateway / checkout forms",
                "Stage enterprise-wide ransomware (BlackCat / ALPHV)",
                "Demand double-extortion cryptocurrency ransom",
            ],
        ),
    ]

    def map_evidence_to_ttps(
        self,
        finding_titles: List[str],
        tool_names: Optional[List[str]] = None,
    ) -> List[MitreTechnique]:
        """Maps finding titles and tool names to MITRE ATT&CK techniques."""
        techniques: Dict[str, MitreTechnique] = {}

        # Scan finding titles
        for title in finding_titles:
            t_upper = title.upper()
            for kw, ttp_list in self.VULN_TO_MITRE.items():
                if kw in t_upper:
                    for ttp in ttp_list:
                        techniques[ttp.technique_id] = ttp

        # Scan tool names
        if tool_names:
            for tool in tool_names:
                tool_upper = tool.upper()
                for kw, ttp_list in self.VULN_TO_MITRE.items():
                    if kw in tool_upper:
                        for ttp in ttp_list:
                            techniques[ttp.technique_id] = ttp

        # Fallback if no specific match
        if not techniques and finding_titles:
            fallback = MitreTechnique("Initial Access", "T1190", "Exploit Public-Facing Application", "General vulnerability exploitation")
            techniques[fallback.technique_id] = fallback

        return list(techniques.values())

    def attribute_campaign(
        self,
        finding_titles: List[str],
        tool_names: Optional[List[str]] = None,
    ) -> CampaignAttributionReport:
        """Analyzes campaign activity and attributes it to threat actor profiles using Jaccard TTP similarity."""
        observed = self.map_evidence_to_ttps(finding_titles, tool_names)
        observed_ids: Set[str] = {t.technique_id for t in observed}

        matches: List[ThreatAttributionMatch] = []

        for actor in self.KNOWN_ACTORS:
            intersection = observed_ids.intersection(actor.signature_ttps)
            union = observed_ids.union(actor.signature_ttps)
            similarity = len(intersection) / len(union) if union else 0.0

            # Weighting: boost score if high-consequence initial access (T1190/T1059) matched
            if "T1190" in intersection and "T1059" in intersection:
                similarity = min(1.0, similarity * 1.25)

            matches.append(
                ThreatAttributionMatch(
                    actor_name=actor.name,
                    aliases=actor.aliases,
                    origin=actor.origin,
                    motivation=actor.primary_motivation,
                    similarity_score=similarity,
                    matched_ttps=sorted(list(intersection)),
                    predicted_next_steps=actor.predicted_next_steps,
                )
            )

        # Sort matches by similarity score descending
        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        top_matches = matches[:3]

        top_actor = top_matches[0] if top_matches else None
        if top_actor and top_actor.similarity_score >= 0.40:
            archetype = f"{top_actor.actor_name} ({top_actor.origin}) - {top_actor.motivation}"
            briefing = (
                f"Campaign TTPs exhibit {top_actor.similarity_score*100:.1f}% behavioral concordance with "
                f"{top_actor.actor_name} ({', '.join(top_actor.aliases[:2])}). "
                f"Observed kill-chain techniques ({', '.join(top_actor.matched_ttps)}) indicate state-sponsored "
                f"or organized syndicate reconnaissance. Immediate priority should be interdicting predicted next steps: "
                f"'{top_actor.predicted_next_steps[0]}'."
            )
        else:
            archetype = "Opportunistic Web Exploitation / Cybercrime Reconnaissance"
            briefing = (
                "Observed TTPs reflect broad opportunistic vulnerability scanning and public-facing exploitation. "
                "While not uniquely fingerprinted to a single state-sponsored APT, the attack vectors present severe "
                "risk of secondary ransomware infection or credential exfiltration if left unremediated."
            )

        return CampaignAttributionReport(
            observed_techniques=observed,
            top_matched_actors=top_matches,
            primary_adversary_archetype=archetype,
            ciso_briefing=briefing,
        )
