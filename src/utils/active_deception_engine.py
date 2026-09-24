"""Autonomous Active Deception & Honey-Token Topology Synthesizer.

Generates high-interaction active cyber deception assets, canary honey-tokens,
decoy routes, and tripwire alert rules to catch adversaries early in reconnaissance
and lateral movement kill-chains.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DeceptionAssetType(str, Enum):
    CANARY_AWS_KEY = "CANARY_AWS_KEY"
    CANARY_JWT = "CANARY_JWT"
    CANARY_DB_CREDENTIAL = "CANARY_DB_CREDENTIAL"
    DECOY_ENDPOINT = "DECOY_ENDPOINT"
    CLIENT_BREADCRUMB = "CLIENT_BREADCRUMB"


@dataclass
class CanaryToken:
    token_id: str
    token_type: DeceptionAssetType
    token_value: str
    target_placement: str  # e.g., ".env", "localStorage", "HTTP Header"
    webhook_callback_url: str
    description: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "token_value": self.token_value,
            "target_placement": self.target_placement,
            "webhook_callback_url": self.webhook_callback_url,
            "description": self.description,
            "created_at": self.created_at,
        }


@dataclass
class DecoyRouteTrap:
    path: str
    http_method: str
    synthetic_response_code: int
    synthetic_body: str
    tripwire_alert_rule: str
    severity: str = "EMERGENCY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "http_method": self.http_method,
            "synthetic_response_code": self.synthetic_response_code,
            "synthetic_body": self.synthetic_body,
            "tripwire_alert_rule": self.tripwire_alert_rule,
            "severity": self.severity,
        }


@dataclass
class DeceptionTopology:
    target_domain: str
    canary_tokens: List[CanaryToken] = field(default_factory=list)
    decoy_traps: List[DecoyRouteTrap] = field(default_factory=list)
    tripwire_waf_rules: List[str] = field(default_factory=list)
    total_assets: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "total_assets": self.total_assets,
            "canary_tokens": [t.to_dict() for t in self.canary_tokens],
            "decoy_traps": [d.to_dict() for d in self.decoy_traps],
            "tripwire_waf_rules": self.tripwire_waf_rules,
        }


class ActiveDeceptionEngine:
    """Synthesizes active cyber deception topologies tailored to the application's attack surface."""

    def __init__(self, callback_host: str = "canary-telemetry.mesh"):
        self.callback_host = callback_host

    def _generate_canary_id(self, seed: str) -> str:
        h = hashlib.sha256(f"{seed}:{time.time()}:{secrets.token_hex(8)}".encode()).hexdigest()
        return f"canary_{h[:12]}"

    def generate_aws_honeytoken(self, domain: str) -> CanaryToken:
        """Generates an AWS Access Key ID and Secret canary token pair."""
        canary_id = self._generate_canary_id(f"aws_{domain}")
        key_suffix = secrets.token_hex(8).upper()
        access_key = f"AKIA{key_suffix}"
        secret_key = secrets.token_urlsafe(32)
        callback = f"https://{self.callback_host}/api/v1/trigger/{canary_id}"

        content = (
            f"AWS_ACCESS_KEY_ID={access_key}\n"
            f"AWS_SECRET_ACCESS_KEY={secret_key}\n"
            f"AWS_DEFAULT_REGION=us-east-1\n"
            f"# CANARY_ID={canary_id}"
        )

        return CanaryToken(
            token_id=canary_id,
            token_type=DeceptionAssetType.CANARY_AWS_KEY,
            token_value=content,
            target_placement=".env.staging / config.json / public repo decoy",
            webhook_callback_url=callback,
            description="High-interaction AWS credential canary triggering alerts on any STS GetCallerIdentity call.",
        )

    def generate_jwt_honeytoken(self, domain: str) -> CanaryToken:
        """Generates a fake high-privilege JWT token canary."""
        canary_id = self._generate_canary_id(f"jwt_{domain}")
        callback = f"https://{self.callback_host}/api/v1/trigger/{canary_id}"

        # Synthetic JWT structure: header.payload.signature
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        # Payload containing canary_id and fake superadmin claims
        payload = "eyJzdWIiOiJhZG1pbi1jYW5hcnkiLCJyb2xlIjoic3VwZXJhZG1pbiIsImlzcyI6ImF1dGgtY2FuYXJ5LmludGVybmFsIiwiY2FuYXJ5X2lkIjoi" + canary_id + "\"}"
        sig = secrets.token_urlsafe(24).replace("-", "").replace("_", "")
        fake_jwt = f"{header}.{payload}.{sig}"

        return CanaryToken(
            token_id=canary_id,
            token_type=DeceptionAssetType.CANARY_JWT,
            token_value=fake_jwt,
            target_placement="localStorage['_canary_admin_session'] / client cookies",
            webhook_callback_url=callback,
            description="Decoy administrative JWT canary triggering instant SOC alerts upon presentation.",
        )

    def generate_database_honeytoken(self, domain: str) -> CanaryToken:
        """Generates a canary database connection string."""
        canary_id = self._generate_canary_id(f"db_{domain}")
        callback = f"https://{self.callback_host}/api/v1/trigger/{canary_id}"
        db_user = f"pg_backup_{canary_id[:6]}"
        db_pass = secrets.token_urlsafe(12)
        uri = f"postgresql://{db_user}:{db_pass}@{self.callback_host}:5432/finance_prod"

        return CanaryToken(
            token_id=canary_id,
            token_type=DeceptionAssetType.CANARY_DB_CREDENTIAL,
            token_value=uri,
            target_placement="docker-compose.yml / database.yml / environment secrets",
            webhook_callback_url=callback,
            description="Database credential canary configured to alert on initial TCP handshake connection.",
        )

    def generate_decoy_route_traps(self, domain: str, tech_stack: Optional[List[str]] = None) -> List[DecoyRouteTrap]:
        """Synthesizes high-interaction decoy route traps based on target tech stack."""
        traps: List[DecoyRouteTrap] = []
        rule_base_id = 998000

        # Generic High-Value Administrative Traps
        traps.append(
            DecoyRouteTrap(
                path="/api/v1/internal/admin-debug",
                http_method="GET",
                synthetic_response_code=200,
                synthetic_body='{"status":"active","debug_mode":true,"cluster_nodes":["10.142.0.2","10.142.0.3"]}',
                tripwire_alert_rule=(
                    f'SecRule REQUEST_URI "@streq /api/v1/internal/admin-debug" \\\n'
                    f'    "id:{rule_base_id + 1},phase:1,deny,status:403,log,\\\n'
                    f'    msg:\'TRIPWIRE DECEPTION: High-Severity Decoy Admin Route Accessed by Adversary\',\\\n'
                    f'    tag:\'deception-trap\',severity:\'EMERGENCY\'"'
                ),
            )
        )

        traps.append(
            DecoyRouteTrap(
                path="/.env.staging.bak",
                http_method="GET",
                synthetic_response_code=200,
                synthetic_body="DB_HOST=canary-db.mesh\nSECRET_KEY=canary_secret_tripwire_alpha\n",
                tripwire_alert_rule=(
                    f'SecRule REQUEST_URI "@streq /.env.staging.bak" \\\n'
                    f'    "id:{rule_base_id + 2},phase:1,deny,status:403,log,\\\n'
                    f'    msg:\'TRIPWIRE DECEPTION: Sensitive Environment Decoy File Accessed\',\\\n'
                    f'    tag:\'deception-trap\',severity:\'EMERGENCY\'"'
                ),
            )
        )

        traps.append(
            DecoyRouteTrap(
                path="/v2/management/token-exchange",
                http_method="POST",
                synthetic_response_code=400,
                synthetic_body='{"error":"invalid_grant","canary_alert":"triggered"}',
                tripwire_alert_rule=(
                    f'SecRule REQUEST_URI "@streq /v2/management/token-exchange" \\\n'
                    f'    "id:{rule_base_id + 3},phase:1,deny,status:403,log,\\\n'
                    f'    msg:\'TRIPWIRE DECEPTION: Decoy Token Exchange Probe Detected\',\\\n'
                    f'    tag:\'deception-trap\',severity:\'EMERGENCY\'"'
                ),
            )
        )

        return traps

    def synthesize_deception_topology(
        self,
        domain: str,
        tech_stack: Optional[List[str]] = None,
    ) -> DeceptionTopology:
        """Synthesizes a complete enterprise active defense & deception topology."""
        aws_token = self.generate_aws_honeytoken(domain)
        jwt_token = self.generate_jwt_honeytoken(domain)
        db_token = self.generate_database_honeytoken(domain)
        canary_tokens = [aws_token, jwt_token, db_token]

        decoy_traps = self.generate_decoy_route_traps(domain, tech_stack)
        waf_rules = [trap.tripwire_alert_rule for trap in decoy_traps]

        # Add generic honeytoken detection rule
        canary_ids = [t.token_id for t in canary_tokens]
        canary_regex = "|".join(canary_ids)
        waf_rules.append(
            f'SecRule REQUEST_COOKIES|REQUEST_HEADERS|ARGS "@rx (?i)({canary_regex})" \\\n'
            f'    "id:998100,phase:1,deny,status:403,log,\\\n'
            f'    msg:\'TRIPWIRE DECEPTION: Presentation of Injected Honeytoken Detected\',\\\n'
            f'    tag:\'honeytoken-alert\',severity:\'EMERGENCY\'"'
        )

        return DeceptionTopology(
            target_domain=domain,
            canary_tokens=canary_tokens,
            decoy_traps=decoy_traps,
            tripwire_waf_rules=waf_rules,
            total_assets=len(canary_tokens) + len(decoy_traps),
        )
