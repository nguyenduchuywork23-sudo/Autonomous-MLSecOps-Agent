"""Technology-Aware Adaptive Wordlist Selector.

Selects the most effective fuzzing dictionary based on technologies detected
on the target (e.g. WordPress, Spring Boot, PHP, API/Swagger, Sensitive files).
"""

import os
from typing import Optional

# Technology keyword mappings to specialized wordlist names
TECH_WORDLIST_MAP = [
    ("wordpress", "tech/wordpress.txt"),
    ("wp", "tech/wordpress.txt"),
    ("spring", "tech/spring.txt"),
    ("java", "tech/spring.txt"),
    ("actuator", "tech/spring.txt"),
    ("php", "tech/php.txt"),
    ("apache", "tech/php.txt"),
    ("api", "tech/api.txt"),
    ("swagger", "tech/api.txt"),
    ("fastapi", "tech/api.txt"),
    ("flask", "tech/api.txt"),
    ("django", "tech/sensitive_files.txt"),
    ("node", "tech/api.txt"),
    ("express", "tech/api.txt"),
]


def resolve_technology_wordlist(
    detected_technologies: list[str],
    base_dir: str | None = None,
) -> Optional[str]:
    """Resolve specialized wordlist path matching target's detected technologies."""
    if not detected_technologies:
        return None

    if not base_dir:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    wordlists_dir = os.path.join(base_dir, "wordlists")
    normalized_techs = [t.lower().strip() for t in detected_technologies if t]

    for keyword, rel_path in TECH_WORDLIST_MAP:
        for tech in normalized_techs:
            if keyword in tech or tech in keyword:
                candidate = os.path.join(wordlists_dir, rel_path)
                if os.path.exists(candidate) and os.path.getsize(candidate) > 10:
                    return candidate
                # Check directly in wordlists directory without tech/ prefix
                alt_candidate = os.path.join(wordlists_dir, os.path.basename(rel_path))
                if os.path.exists(alt_candidate) and os.path.getsize(alt_candidate) > 10:
                    return alt_candidate

    return None
