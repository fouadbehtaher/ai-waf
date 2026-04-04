from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class AttackFamily:
    attack_type: str
    label: str
    description: str
    aliases: tuple[str, ...] = ()


ATTACK_FAMILIES: tuple[AttackFamily, ...] = (
    AttackFamily(
        attack_type="sql_injection",
        label="SQL Injection",
        description="Database query manipulation attempts such as UNION, OR 1=1, SLEEP, or DROP patterns.",
    ),
    AttackFamily(
        attack_type="xss",
        label="Cross-Site Scripting (XSS)",
        description="Script injection attempts targeting browser execution via tags, handlers, or javascript: payloads.",
    ),
    AttackFamily(
        attack_type="ddos",
        label="DDoS / Request Flood",
        description="Burst traffic, token bucket exhaustion, or request flooding intended to degrade availability.",
        aliases=("rate_limit",),
    ),
    AttackFamily(
        attack_type="path_traversal",
        label="Path Traversal / LFI",
        description="Directory traversal and local file access attempts such as ../ or /etc/passwd payloads.",
    ),
    AttackFamily(
        attack_type="command_injection",
        label="Command Injection / RCE",
        description="Shell chaining and operating-system command execution attempts against the application stack.",
    ),
    AttackFamily(
        attack_type="brute_force",
        label="Brute Force / Login Abuse",
        description="Repeated authentication attempts, password spraying, or credential stuffing behavior.",
        aliases=("credential_stuffing",),
    ),
    AttackFamily(
        attack_type="reconnaissance",
        label="Reconnaissance / Scanning",
        description="Automated probing of many paths, admin surfaces, or technology fingerprints.",
    ),
    AttackFamily(
        attack_type="automation_abuse",
        label="Malicious Automation / Bot Activity",
        description="Suspicious scripted traffic from scanners, bots, or repeat abusive clients.",
        aliases=("malicious_automation",),
    ),
    AttackFamily(
        attack_type="payload_evasion",
        label="Suspicious Payload / Evasion",
        description="Encoded, ambiguous, or evasive payloads likely attempting to bypass normal signature checks.",
        aliases=("suspicious_payload",),
    ),
    AttackFamily(
        attack_type="anomaly",
        label="Anomaly / Zero-Day Indicator",
        description="Abnormal behavior flagged by the hybrid model despite lacking a fixed rule signature.",
    ),
)

OPERATIONAL_TAGS = {"blacklist", "manual_policy", "repeat_offender"}

_FAMILY_BY_TYPE: Dict[str, AttackFamily] = {family.attack_type: family for family in ATTACK_FAMILIES}
_ALIAS_TO_CANONICAL: Dict[str, str] = {}
_ORDER_INDEX: Dict[str, int] = {}

for index, family in enumerate(ATTACK_FAMILIES):
    _ORDER_INDEX[family.attack_type] = index
    _ALIAS_TO_CANONICAL[family.attack_type] = family.attack_type
    for alias in family.aliases:
        _ALIAS_TO_CANONICAL[alias] = family.attack_type


def canonical_attack_type(raw_attack_type: str) -> Optional[str]:
    normalized = str(raw_attack_type or "").strip().lower()
    if not normalized or normalized in OPERATIONAL_TAGS:
        return None
    return _ALIAS_TO_CANONICAL.get(normalized, normalized)


def attack_family_metadata(attack_type: str) -> dict:
    canonical = canonical_attack_type(attack_type) or str(attack_type or "").strip().lower()
    family = _FAMILY_BY_TYPE.get(canonical)
    if family:
        return {
            "attack_type": family.attack_type,
            "label": family.label,
            "description": family.description,
        }

    label = canonical.replace("_", " ").title() if canonical else "Unknown"
    return {
        "attack_type": canonical or "unknown",
        "label": label,
        "description": "Custom threat category observed by the WAF pipeline.",
    }


def build_attack_distribution(raw_attack_types: Iterable[str], raw_counts: Dict[str, int]) -> List[dict]:
    canonical_counts: Dict[str, int] = {family.attack_type: 0 for family in ATTACK_FAMILIES}

    for raw_attack_type in raw_attack_types:
        canonical = canonical_attack_type(raw_attack_type)
        if not canonical:
            continue
        canonical_counts[canonical] = canonical_counts.get(canonical, 0) + int(raw_counts.get(raw_attack_type, 0))

    rows: List[dict] = []
    known_canonicals = set(canonical_counts)

    for family in ATTACK_FAMILIES:
        rows.append(
            {
                "attack_type": family.attack_type,
                "label": family.label,
                "description": family.description,
                "count": int(canonical_counts.get(family.attack_type, 0)),
            }
        )

    for raw_attack_type in raw_attack_types:
        canonical = canonical_attack_type(raw_attack_type)
        if not canonical or canonical in known_canonicals:
            continue
        metadata = attack_family_metadata(canonical)
        rows.append(
            {
                "attack_type": metadata["attack_type"],
                "label": metadata["label"],
                "description": metadata["description"],
                "count": int(raw_counts.get(raw_attack_type, 0)),
            }
        )
        known_canonicals.add(canonical)

    rows.sort(key=lambda item: (-int(item.get("count", 0)), _ORDER_INDEX.get(item["attack_type"], 999), item["label"]))
    return rows
