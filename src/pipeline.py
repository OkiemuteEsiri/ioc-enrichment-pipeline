"""Offline IOC normalization, enrichment and prioritization pipeline.

Uses synthetic/local intelligence only; it does not query live reputation services.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from hashlib import sha256
import ipaddress, re
from typing import Iterable

HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")

@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str
    source: str
    confidence: int

    def __post_init__(self):
        if self.kind not in {"ipv4", "domain", "sha256"}: raise ValueError("unsupported IOC type")
        if not 0 <= self.confidence <= 100: raise ValueError("confidence must be 0-100")
        if not self.source.strip(): raise ValueError("source required")
        validate_value(self.value, self.kind)

@dataclass(frozen=True)
class Enrichment:
    indicator: Indicator
    intel_matches: int
    malicious_votes: int
    first_seen_days: int
    prevalence: int
    attack_techniques: tuple[str, ...]
    score: int
    priority: str
    finding_id: str

def validate_value(value: str, kind: str) -> None:
    if kind == "ipv4":
        ip = ipaddress.ip_address(value)
        if ip.version != 4: raise ValueError("expected IPv4")
    elif kind == "domain" and not DOMAIN_RE.match(value): raise ValueError("invalid domain")
    elif kind == "sha256" and not HASH_RE.match(value): raise ValueError("invalid SHA-256")

def normalize(value: str, kind: str) -> str:
    value = value.strip()
    return value.lower() if kind in {"domain", "sha256"} else str(ipaddress.ip_address(value))

def score_indicator(indicator: Indicator, intel: dict) -> Enrichment:
    matches = int(intel.get("intel_matches", 0)); votes = int(intel.get("malicious_votes", 0))
    age = max(0, int(intel.get("first_seen_days", 0))); prevalence = max(0, int(intel.get("prevalence", 0)))
    techniques = tuple(sorted(set(intel.get("attack_techniques", []))))
    score = min(100, round(indicator.confidence * .35 + min(matches, 5) * 6 + min(votes, 5) * 7 + min(age, 90) / 9 + (10 if prevalence <= 2 else 0)))
    priority = "P0" if score >= 85 else "P1" if score >= 70 else "P2" if score >= 45 else "P3"
    fid = "IOC-" + sha256(f"{indicator.kind}|{normalize(indicator.value, indicator.kind)}".encode()).hexdigest()[:12].upper()
    return Enrichment(indicator, matches, votes, age, prevalence, techniques, score, priority, fid)

def run(indicators: Iterable[Indicator], intelligence: dict[str, dict]) -> list[Enrichment]:
    seen = set(); results = []
    for item in indicators:
        key = (item.kind, normalize(item.value, item.kind))
        if key in seen: continue
        seen.add(key)
        results.append(score_indicator(item, intelligence.get(f"{key[0]}:{key[1]}", {})))
    return sorted(results, key=lambda x: (-x.score, x.finding_id))

def to_dict(result: Enrichment) -> dict:
    data = asdict(result); data["attack_techniques"] = list(result.attack_techniques); return data
