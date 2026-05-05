from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEVERITY_LABELS_FR = {
    "Critical": "Critique",
    "High": "Eleve",
    "Medium": "Moyen",
    "Low": "Bas",
    "Info": "Information",
}


@dataclass(slots=True)
class ServiceRecord:
    port: int
    protocol: str
    service: str
    banner: str | None = None
    product: str | None = None
    version: str | None = None
    vendor: str | None = None


@dataclass(slots=True)
class HostRecord:
    ip: str
    hostname: str | None = None
    is_alive: bool = False
    latency_ms: float | None = None
    services: list[ServiceRecord] = field(default_factory=list)
    operating_system: str | None = None
    device_type: str | None = None
    fingerprint: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SoftwareRecord:
    name: str
    version: str | None = None
    vendor: str | None = None
    install_date: str | None = None
    host: str | None = None


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    target: str
    category: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = "local"


@dataclass(slots=True)
class AssessmentReport:
    generated_at: str
    network: str | None
    hosts: list[HostRecord] = field(default_factory=list)
    software_inventory: list[SoftwareRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "network": self.network,
            "hosts": [asdict(host) for host in self.hosts],
            "software_inventory": [asdict(item) for item in self.software_inventory],
            "findings": [asdict(finding) for finding in self.findings],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AssessmentReport":
        return cls(
            generated_at=str(payload.get("generated_at") or now_iso()),
            network=payload.get("network"),
            hosts=[
                HostRecord(
                    ip=str(item.get("ip", "")),
                    hostname=item.get("hostname"),
                    is_alive=bool(item.get("is_alive", False)),
                    latency_ms=item.get("latency_ms"),
                    services=[
                        ServiceRecord(
                            port=int(service.get("port", 0)),
                            protocol=str(service.get("protocol") or "tcp"),
                            service=str(service.get("service") or "unknown"),
                            banner=service.get("banner"),
                            product=service.get("product"),
                            version=service.get("version"),
                            vendor=service.get("vendor"),
                        )
                        for service in item.get("services", [])
                        if isinstance(service, dict)
                    ],
                    operating_system=item.get("operating_system"),
                    device_type=item.get("device_type"),
                    fingerprint=item.get("fingerprint"),
                    notes=[str(note) for note in item.get("notes", [])],
                )
                for item in payload.get("hosts", [])
                if isinstance(item, dict) and item.get("ip")
            ],
            software_inventory=[
                SoftwareRecord(
                    name=str(item.get("name", "")),
                    version=item.get("version"),
                    vendor=item.get("vendor"),
                    install_date=item.get("install_date"),
                    host=item.get("host"),
                )
                for item in payload.get("software_inventory", [])
                if isinstance(item, dict) and item.get("name")
            ],
            findings=[
                Finding(
                    title=str(item.get("title", "Constat sans titre")),
                    severity=str(item.get("severity", "Info")),
                    target=str(item.get("target", "N/A")),
                    category=str(item.get("category", "General")),
                    description=str(item.get("description", "")),
                    recommendation=str(item.get("recommendation", "")),
                    evidence=item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
                    source=str(item.get("source", "agent")),
                )
                for item in payload.get("findings", [])
                if isinstance(item, dict)
            ],
            metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.target, item.title))


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary = {label: 0 for label in SEVERITY_LABELS_FR}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def compute_security_score(findings: list[Finding]) -> int:
    weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2, "Info": 0}
    score = 100
    for finding in findings:
        score -= weights.get(finding.severity, 0)
    return max(score, 0)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")
