from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    88,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    464,
    548,
    593,
    636,
    873,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5000,
    5001,
    5357,
    5432,
    5900,
    5985,
    5986,
    6379,
    8000,
    8080,
    8081,
    8088,
    8090,
    8091,
    8443,
    9000,
    9001,
    9090,
    9091,
    9200,
    10000,
    1311,
    32400,
    3268,
    3269,
    9389,
    27017,
]
DISCOVERY_PORTS = [22, 80, 135, 139, 443, 445, 5000, 5001, 5985, 5986, 8080, 8081]
DEFAULT_UDP_DISCOVERY_PORTS = [137, 161]
SCAN_PROFILES = {
    "quick": {
        "ports": [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080],
        "udp": [137],
    },
    "standard": {
        "ports": DEFAULT_PORTS,
        "udp": DEFAULT_UDP_DISCOVERY_PORTS,
    },
    "windows": {
        "ports": [53, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3389, 5985, 5986, 3268, 3269, 9389],
        "udp": [137, 5355],
    },
    "infrastructure": {
        "ports": sorted(set(DEFAULT_PORTS + [53, 123, 161, 162, 515, 631, 9100])),
        "udp": [53, 123, 137, 161, 5353, 5355],
    },
    "full": {
        "ports": sorted(set(DEFAULT_PORTS + [53, 110, 123, 161, 162, 515, 631, 9100])),
        "udp": [53, 123, 137, 161, 5353, 5355],
    },
}


@dataclass(slots=True)
class ScanConfig:
    network_cidr: str | None = None
    scan_profile: str = "standard"
    ports: list[int] = field(default_factory=lambda: DEFAULT_PORTS.copy())
    discovery_ports: list[int] = field(default_factory=lambda: DISCOVERY_PORTS.copy())
    udp_discovery_ports: list[int] = field(default_factory=lambda: DEFAULT_UDP_DISCOVERY_PORTS.copy())
    enable_udp_discovery: bool = True
    snmp_communities: list[str] = field(default_factory=lambda: ["public"])
    connect_timeout: float = 0.35
    discovery_timeout: float = 0.18
    udp_timeout: float = 0.4
    banner_timeout: float = 0.35
    workers: int = 192
    port_workers: int = 24
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    audit_localhost: bool = False
    skip_network: bool = False
    allow_non_private_targets: bool = False
    nvd_api_key: str | None = None
    max_cve_products: int = 8
    max_cves_per_product: int = 4
    max_remote_service_cves: int = 12
    max_remote_cves_per_service: int = 3
    max_hosts: int = 1024

    @classmethod
    def from_args(cls, args) -> "ScanConfig":
        profile = normalize_scan_profile(getattr(args, "scan_profile", "standard"))
        profile_ports = SCAN_PROFILES[profile]["ports"]
        ports = parse_ports(args.ports) if getattr(args, "ports", None) else profile_ports.copy()
        udp_ports_raw = getattr(args, "udp_discovery_ports", None)
        udp_ports = parse_ports(udp_ports_raw) if udp_ports_raw else SCAN_PROFILES[profile]["udp"].copy()
        return cls(
            network_cidr=getattr(args, "network", None),
            scan_profile=profile,
            ports=ports,
            connect_timeout=float(getattr(args, "timeout", 0.35)),
            discovery_ports=[port for port in DISCOVERY_PORTS if port in ports] or DISCOVERY_PORTS.copy(),
            udp_discovery_ports=udp_ports,
            enable_udp_discovery=not bool(getattr(args, "disable_udp_discovery", False)),
            snmp_communities=parse_hosts(getattr(args, "snmp_communities", None)) or ["public"],
            discovery_timeout=0.18,
            udp_timeout=float(getattr(args, "udp_timeout", 0.4)),
            banner_timeout=0.35,
            workers=int(getattr(args, "workers", 192)),
            port_workers=24,
            output_dir=Path(getattr(args, "output", "reports")),
            audit_localhost=bool(getattr(args, "audit_localhost", False)),
            skip_network=bool(getattr(args, "skip_network", False)),
            allow_non_private_targets=bool(getattr(args, "allow_non_private", False)),
            nvd_api_key=getattr(args, "nvd_api_key", None),
        )

    @classmethod
    def from_form(cls, form) -> "ScanConfig":
        profile = normalize_scan_profile(form.get("scan_profile", "standard"))
        profile_ports = SCAN_PROFILES[profile]["ports"]
        ports_raw = form.get("ports", "")
        ports = parse_ports(ports_raw) if ports_raw else profile_ports.copy()
        udp_ports_raw = form.get("udp_discovery_ports", "")
        udp_ports = parse_ports(udp_ports_raw) if udp_ports_raw else SCAN_PROFILES[profile]["udp"].copy()
        return cls(
            network_cidr=(form.get("network") or None),
            scan_profile=profile,
            ports=ports,
            connect_timeout=float(form.get("timeout", 0.35)),
            discovery_ports=[port for port in DISCOVERY_PORTS if port in ports] or DISCOVERY_PORTS.copy(),
            udp_discovery_ports=udp_ports,
            enable_udp_discovery=form.get("disable_udp_discovery") != "on",
            snmp_communities=parse_hosts(form.get("snmp_communities")) or ["public"],
            discovery_timeout=0.18,
            udp_timeout=float(form.get("udp_timeout", 0.4)),
            workers=int(form.get("workers", 192)),
            port_workers=24,
            output_dir=Path(form.get("output_dir") or "reports"),
            audit_localhost=form.get("audit_localhost") == "on",
            skip_network=form.get("skip_network") == "on",
            allow_non_private_targets=form.get("allow_non_private_targets") == "on",
            nvd_api_key=form.get("nvd_api_key") or None,
        )


def parse_ports(raw: str) -> list[int]:
    ports: set[int] = set()
    for chunk in raw.split(","):
        token = chunk.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            for port in range(start, end + 1):
                validate_port(port)
                ports.add(port)
            continue
        port = int(token)
        validate_port(port)
        ports.add(port)
    return sorted(ports)


def validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port invalide: {port}")


def normalize_scan_profile(value: str | None) -> str:
    profile = (value or "standard").strip().lower()
    if profile not in SCAN_PROFILES:
        allowed = ", ".join(sorted(SCAN_PROFILES))
        raise ValueError(f"Profil de scan invalide: {profile}. Valeurs autorisees: {allowed}")
    return profile


def parse_hosts(raw: str | None) -> list[str]:
    if not raw:
        return []
    hosts: list[str] = []
    for chunk in raw.replace(";", ",").split(","):
        host = chunk.strip()
        if host:
            hosts.append(host)
    return hosts
