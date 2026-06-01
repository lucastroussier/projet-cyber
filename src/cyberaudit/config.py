from __future__ import annotations

import os
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
CVE_PROFILE_LIMITS = {
    "quick": {"max_cve_products": 5, "max_cves_per_product": 3},
    "standard": {"max_cve_products": 8, "max_cves_per_product": 4},
    "windows": {"max_cve_products": 20, "max_cves_per_product": 5},
    "infrastructure": {"max_cve_products": 12, "max_cves_per_product": 4},
    "full": {"max_cve_products": 40, "max_cves_per_product": 8},
}
NVD_API_KEY_FILE_ENV = "CYBERAUDIT_NVD_API_KEY_FILE"
DEFAULT_NVD_API_KEY_FILES = ("nvd_api_key.txt", "apikay.txt")


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
        cve_limits = CVE_PROFILE_LIMITS[profile]
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
            nvd_api_key=getattr(args, "nvd_api_key", None) or load_default_nvd_api_key(),
            max_cve_products=_int_or_default(getattr(args, "max_cve_products", None), cve_limits["max_cve_products"]),
            max_cves_per_product=_int_or_default(getattr(args, "max_cves_per_product", None), cve_limits["max_cves_per_product"]),
            max_remote_service_cves=_int_or_default(getattr(args, "max_remote_service_cves", None), 12),
            max_remote_cves_per_service=_int_or_default(getattr(args, "max_remote_cves_per_service", None), 3),
        )

    @classmethod
    def from_form(cls, form) -> "ScanConfig":
        profile = normalize_scan_profile(form.get("scan_profile", "standard"))
        profile_ports = SCAN_PROFILES[profile]["ports"]
        cve_limits = CVE_PROFILE_LIMITS[profile]
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
            nvd_api_key=form.get("nvd_api_key") or load_default_nvd_api_key(),
            max_cve_products=_int_or_default(form.get("max_cve_products"), cve_limits["max_cve_products"]),
            max_cves_per_product=_int_or_default(form.get("max_cves_per_product"), cve_limits["max_cves_per_product"]),
            max_remote_service_cves=_int_or_default(form.get("max_remote_service_cves"), 12),
            max_remote_cves_per_service=_int_or_default(form.get("max_remote_cves_per_service"), 3),
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


def load_default_nvd_api_key() -> str | None:
    for path in _nvd_api_key_file_candidates():
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in raw.splitlines():
            key = line.strip()
            if key and not key.startswith("#"):
                return key
    return None


def _nvd_api_key_file_candidates() -> list[Path]:
    candidates: list[Path] = []
    configured = os.environ.get(NVD_API_KEY_FILE_ENV)
    if configured:
        candidates.append(Path(configured).expanduser())

    roots = [Path.cwd(), Path(__file__).resolve().parents[2]]
    for root in roots:
        for filename in DEFAULT_NVD_API_KEY_FILES:
            candidates.append(root / filename)

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            key = str(candidate.resolve())
        except OSError:
            key = str(candidate.absolute())
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _int_or_default(value: object, default: int) -> int:
    if value is None or value == "":
        return default
    parsed = int(value)
    if parsed < 0:
        raise ValueError("La valeur numerique doit etre positive ou egale a 0.")
    return parsed


def parse_hosts(raw: str | None) -> list[str]:
    if not raw:
        return []
    hosts: list[str] = []
    for chunk in raw.replace(";", ",").split(","):
        host = chunk.strip()
        if host:
            hosts.append(host)
    return hosts
