from __future__ import annotations

import re
import time
from typing import Any

import requests

from .models import Finding, HostRecord, ServiceRecord, SoftwareRecord


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
INTERESTING_SOFTWARE_HINTS = (
    "chrome",
    "firefox",
    "edge",
    "office",
    "acrobat",
    "reader",
    "java",
    "openvpn",
    "forticlient",
    "7-zip",
    "notepad++",
    "teamviewer",
    "zoom",
    "putty",
    "winscp",
    "vmware",
    "virtualbox",
)


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberAudit/0.1"})
        if api_key:
            self.session.headers["apiKey"] = api_key

    def find_product_cves(self, software: list[SoftwareRecord], max_products: int = 8, max_cves: int = 4) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_products(software, max_products=max_products)
        for product in selected:
            findings.extend(self._search_product(product, max_cves=max_cves))
            time.sleep(0.2)
        return findings

    def find_remote_service_cves(self, hosts: list[HostRecord], max_services: int = 12, max_cves: int = 3) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_remote_services(hosts, max_services=max_services)
        for host, service in selected:
            findings.extend(self._search_remote_service(host, service, max_cves=max_cves))
            time.sleep(0.2)
        return findings

    def _select_products(self, software: list[SoftwareRecord], max_products: int) -> list[SoftwareRecord]:
        def score(item: SoftwareRecord) -> tuple[int, str]:
            name = item.name.lower()
            interesting = any(hint in name for hint in INTERESTING_SOFTWARE_HINTS)
            vendor_penalty = 1 if (item.vendor or "").lower().startswith("microsoft") else 0
            return (2 if interesting else 0) - vendor_penalty, name

        candidates = [item for item in software if self._is_searchable(item)]
        ranked = sorted(candidates, key=score, reverse=True)
        return ranked[:max_products]

    def _select_remote_services(self, hosts: list[HostRecord], max_services: int) -> list[tuple[HostRecord, ServiceRecord]]:
        candidates: list[tuple[HostRecord, ServiceRecord]] = []
        seen: set[tuple[str, str, str]] = set()
        for host in hosts:
            for service in host.services:
                if not service.product or not service.version:
                    continue
                key = (service.vendor or "", service.product, service.version)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((host, service))

        def score(item: tuple[HostRecord, ServiceRecord]) -> tuple[int, str]:
            _, service = item
            product = (service.product or "").lower()
            versioned = 1 if service.version else 0
            common = 1 if product in {"openssh", "apache http server", "nginx", "microsoft iis", "webmin"} else 0
            return (common + versioned, f"{service.product}-{service.version}")

        return sorted(candidates, key=score, reverse=True)[:max_services]

    def _search_product(self, product: SoftwareRecord, max_cves: int) -> list[Finding]:
        keywords = " ".join(part for part in [product.vendor, product.name, product.version] if part)
        params = {
            "keywordSearch": keywords[:120],
            "resultsPerPage": min(max_cves * 5, 20),
        }
        try:
            response = self.session.get(NVD_API_URL, params=params, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            return [
                Finding(
                    title=f"Recherche CVE indisponible pour {product.name}",
                    severity="Info",
                    target=product.name,
                    category="Threat Intelligence",
                    description="La corrélation NVD n'a pas pu aboutir pour ce logiciel.",
                    recommendation="Relancer ultérieurement ou configurer une clé API NVD pour fiabiliser les requêtes.",
                    evidence={"error": str(exc)},
                    source="nvd",
                )
            ]

        payload = response.json()
        findings: list[Finding] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            description = self._pick_description(cve.get("descriptions", []))
            if not self._looks_relevant(product, cve, description):
                continue
            severity, score = self._extract_severity(cve.get("metrics", {}))
            cve_id = cve.get("id", "CVE-inconnue")
            findings.append(
                Finding(
                    title=f"{cve_id} associe a {product.name}",
                    severity=severity,
                    target=f"{product.host}:{product.name}" if product.host else product.name,
                    category="Known Vulnerability",
                    description=description or "Entree NVD potentiellement liee au logiciel inventorie.",
                    recommendation=f"Verifier si {product.name} {product.version or ''} est impacte, puis appliquer le correctif editeur correspondant.",
                    evidence={
                        "host": product.host,
                        "software": product.name,
                        "version": product.version,
                        "vendor": product.vendor,
                        "cve": cve_id,
                        "cvss_score": score,
                        "published": cve.get("published"),
                        "references": [ref.get("url") for ref in cve.get("references", [])[:3]],
                    },
                    source="nvd",
                )
            )
            if len(findings) >= max_cves:
                break
        return findings

    def _search_remote_service(self, host: HostRecord, service: ServiceRecord, max_cves: int) -> list[Finding]:
        keywords = " ".join(part for part in [service.vendor, service.product, service.version] if part)
        params = {
            "keywordSearch": keywords[:120],
            "resultsPerPage": min(max_cves * 5, 20),
        }
        try:
            response = self.session.get(NVD_API_URL, params=params, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException:
            return []

        payload = response.json()
        findings: list[Finding] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            description = self._pick_description(cve.get("descriptions", []))
            if not self._looks_relevant_service(service, cve, description):
                continue
            severity, score = self._extract_severity(cve.get("metrics", {}))
            cve_id = cve.get("id", "CVE-inconnue")
            findings.append(
                Finding(
                    title=f"{cve_id} potentiel sur {host.ip}:{service.port}",
                    severity=severity,
                    target=host.ip,
                    category="Known Vulnerability",
                    description=description or "Entree NVD potentiellement liee au service distant detecte.",
                    recommendation=f"Verifier si {service.product} {service.version or ''} est bien la version exposee sur {host.ip}, puis appliquer le correctif ou la mitigation editeur.",
                    evidence={
                        "host": host.ip,
                        "hostname": host.hostname,
                        "port": service.port,
                        "service": service.service,
                        "product": service.product,
                        "version": service.version,
                        "vendor": service.vendor,
                        "cve": cve_id,
                        "cvss_score": score,
                        "published": cve.get("published"),
                        "references": [ref.get("url") for ref in cve.get("references", [])[:3]],
                    },
                    source="nvd",
                )
            )
            if len(findings) >= max_cves:
                break
        return findings

    def _looks_relevant(self, product: SoftwareRecord, cve: dict[str, Any], description: str) -> bool:
        haystacks = [description.lower()]
        configurations = cve.get("configurations", [])
        for conf in configurations:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criterion = (match.get("criteria") or "").lower()
                    haystacks.append(criterion)
        merged = " ".join(haystacks)
        tokens = {token for token in re.split(r"[^a-z0-9]+", product.name.lower()) if len(token) > 2}
        if product.vendor:
            tokens |= {token for token in re.split(r"[^a-z0-9]+", product.vendor.lower()) if len(token) > 2}
        matches = sum(1 for token in tokens if token in merged)
        version_match = bool(product.version and str(product.version).lower() in merged)
        return matches >= 1 and (version_match or matches >= 2)

    def _looks_relevant_service(self, service: ServiceRecord, cve: dict[str, Any], description: str) -> bool:
        haystacks = [description.lower()]
        configurations = cve.get("configurations", [])
        for conf in configurations:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criterion = (match.get("criteria") or "").lower()
                    haystacks.append(criterion)
        merged = " ".join(haystacks)
        tokens = {token for token in re.split(r"[^a-z0-9]+", (service.product or "").lower()) if len(token) > 2}
        if service.vendor:
            tokens |= {token for token in re.split(r"[^a-z0-9]+", service.vendor.lower()) if len(token) > 2}
        matches = sum(1 for token in tokens if token in merged)
        version_match = bool(service.version and service.version.lower() in merged)
        return matches >= 1 and (version_match or matches >= 2)

    def _extract_severity(self, metrics: dict[str, Any]) -> tuple[str, float | None]:
        candidates = [
            ("cvssMetricV40", "cvssData"),
            ("cvssMetricV31", "cvssData"),
            ("cvssMetricV30", "cvssData"),
            ("cvssMetricV2", "cvssData"),
        ]
        for metric_name, data_key in candidates:
            items = metrics.get(metric_name)
            if not items:
                continue
            data = items[0].get(data_key, {})
            base_score = data.get("baseScore")
            if base_score is None:
                continue
            return self._score_to_severity(float(base_score)), float(base_score)
        return "Medium", None

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"

    def _pick_description(self, descriptions: list[dict[str, Any]]) -> str:
        for item in descriptions:
            if item.get("lang") == "en":
                return item.get("value", "")
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    def _is_searchable(self, item: SoftwareRecord) -> bool:
        name = item.name.lower()
        if len(name) < 3:
            return False
        excluded = ("update", "redistributable", "driver", "security update", "language pack")
        return not any(token in name for token in excluded)
