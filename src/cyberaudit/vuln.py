from __future__ import annotations

import re
import time
from typing import Any

import requests

from .models import Finding, HostRecord, ServiceRecord, SoftwareRecord


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
INTERESTING_SOFTWARE_HINTS = (
    "windows",
    "windows server",
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
    "openssl",
    "python",
    "node.js",
    "nodejs",
    "git",
)
TOKEN_STOPWORDS = {
    "application",
    "apps",
    "corporation",
    "desktop",
    "edition",
    "for",
    "inc",
    "installer",
    "ltd",
    "microsoft",
    "program",
    "runtime",
    "software",
    "the",
    "update",
    "version",
    "x64",
    "x86",
}


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberAudit/0.1"})
        if api_key:
            self.session.headers["apiKey"] = api_key
        self.delay_seconds = 0.75 if api_key else 6.2
        self._last_request_at = 0.0

    def find_product_cves(self, software: list[SoftwareRecord], max_products: int = 8, max_cves: int = 4) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_products(software, max_products=max_products)
        for product in selected:
            findings.extend(self._search_product(product, max_cves=max_cves))
        return findings

    def find_remote_service_cves(self, hosts: list[HostRecord], max_services: int = 12, max_cves: int = 3) -> list[Finding]:
        findings: list[Finding] = []
        selected = self._select_remote_services(hosts, max_services=max_services)
        for host, service in selected:
            findings.extend(self._search_remote_service(host, service, max_cves=max_cves))
        return findings

    def _select_products(self, software: list[SoftwareRecord], max_products: int) -> list[SoftwareRecord]:
        def score(item: SoftwareRecord) -> tuple[int, str]:
            name = item.name.lower()
            interesting = any(hint in name for hint in INTERESTING_SOFTWARE_HINTS)
            os_bonus = 4 if "windows" in name else 0
            version_bonus = 1 if item.version else 0
            vendor_penalty = 1 if (item.vendor or "").lower().startswith("microsoft") and "windows" not in name else 0
            return os_bonus + (3 if interesting else 0) + version_bonus - vendor_penalty, name

        candidates = self._dedupe_software([item for item in software if self._is_searchable(item)])
        ranked = sorted(candidates, key=score, reverse=True)
        if max_products == 0:
            return ranked
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
            return common + versioned, f"{service.product}-{service.version}"

        ranked = sorted(candidates, key=score, reverse=True)
        if max_services == 0:
            return ranked
        return ranked[:max_services]

    def _search_product(self, product: SoftwareRecord, max_cves: int) -> list[Finding]:
        if max_cves <= 0:
            return []

        findings: list[Finding] = []
        seen_cves: set[str] = set()
        try:
            use_cpe_lookup = bool(self.api_key) or "windows" in product.name.lower()
            cpe_names = self._find_cpe_names(product, max_cpes=2) if use_cpe_lookup else []
            for cpe_name in cpe_names:
                cpe_findings = self._search_product_cpe(product, cpe_name, max_cves=max_cves - len(findings))
                self._extend_unique(findings, cpe_findings, seen_cves, max_cves)
                if len(findings) >= max_cves:
                    return findings

            keyword_findings = self._search_product_keywords(product, max_cves=max_cves - len(findings))
            self._extend_unique(findings, keyword_findings, seen_cves, max_cves)
            return findings
        except requests.RequestException as exc:
            if findings:
                return findings
            return [self._nvd_error_finding(product, exc)]

    def _search_product_cpe(self, product: SoftwareRecord, cpe_name: str, max_cves: int) -> list[Finding]:
        if max_cves <= 0:
            return []
        params = {"cpeName": cpe_name, "resultsPerPage": min(max_cves * 6, 30)}
        payload = self._get_json(NVD_API_URL, params=params)
        findings: list[Finding] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            description = self._pick_description(cve.get("descriptions", []))
            if not self._looks_relevant(product, cve, description):
                continue
            findings.append(self._finding_from_cve(cve, description, product, match_method="cpe", cpe_name=cpe_name))
            if len(findings) >= max_cves:
                break
        return findings

    def _search_product_keywords(self, product: SoftwareRecord, max_cves: int) -> list[Finding]:
        if max_cves <= 0:
            return []
        keywords = self._product_keywords(product, include_version=True)
        if not keywords:
            return []
        params = {"keywordSearch": keywords[:120], "resultsPerPage": min(max_cves * 6, 30)}
        payload = self._get_json(NVD_API_URL, params=params)
        findings: list[Finding] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            description = self._pick_description(cve.get("descriptions", []))
            if not self._looks_relevant(product, cve, description):
                continue
            findings.append(self._finding_from_cve(cve, description, product, match_method="keyword", cpe_name=None))
            if len(findings) >= max_cves:
                break
        return findings

    def _search_remote_service(self, host: HostRecord, service: ServiceRecord, max_cves: int) -> list[Finding]:
        if max_cves <= 0:
            return []
        keywords = " ".join(part for part in [service.vendor, service.product, service.version] if part)
        params = {"keywordSearch": keywords[:120], "resultsPerPage": min(max_cves * 5, 20)}
        try:
            payload = self._get_json(NVD_API_URL, params=params)
        except requests.RequestException:
            return []

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
                        "last_modified": cve.get("lastModified"),
                        "match_method": "keyword",
                        "references": [ref.get("url") for ref in cve.get("references", [])[:5]],
                    },
                    source="nvd",
                )
            )
            if len(findings) >= max_cves:
                break
        return findings

    def _find_cpe_names(self, product: SoftwareRecord, max_cpes: int) -> list[str]:
        keywords = self._product_keywords(product, include_version=False)
        if not keywords:
            return []
        params = {"keywordSearch": keywords[:120], "resultsPerPage": 20}
        try:
            payload = self._get_json(NVD_CPE_API_URL, params=params)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return []
            raise

        candidates: list[tuple[int, str]] = []
        for entry in payload.get("products", []):
            cpe = entry.get("cpe", {}) if isinstance(entry, dict) else {}
            cpe_name = cpe.get("cpeName")
            if not cpe_name:
                continue
            titles = [title.get("title", "") for title in cpe.get("titles", []) if isinstance(title, dict)]
            score = self._score_cpe_candidate(product, cpe_name, " ".join(titles))
            if score > 0:
                candidates.append((score, cpe_name))

        seen: set[str] = set()
        selected: list[str] = []
        for _, cpe_name in sorted(candidates, key=lambda item: (item[0], item[1]), reverse=True):
            if cpe_name in seen:
                continue
            seen.add(cpe_name)
            selected.append(cpe_name)
            if len(selected) >= max_cpes:
                break
        return selected

    def _finding_from_cve(
        self,
        cve: dict[str, Any],
        description: str,
        product: SoftwareRecord,
        match_method: str,
        cpe_name: str | None,
    ) -> Finding:
        severity, score = self._extract_severity(cve.get("metrics", {}))
        cve_id = cve.get("id", "CVE-inconnue")
        evidence = {
            "host": product.host,
            "software": product.name,
            "version": product.version,
            "vendor": product.vendor,
            "cve": cve_id,
            "cvss_score": score,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "match_method": match_method,
            "references": [ref.get("url") for ref in cve.get("references", [])[:5]],
        }
        if cpe_name:
            evidence["cpe"] = cpe_name
        return Finding(
            title=f"{cve_id} associe a {product.name}",
            severity=severity,
            target=f"{product.host}:{product.name}" if product.host else product.name,
            category="Known Vulnerability",
            description=description or "Entree NVD potentiellement liee au logiciel inventorie.",
            recommendation=f"Verifier si {product.name} {product.version or ''} est impacte, puis appliquer le correctif editeur correspondant.",
            evidence=evidence,
            source="nvd",
        )

    def _nvd_error_finding(self, product: SoftwareRecord, exc: requests.RequestException) -> Finding:
        return Finding(
            title=f"Recherche CVE indisponible pour {product.name}",
            severity="Info",
            target=f"{product.host}:{product.name}" if product.host else product.name,
            category="Threat Intelligence",
            description="La correlation NVD n'a pas pu aboutir pour ce logiciel.",
            recommendation="Relancer ulterieurement ou configurer une cle API NVD pour fiabiliser les requetes.",
            evidence={"error": str(exc), "software": product.name, "version": product.version, "vendor": product.vendor},
            source="nvd",
        )

    def _extend_unique(self, findings: list[Finding], incoming: list[Finding], seen_cves: set[str], max_cves: int) -> None:
        for finding in incoming:
            cve_id = str(finding.evidence.get("cve", ""))
            if cve_id and cve_id in seen_cves:
                continue
            findings.append(finding)
            if cve_id:
                seen_cves.add(cve_id)
            if len(findings) >= max_cves:
                break

    def _get_json(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        self._throttle()
        response = self.session.get(url, params=params, timeout=self.timeout)
        if response.status_code == 429:
            retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
            time.sleep(retry_after or max(self.delay_seconds, 6.2))
            self._last_request_at = 0.0
            self._throttle()
            response = self.session.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    def _throttle(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_at
        if self._last_request_at and elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)
        self._last_request_at = time.monotonic()

    def _parse_retry_after(self, value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(float(value), 0.0)
        except ValueError:
            return None

    def _looks_relevant(self, product: SoftwareRecord, cve: dict[str, Any], description: str) -> bool:
        haystacks = [description.lower()]
        haystacks.extend(self._configuration_criteria(cve.get("configurations", [])))
        merged = " ".join(haystacks).replace("_", " ")
        tokens = self._tokens(product.name)
        vendor_tokens = self._tokens(product.vendor)
        matches = sum(1 for token in tokens if token in merged)
        vendor_matches = sum(1 for token in vendor_tokens if token in merged)
        version_match = self._version_matches(product.version, merged)
        if "windows" in product.name.lower() and vendor_matches:
            return matches >= 1
        return matches >= 1 and (version_match or matches + vendor_matches >= 2)

    def _looks_relevant_service(self, service: ServiceRecord, cve: dict[str, Any], description: str) -> bool:
        haystacks = [description.lower()]
        haystacks.extend(self._configuration_criteria(cve.get("configurations", [])))
        merged = " ".join(haystacks).replace("_", " ")
        tokens = self._tokens(service.product)
        vendor_tokens = self._tokens(service.vendor)
        matches = sum(1 for token in tokens if token in merged)
        vendor_matches = sum(1 for token in vendor_tokens if token in merged)
        version_match = self._version_matches(service.version, merged)
        return matches >= 1 and (version_match or matches + vendor_matches >= 2)

    def _configuration_criteria(self, configurations: Any) -> list[str]:
        criteria: list[str] = []
        if not isinstance(configurations, list):
            return criteria
        for conf in configurations:
            if not isinstance(conf, dict):
                continue
            for node in conf.get("nodes", []):
                criteria.extend(self._node_criteria(node))
        return criteria

    def _node_criteria(self, node: dict[str, Any]) -> list[str]:
        criteria: list[str] = []
        if not isinstance(node, dict):
            return criteria
        for match in node.get("cpeMatch", []):
            if isinstance(match, dict) and match.get("criteria"):
                criteria.append(str(match["criteria"]).lower())
        for child in node.get("children", []):
            if isinstance(child, dict):
                criteria.extend(self._node_criteria(child))
        return criteria

    def _score_cpe_candidate(self, product: SoftwareRecord, cpe_name: str, titles: str) -> int:
        text = f"{cpe_name} {titles}".lower().replace("_", " ")
        name_tokens = self._tokens(product.name)
        vendor_tokens = self._tokens(product.vendor)
        if not name_tokens:
            return 0
        matches = sum(1 for token in name_tokens if token in text)
        vendor_matches = sum(1 for token in vendor_tokens if token in text)
        version_match = self._version_matches(product.version, text)
        score = matches + (vendor_matches * 2)
        if version_match:
            score += 3
        if "windows" in product.name.lower() and ":o:" in cpe_name:
            score += 2
        if vendor_tokens and not vendor_matches:
            score -= 1
        return score if score >= 2 else 0

    def _product_keywords(self, product: SoftwareRecord, include_version: bool) -> str:
        name = product.name.strip()
        vendor = (product.vendor or "").strip()
        version = (product.version or "").strip()
        merged = f"{vendor} {name}".lower()
        if "windows server 2025" in merged:
            name = "Windows Server 2025"
            vendor = "Microsoft"
        elif "windows server 2022" in merged:
            name = "Windows Server 2022"
            vendor = "Microsoft"
        elif "windows server 2019" in merged:
            name = "Windows Server 2019"
            vendor = "Microsoft"
        elif "windows 11" in merged:
            name = "Windows 11"
            vendor = "Microsoft"
        elif "windows 10" in merged:
            name = "Windows 10"
            vendor = "Microsoft"
        parts = [vendor, name]
        if include_version and version and "windows" not in name.lower():
            parts.append(version)
        return re.sub(r"\s+", " ", " ".join(part for part in parts if part)).strip()

    def _tokens(self, value: str | None) -> set[str]:
        if not value:
            return set()
        tokens = set()
        for token in re.split(r"[^a-z0-9]+", value.lower()):
            if len(token) <= 2 or token.isdigit() or token in TOKEN_STOPWORDS:
                continue
            tokens.add(token)
        return tokens

    def _version_matches(self, version: str | None, text: str) -> bool:
        if not version:
            return False
        normalized = version.lower().strip()
        if not normalized:
            return False
        if normalized in text:
            return True
        without_build = re.sub(r"\s+build\s+\d+", "", normalized).strip()
        if without_build and without_build in text:
            return True
        version_tokens = [token for token in re.split(r"[^0-9.]+", normalized) if token and any(char.isdigit() for char in token)]
        return any(len(token) >= 3 and token in text for token in version_tokens)

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
        excluded = ("update for", "security update", "language pack", "redistributable", "driver package")
        return not any(token in name for token in excluded)

    def _dedupe_software(self, software: list[SoftwareRecord]) -> list[SoftwareRecord]:
        deduped: list[SoftwareRecord] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in software:
            key = (
                item.name.strip().lower(),
                (item.version or "").strip().lower(),
                (item.vendor or "").strip().lower(),
                (item.host or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped
