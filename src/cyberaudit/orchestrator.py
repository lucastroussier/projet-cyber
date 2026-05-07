from __future__ import annotations

from .config import ScanConfig
from .models import AssessmentReport, Finding, HostRecord, now_iso, sort_findings
from .network import NetworkScanner, detect_local_network_cidr
from .remote_analysis import RemoteRiskAnalyzer
from .reporting import ReportWriter
from .vuln import NvdClient
from .windows_audit import WindowsLocalAuditor


class AssessmentEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def run(self) -> tuple[AssessmentReport, dict]:
        hosts: list[HostRecord] = []
        findings: list[Finding] = []
        metadata: dict = {
            "scope": {},
            "notes": [],
            "cve_correlation": {
                "provider": "NVD",
                "api_key_configured": bool(self.config.nvd_api_key),
                "max_cve_products": self.config.max_cve_products,
                "max_cves_per_product": self.config.max_cves_per_product,
                "max_remote_service_cves": self.config.max_remote_service_cves,
                "max_remote_cves_per_service": self.config.max_remote_cves_per_service,
            },
        }
        software_inventory = []

        if not self.config.skip_network and not self.config.network_cidr:
            autodetected = detect_local_network_cidr()
            if autodetected:
                self.config.network_cidr = autodetected
                metadata["notes"].append(f"Sous-reseau local detecte automatiquement: {autodetected}")
            else:
                self.config.skip_network = True
                metadata["notes"].append("Sous-reseau local non detecte automatiquement. Scan reseau ignore.")

        if not self.config.skip_network:
            scanner = NetworkScanner(self.config)
            hosts = scanner.scan()
            findings.extend(RemoteRiskAnalyzer().analyze(hosts))
            metadata["scope"]["network"] = self.config.network_cidr
            if hosts:
                nvd = NvdClient(api_key=self.config.nvd_api_key)
                findings.extend(
                    nvd.find_remote_service_cves(
                        hosts,
                        max_services=self.config.max_remote_service_cves,
                        max_cves=self.config.max_remote_cves_per_service,
                    )
                )

        if self.config.audit_localhost:
            auditor = WindowsLocalAuditor()
            audit_result = auditor.run()
            findings.extend(audit_result.findings)
            software_inventory.extend(audit_result.software_inventory)
            metadata["localhost_audit"] = audit_result.metadata
            localhost_record = self._localhost_host_record(audit_result.metadata)
            if localhost_record and not any(host.ip == localhost_record.ip and host.hostname == localhost_record.hostname for host in hosts):
                hosts.append(localhost_record)

        if software_inventory:
            metadata["cve_correlation"]["software_inventory_count"] = len(software_inventory)
            if not self.config.nvd_api_key and (self.config.max_cve_products == 0 or self.config.max_cve_products > 8):
                metadata["notes"].append("Correlation CVE etendue sans cle API NVD: l'analyse peut etre lente a cause des limites publiques NVD.")
            nvd = NvdClient(api_key=self.config.nvd_api_key)
            findings.extend(
                nvd.find_product_cves(
                    software_inventory,
                    max_products=self.config.max_cve_products,
                    max_cves=self.config.max_cves_per_product,
                )
            )
        elif self.config.audit_localhost:
            metadata["notes"].append("Aucun logiciel inventorie n'a ete collecte pour la correlation CVE.")

        report = AssessmentReport(
            generated_at=now_iso(),
            network=self.config.network_cidr,
            hosts=hosts,
            software_inventory=software_inventory,
            findings=sort_findings(findings),
            metadata=metadata,
        )
        writer = ReportWriter()
        paths = writer.write(report, self.config.output_dir)
        return report, paths

    def _localhost_host_record(self, metadata: dict) -> HostRecord | None:
        return self._windows_host_record_from_metadata("127.0.0.1", metadata, "Audit local Windows effectue.")

    def _windows_host_record_from_metadata(self, ip_or_target: str, metadata: dict, audit_note: str) -> HostRecord | None:
        system_profile = metadata.get("system_profile") or {}
        os_data = system_profile.get("os") or {}
        hardware = system_profile.get("hardware") or {}
        hostname = os_data.get("CSName")
        caption = os_data.get("Caption")
        version = os_data.get("Version")
        build = os_data.get("BuildNumber")
        os_label = " ".join(part for part in [caption, f"v{version}" if version else None, f"build {build}" if build else None] if part) or None
        notes = [audit_note]
        model = " ".join(part for part in [hardware.get("Manufacturer"), hardware.get("Model")] if part).strip()
        if model:
            notes.append(f"Materiel: {model}")
        if hardware.get("Domain"):
            relation = "domaine" if hardware.get("PartOfDomain") else "workgroup"
            notes.append(f"{relation}: {hardware.get('Domain')}")
        return HostRecord(
            ip=ip_or_target,
            hostname=hostname or ip_or_target,
            is_alive=True,
            latency_ms=0.0,
            services=[],
            operating_system=os_label,
            device_type="poste_local_windows",
            fingerprint="Poste Windows local audite",
            notes=notes,
        )

    def _merge_host_record(self, hosts: list[HostRecord], incoming: HostRecord) -> None:
        for host in hosts:
            same_ip = host.ip == incoming.ip
            same_hostname = bool(host.hostname and incoming.hostname and host.hostname.lower() == incoming.hostname.lower())
            if not (same_ip or same_hostname):
                continue
            host.hostname = host.hostname or incoming.hostname
            host.operating_system = host.operating_system or incoming.operating_system
            host.device_type = incoming.device_type or host.device_type
            host.fingerprint = incoming.fingerprint or host.fingerprint
            host.notes.extend(note for note in incoming.notes if note not in host.notes)
            host.is_alive = host.is_alive or incoming.is_alive
            return
        hosts.append(incoming)
