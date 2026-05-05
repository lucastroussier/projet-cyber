from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any

import requests
from flask import Flask, abort, jsonify, render_template, request, send_file

from .config import SCAN_PROFILES, ScanConfig, normalize_scan_profile
from .models import AssessmentReport, Finding, HostRecord, SoftwareRecord, now_iso, sort_findings
from .orchestrator import AssessmentEngine
from .reporting import ReportWriter


AGENT_ENDPOINT = "/api/agent/report"
AGGREGATE_REPORT_BASENAME = "cyberaudit_agents_consolide"


def create_collector_app(output_dir: str, token: str) -> Flask:
    if not token:
        raise ValueError("Le collecteur requiert un token non vide.")

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "cyberaudit-collector-dev-key"
    app.config["OUTPUT_DIR"] = str(Path(output_dir).resolve())
    app.config["COLLECTOR_TOKEN"] = token
    aggregate_lock = Lock()

    @app.get("/")
    def index():
        reports_dir = Path(app.config["OUTPUT_DIR"])
        reports = sorted(reports_dir.glob("cyberaudit_*.html"), reverse=True) if reports_dir.exists() else []
        aggregate_report = reports_dir / f"{AGGREGATE_REPORT_BASENAME}.html"
        return render_template(
            "collector.html",
            reports=reports,
            endpoint=AGENT_ENDPOINT,
            aggregate_report=aggregate_report if aggregate_report.exists() else None,
        )

    @app.post(AGENT_ENDPOINT)
    def receive_report():
        if not _is_authorized(request.headers, app.config["COLLECTOR_TOKEN"]):
            abort(401)

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Payload JSON invalide."}), 400

        try:
            report = AssessmentReport.from_dict(payload)
        except (TypeError, ValueError) as exc:
            return jsonify({"error": f"Rapport agent invalide: {exc}"}), 400

        metadata = dict(report.metadata)
        metadata["collector_received_at"] = now_iso()
        metadata["collector_remote_addr"] = request.remote_addr
        report.metadata = metadata

        with aggregate_lock:
            paths = _write_aggregate_report(report, Path(app.config["OUTPUT_DIR"]))
        return jsonify({"status": "ok", "html": paths["html"].name, "json": paths["json"].name, "mode": "aggregate"})

    @app.get("/reports/<path:filename>")
    def view_report(filename: str):
        base_dir = Path(app.config["OUTPUT_DIR"]).resolve()
        path = (base_dir / filename).resolve()
        if base_dir not in path.parents and path != base_dir:
            abort(404)
        if not path.exists() or not path.is_file():
            abort(404)
        return send_file(path)

    return app


def run_agent(
    collector: str,
    token: str,
    output_dir: str,
    nvd_api_key: str | None = None,
    agent_id: str | None = None,
    scan_profile: str = "standard",
) -> tuple[AssessmentReport, dict[str, Path], dict[str, Any]]:
    if not token:
        raise ValueError("L'agent requiert un token non vide.")

    profile = normalize_scan_profile(scan_profile)
    config = ScanConfig(
        skip_network=True,
        audit_localhost=True,
        output_dir=Path(output_dir),
        nvd_api_key=nvd_api_key,
        scan_profile=profile,
        ports=SCAN_PROFILES[profile]["ports"].copy(),
        udp_discovery_ports=SCAN_PROFILES[profile]["udp"].copy(),
    )
    report, paths = AssessmentEngine(config).run()
    metadata = dict(report.metadata)
    metadata["analysis"] = {
        "type": profile,
        "scope": "windows_agent",
    }
    metadata["agent"] = {
        "id": agent_id or _default_agent_id(report),
        "sent_at": now_iso(),
        "mode": "local_agent",
        "analysis_type": profile,
    }
    report.metadata = metadata

    # Reecrit le rapport local avec les metadonnees agent avant envoi.
    paths = ReportWriter().write(report, Path(output_dir), overwrite=True)
    response = requests.post(
        _collector_url(collector),
        json=report.to_dict(),
        headers={"Authorization": f"Bearer {token}", "X-CyberAudit-Token": token},
        timeout=60,
    )
    response.raise_for_status()
    return report, paths, response.json()


def _collector_url(collector: str) -> str:
    base = collector.strip().rstrip("/")
    if base.endswith(AGENT_ENDPOINT):
        return base
    return f"{base}{AGENT_ENDPOINT}"


def _is_authorized(headers, token: str) -> bool:
    auth = headers.get("Authorization", "")
    if auth == f"Bearer {token}":
        return True
    return headers.get("X-CyberAudit-Token") == token


def _write_aggregate_report(incoming: AssessmentReport, output_dir: Path) -> dict[str, Path]:
    reports = _load_agent_reports(output_dir)
    incoming_id = _agent_id(incoming)
    reports = [report for report in reports if _agent_id(report) != incoming_id]
    reports.append(incoming)

    aggregate = _build_aggregate_report(reports)
    return ReportWriter().write(aggregate, output_dir, overwrite=True, basename=AGGREGATE_REPORT_BASENAME)


def _load_agent_reports(output_dir: Path) -> list[AssessmentReport]:
    aggregate_json = output_dir / f"{AGGREGATE_REPORT_BASENAME}.json"
    if not aggregate_json.exists():
        return []
    try:
        payload = json.loads(aggregate_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    metadata = payload.get("metadata") if isinstance(payload, dict) else {}
    raw_reports = metadata.get("agent_reports") if isinstance(metadata, dict) else []
    reports: list[AssessmentReport] = []
    for raw_report in raw_reports:
        if not isinstance(raw_report, dict):
            continue
        try:
            reports.append(AssessmentReport.from_dict(raw_report))
        except (TypeError, ValueError):
            continue
    return reports


def _build_aggregate_report(reports: list[AssessmentReport]) -> AssessmentReport:
    hosts: list[HostRecord] = []
    software_inventory: list[SoftwareRecord] = []
    findings: list[Finding] = []
    agent_summaries: list[dict[str, Any]] = []
    agent_audits: list[dict[str, Any]] = []

    for report in reports:
        agent_id = _agent_id(report)
        analysis_type = _analysis_type(report)

        normalized_hosts = [_host_for_agent(host, agent_id) for host in report.hosts]
        for host in normalized_hosts:
            _merge_host(hosts, host)

        normalized_software = [_software_for_agent(item, agent_id) for item in report.software_inventory]
        software_inventory.extend(normalized_software)
        findings.extend(_finding_for_agent(finding, agent_id) for finding in report.findings)

        localhost_audit = report.metadata.get("localhost_audit", {}) if isinstance(report.metadata, dict) else {}
        agent_summaries.append(
            {
                "id": agent_id,
                "analysis_type": analysis_type,
                "sent_at": _agent_sent_at(report),
                "received_at": report.metadata.get("collector_received_at") if isinstance(report.metadata, dict) else None,
                "hosts": len(normalized_hosts),
                "software": len(normalized_software),
                "findings": len(report.findings),
            }
        )
        if isinstance(localhost_audit, dict) and localhost_audit:
            agent_audits.append({"agent_id": agent_id, "analysis_type": analysis_type, "localhost_audit": localhost_audit})

    analysis_types = sorted({_analysis_type(report) for report in reports})
    analysis_label = analysis_types[0] if len(analysis_types) == 1 else "mixte: " + ", ".join(analysis_types)
    metadata = {
        "scope": {"agents": [summary["id"] for summary in agent_summaries]},
        "collector": {
            "mode": "multi_agent",
            "updated_at": now_iso(),
            "agent_count": len(agent_summaries),
            "agents": agent_summaries,
            "analysis_type": analysis_label,
            "analysis_types": analysis_types,
        },
        "agent_audits": agent_audits,
        "agent_reports": [report.to_dict() for report in reports],
        "notes": ["Rapport consolide a partir des audits envoyes par les agents."],
    }
    return AssessmentReport(
        generated_at=now_iso(),
        network="agents distants",
        hosts=hosts,
        software_inventory=software_inventory,
        findings=sort_findings(findings),
        metadata=metadata,
    )


def _host_for_agent(host: HostRecord, agent_id: str) -> HostRecord:
    normalized = deepcopy(host)
    if normalized.ip in {"127.0.0.1", "::1", "localhost"}:
        normalized.ip = agent_id
    normalized.hostname = normalized.hostname or agent_id
    note = f"Agent: {agent_id}"
    if note not in normalized.notes:
        normalized.notes.append(note)
    return normalized


def _software_for_agent(item: SoftwareRecord, agent_id: str) -> SoftwareRecord:
    normalized = deepcopy(item)
    if not normalized.host or normalized.host in {"127.0.0.1", "::1", "localhost", "local"}:
        normalized.host = agent_id
    return normalized


def _finding_for_agent(finding: Finding, agent_id: str) -> Finding:
    normalized = deepcopy(finding)
    if normalized.target in {"127.0.0.1", "::1", "localhost", "local"}:
        normalized.target = agent_id
    normalized.source = f"agent:{agent_id}"
    return normalized


def _merge_host(hosts: list[HostRecord], incoming: HostRecord) -> None:
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
        host.services.extend(service for service in incoming.services if service not in host.services)
        host.is_alive = host.is_alive or incoming.is_alive
        return
    hosts.append(incoming)


def _agent_id(report: AssessmentReport) -> str:
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    agent = metadata.get("agent") if isinstance(metadata.get("agent"), dict) else {}
    if agent.get("id"):
        return str(agent["id"])

    localhost = metadata.get("localhost_audit") if isinstance(metadata.get("localhost_audit"), dict) else {}
    system_profile = localhost.get("system_profile") if isinstance(localhost.get("system_profile"), dict) else {}
    os_data = system_profile.get("os") if isinstance(system_profile.get("os"), dict) else {}
    if os_data.get("CSName"):
        return str(os_data["CSName"])
    if report.hosts:
        host = report.hosts[0]
        return host.hostname or host.ip
    if metadata.get("collector_remote_addr"):
        return str(metadata["collector_remote_addr"])
    return "agent-local"


def _analysis_type(report: AssessmentReport) -> str:
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    analysis = metadata.get("analysis") if isinstance(metadata.get("analysis"), dict) else {}
    if analysis.get("type"):
        return str(analysis["type"])
    agent = metadata.get("agent") if isinstance(metadata.get("agent"), dict) else {}
    if agent.get("analysis_type"):
        return str(agent["analysis_type"])
    return "standard"


def _agent_sent_at(report: AssessmentReport) -> str | None:
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    agent = metadata.get("agent") if isinstance(metadata.get("agent"), dict) else {}
    sent_at = agent.get("sent_at")
    return str(sent_at) if sent_at else None


def _default_agent_id(report: AssessmentReport) -> str:
    localhost = report.metadata.get("localhost_audit", {})
    system_profile = localhost.get("system_profile", {}) if isinstance(localhost, dict) else {}
    os_data = system_profile.get("os", {}) if isinstance(system_profile, dict) else {}
    hostname = os_data.get("CSName") if isinstance(os_data, dict) else None
    return hostname or "agent-local"
