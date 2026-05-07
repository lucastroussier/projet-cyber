from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from threading import Lock

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from .agent import AGENT_ENDPOINT, AGGREGATE_REPORT_BASENAME, _find_agent_binary, _is_authorized, _write_aggregate_report, random_agent_id
from .config import DEFAULT_PORTS, SCAN_PROFILES, ScanConfig
from .models import AssessmentReport, now_iso
from .orchestrator import AssessmentEngine
from .reporting import PdfReportWriter


def create_app(default_output: str = "reports", token: str = "secret-audit") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "cyberaudit-dev-key"
    app.config["DEFAULT_OUTPUT_DIR"] = str(Path(default_output).resolve())
    app.config["COLLECTOR_TOKEN"] = token
    aggregate_lock = Lock()
    agent_binary = _find_agent_binary()

    @app.get("/")
    def index():
        reports_dir = Path(app.config["DEFAULT_OUTPUT_DIR"])
        reports = []
        if reports_dir.exists():
            reports = [
                report
                for report in sorted(reports_dir.glob("cyberaudit_*.html"), reverse=True)
                if report.name != f"{AGGREGATE_REPORT_BASENAME}.html"
            ]
        aggregate_report = reports_dir / f"{AGGREGATE_REPORT_BASENAME}.html"
        last_generated_report = session.pop("last_generated_report", None)
        return render_template(
            "index.html",
            reports=reports,
            aggregate_report=aggregate_report if aggregate_report.exists() else None,
            last_generated_report=last_generated_report,
            default_ports=",".join(str(port) for port in DEFAULT_PORTS),
            scan_profiles=sorted(SCAN_PROFILES),
            default_udp_ports=",".join(str(port) for port in SCAN_PROFILES["standard"]["udp"]),
            collector_url=_base_url(),
            collector_token=app.config["COLLECTOR_TOKEN"],
            agent_endpoint=AGENT_ENDPOINT,
            agent_binary=agent_binary if agent_binary and agent_binary.exists() else None,
            is_loopback_request=_is_loopback_host(request.host),
            suggested_agent_id=random_agent_id(),
        )

    @app.post("/scan")
    def run_scan():
        form_data = request.form.to_dict(flat=True)
        form_data["audit_localhost"] = request.form.get("audit_localhost")
        form_data["skip_network"] = request.form.get("skip_network")
        form_data["allow_non_private_targets"] = request.form.get("allow_non_private_targets")
        form_data["disable_udp_discovery"] = request.form.get("disable_udp_discovery")
        config = ScanConfig.from_form(form_data)
        config.output_dir = config.output_dir.resolve()

        try:
            _, paths = AssessmentEngine(config).run()
        except Exception as exc:  # noqa: BLE001
            flash(str(exc), "error")
            return redirect(url_for("index"))

        session["last_generated_report"] = paths["html"].name
        flash("Analyse terminee.", "success")
        return redirect(url_for("index"))

    @app.post("/reports/delete")
    def delete_report():
        filename = request.form.get("filename", "").strip()
        base_dir = Path(app.config["DEFAULT_OUTPUT_DIR"]).resolve()
        try:
            report_path = _safe_report_path(base_dir, filename)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        candidates = _paired_report_paths(report_path)
        deleted: list[str] = []
        for candidate in candidates:
            if not candidate.exists() or not candidate.is_file():
                continue
            try:
                candidate.unlink()
            except OSError as exc:
                flash(f"Suppression impossible pour {candidate.name}: {exc}", "error")
                return redirect(url_for("index"))
            deleted.append(candidate.name)

        if deleted:
            flash("Rapport supprime: " + ", ".join(deleted), "success")
        else:
            flash("Aucun fichier de rapport correspondant n'a ete trouve.", "error")
        return redirect(url_for("index"))

    @app.post(AGENT_ENDPOINT)
    def receive_agent_report():
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
        metadata["collector_mode"] = "webapp"
        report.metadata = metadata

        with aggregate_lock:
            paths = _write_aggregate_report(report, Path(app.config["DEFAULT_OUTPUT_DIR"]))
        return jsonify({"status": "ok", "html": paths["html"].name, "json": paths["json"].name, "mode": "aggregate"})

    @app.get("/agent/download")
    def download_agent():
        if not agent_binary or not agent_binary.exists():
            abort(404)
        return send_file(agent_binary, as_attachment=True, download_name=agent_binary.name)

    @app.get("/reports/pdf/<path:filename>")
    def download_report_pdf(filename: str):
        base_dir = Path(app.config["DEFAULT_OUTPUT_DIR"]).resolve()
        try:
            report_path = _safe_report_path(base_dir, filename)
        except ValueError:
            abort(404)

        json_path = report_path if report_path.suffix.lower() == ".json" else report_path.with_suffix(".json")
        if not json_path.exists() or not json_path.is_file():
            abort(404)

        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            report = AssessmentReport.from_dict(payload)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            abort(404)

        pdf = PdfReportWriter().render(report)
        return send_file(
            BytesIO(pdf),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{report_path.stem}.pdf",
        )

    @app.get("/reports/<path:filename>")
    def view_report(filename: str):
        path = (Path(app.config["DEFAULT_OUTPUT_DIR"]) / filename).resolve()
        base_dir = Path(app.config["DEFAULT_OUTPUT_DIR"]).resolve()
        if base_dir not in path.parents and path != base_dir:
            abort(404)
        if not path.exists() or not path.is_file():
            abort(404)
        return send_file(path)

    return app


def _base_url() -> str:
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{scheme}://{request.host}".rstrip("/")


def _is_loopback_host(host: str) -> bool:
    hostname = host.split(":", 1)[0].strip().lower()
    return hostname in {"127.0.0.1", "localhost", "::1"}


def _safe_report_path(base_dir: Path, filename: str) -> Path:
    if not filename:
        raise ValueError("Nom de rapport manquant.")
    requested = Path(filename)
    if requested.name != filename:
        raise ValueError("Nom de rapport invalide.")
    if requested.suffix.lower() not in {".html", ".json"}:
        raise ValueError("Seuls les rapports HTML ou JSON peuvent etre supprimes.")

    path = (base_dir / requested.name).resolve()
    if base_dir not in path.parents and path != base_dir:
        raise ValueError("Chemin de rapport invalide.")
    allowed_prefixes = ("cyberaudit_", AGGREGATE_REPORT_BASENAME)
    if not path.name.startswith(allowed_prefixes):
        raise ValueError("Ce fichier n'est pas un rapport CyberAudit.")
    return path


def _paired_report_paths(path: Path) -> list[Path]:
    if path.suffix.lower() == ".html":
        return [path, path.with_suffix(".json")]
    if path.suffix.lower() == ".json":
        return [path, path.with_suffix(".html")]
    return [path]
