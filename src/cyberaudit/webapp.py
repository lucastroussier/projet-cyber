from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for

from .config import DEFAULT_PORTS, SCAN_PROFILES, ScanConfig
from .orchestrator import AssessmentEngine


def create_app(default_output: str = "reports") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "cyberaudit-dev-key"
    app.config["DEFAULT_OUTPUT_DIR"] = str(Path(default_output).resolve())

    @app.get("/")
    def index():
        reports_dir = Path(app.config["DEFAULT_OUTPUT_DIR"])
        reports = []
        if reports_dir.exists():
            reports = sorted(reports_dir.glob("cyberaudit_*.html"), reverse=True)
        last_generated_report = session.pop("last_generated_report", None)
        return render_template(
            "index.html",
            reports=reports,
            last_generated_report=last_generated_report,
            default_ports=",".join(str(port) for port in DEFAULT_PORTS),
            scan_profiles=sorted(SCAN_PROFILES),
            default_udp_ports=",".join(str(port) for port in SCAN_PROFILES["standard"]["udp"]),
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
