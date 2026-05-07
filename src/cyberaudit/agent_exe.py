from __future__ import annotations

import argparse
import getpass
import sys
import threading
import uuid
import webbrowser
from pathlib import Path
from typing import Any

import requests
from flask import Flask, redirect, render_template_string, request, url_for

from cyberaudit.agent import random_agent_id, run_agent
from cyberaudit.config import SCAN_PROFILES, normalize_scan_profile


AGENT_WEB_TEMPLATE = """
<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CyberAudit Agent</title>
    <style>
      :root { --bg: #f6f7f9; --panel: #fff; --ink: #1f2933; --muted: #5d6770; --accent: #2563eb; --line: #d8dee7; --error: #8f2130; --success: #1f6a50; }
      * { box-sizing: border-box; }
      body { margin: 0; color: var(--ink); background: var(--bg); font-family: "Segoe UI", sans-serif; }
      main { max-width: 980px; margin: 0 auto; padding: 28px 18px 48px; }
      section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 24px; box-shadow: 0 10px 28px rgba(15, 23, 42, 0.06); margin-bottom: 18px; }
      h1, h2 { margin: 0 0 10px; }
      .lead, .small { color: var(--muted); }
      form, .grid { display: grid; gap: 14px; }
      .grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
      label { display: flex; flex-direction: column; gap: 6px; font-weight: 700; }
      input, select { width: 100%; padding: 11px 12px; border: 1px solid #cfd6e0; border-radius: 6px; background: #fff; }
      button, .button-link { border: 0; border-radius: 6px; padding: 14px 18px; font-weight: 700; cursor: pointer; background: var(--accent); color: #fff; text-decoration: none; width: fit-content; }
      code { display: inline-block; padding: 2px 6px; border-radius: 6px; background: #eef2f7; }
      .flash { border-radius: 8px; padding: 12px 14px; font-weight: 600; }
      .running { background: #eef2ff; color: #1d4ed8; }
      .success { background: rgba(31, 106, 80, 0.12); color: var(--success); }
      .error { background: rgba(143, 33, 48, 0.12); color: var(--error); }
      .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 16px; }
    </style>
    {% if job and job.status == 'running' %}<meta http-equiv="refresh" content="5">{% endif %}
  </head>
  <body>
    <main>
      <section>
        <h1>CyberAudit Agent</h1>
        <p class="lead">Audit local du poste et envoi au collecteur.</p>
      </section>
      {% if not job %}
        <section>
          <h2>Lancer l'audit</h2>
          <form method="post" action="{{ url_for('start_job') }}">
            <div class="grid">
              <label>URL collecteur
                <input type="text" name="collector" value="{{ defaults.collector }}" placeholder="http://192.168.1.42:8080" required>
              </label>
              <label>Token
                <input type="password" name="token" value="{{ defaults.token }}" required>
              </label>
              <label>Agent ID
                <input type="text" name="agent_id" value="{{ defaults.agent_id }}">
              </label>
              <label>Profil
                <select name="scan_profile">
                  {% for profile in profiles %}
                    <option value="{{ profile }}" {% if profile == defaults.scan_profile %}selected{% endif %}>{{ profile }}</option>
                  {% endfor %}
                </select>
              </label>
              <label>Logiciels CVE
                <input type="number" min="0" name="max_cve_products" value="{{ defaults.max_cve_products }}">
              </label>
              <label>CVE par logiciel
                <input type="number" min="1" name="max_cves_per_product" value="{{ defaults.max_cves_per_product }}">
              </label>
              <label>Cle NVD
                <input type="password" name="nvd_api_key" value="{{ defaults.nvd_api_key }}" placeholder="Optionnel">
              </label>
              <label>Dossier local
                <input type="text" name="output" value="{{ defaults.output }}">
              </label>
            </div>
            <button type="submit">Lancer l'audit</button>
          </form>
        </section>
      {% else %}
        <section>
          <h2>Audit {{ job.status_label }}</h2>
          {% if job.status == 'running' %}
            <div class="flash running">Audit en cours. Cette page se rafraichit automatiquement.</div>
          {% elif job.status == 'done' %}
            <div class="flash success">Audit termine et envoye au collecteur.</div>
            <p>Rapport local HTML : <code>{{ job.html }}</code></p>
            <p>Rapport local JSON : <code>{{ job.json }}</code></p>
            <p>Constats : <code>{{ job.findings }}</code></p>
            <p>Collecteur : <code>{{ job.collector_status }}</code></p>
          {% elif job.status == 'error' %}
            <div class="flash error">{{ job.error }}</div>
          {% endif %}
          <div class="actions">
            <a class="button-link" href="{{ url_for('index') }}">Nouvel audit</a>
          </div>
        </section>
      {% endif %}
    </main>
  </body>
</html>
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberAudit Agent - audit local et envoi au collecteur")
    parser.add_argument("--collector", help="URL de l'interface web PC1, ex. http://192.168.1.10:8080")
    parser.add_argument("--token", help="Token partage avec le collecteur")
    parser.add_argument("--output", default="reports", help="Repertoire local de sortie")
    parser.add_argument("--agent-id", help="Identifiant lisible de l'agent dans le rapport")
    parser.add_argument("--scan-profile", choices=sorted(SCAN_PROFILES), default="standard", help="Type d'analyse a inscrire dans le rapport agent")
    parser.add_argument("--nvd-api-key", help="Cle API NVD optionnelle")
    parser.add_argument("--max-cve-products", type=int, help="Nombre maximum de logiciels locaux a correler avec NVD, 0 = tous")
    parser.add_argument("--max-cves-per-product", type=int, help="Nombre maximum de CVE conservees par logiciel local")
    parser.add_argument("--web", action="store_true", help="Lancer l'interface web locale de l'agent")
    parser.add_argument("--console", action="store_true", help="Utiliser les questions console au lieu de l'interface web locale")
    parser.add_argument("--web-host", default="127.0.0.1", help="Adresse d'ecoute de l'interface web agent")
    parser.add_argument("--web-port", type=int, default=8765, help="Port de l'interface web agent")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir automatiquement le navigateur")
    parser.add_argument("--pause", action="store_true", help="Attendre Entree avant de fermer")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    interactive = _needs_prompt(args)

    if args.web or (interactive and not args.console):
        return run_agent_web(args)

    if interactive:
        print("CyberAudit Agent")
        print("Ce programme audite ce poste puis envoie le rapport au collecteur.")
        args.collector = args.collector or input("URL de l'interface web PC1 (ex. http://192.168.1.10:8080): ").strip()
        args.token = args.token or getpass.getpass("Token collecteur: ").strip()
        suggested_agent_id = random_agent_id()
        agent_id = input(f"Identifiant agent [{suggested_agent_id}]: ").strip()
        args.agent_id = args.agent_id or agent_id or suggested_agent_id
        while True:
            profile = input(f"Type d'analyse [{args.scan_profile}]: ").strip()
            try:
                args.scan_profile = normalize_scan_profile(profile or args.scan_profile)
                break
            except ValueError as exc:
                print(exc)
        output = input(f"Repertoire local de sortie [{args.output}]: ").strip()
        args.output = output or args.output

    try:
        report, paths, response = run_agent(
            collector=args.collector or "",
            token=args.token or "",
            output_dir=args.output,
            nvd_api_key=args.nvd_api_key,
            agent_id=args.agent_id,
            scan_profile=args.scan_profile,
            max_cve_products=args.max_cve_products,
            max_cves_per_product=args.max_cves_per_product,
        )
    except requests.RequestException as exc:
        print(f"Erreur d'envoi au collecteur: {exc}", file=sys.stderr)
        _pause_if_needed(interactive or args.pause)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"Erreur agent: {exc}", file=sys.stderr)
        _pause_if_needed(interactive or args.pause)
        return 1

    print(f"Rapport local HTML : {Path(paths['html']).resolve()}")
    print(f"Rapport local JSON : {Path(paths['json']).resolve()}")
    print(f"Constats           : {len(report.findings)}")
    print(f"Type analyse       : {args.scan_profile}")
    print(f"Collecteur         : {response.get('status', 'ok')}")
    if response.get("html"):
        print(f"Rapport collecteur : {response.get('html')}")
    _pause_if_needed(interactive or args.pause)
    return 0


def run_agent_web(args: argparse.Namespace) -> int:
    app = Flask(__name__)
    jobs: dict[str, dict[str, Any]] = {}
    jobs_lock = threading.Lock()

    defaults = {
        "collector": args.collector or "",
        "token": args.token or "",
        "agent_id": args.agent_id or random_agent_id(),
        "scan_profile": normalize_scan_profile(args.scan_profile or "full"),
        "nvd_api_key": args.nvd_api_key or "",
        "max_cve_products": "0" if args.max_cve_products is None else str(args.max_cve_products),
        "max_cves_per_product": "10" if args.max_cves_per_product is None else str(args.max_cves_per_product),
        "output": args.output or "reports",
    }

    @app.get("/")
    def index():
        return render_template_string(
            AGENT_WEB_TEMPLATE,
            job=None,
            defaults=defaults,
            profiles=sorted(SCAN_PROFILES),
        )

    @app.post("/run")
    def start_job():
        job_id = uuid.uuid4().hex
        job = {"status": "running", "status_label": "en cours"}
        with jobs_lock:
            jobs[job_id] = job

        options = {
            "collector": request.form.get("collector", "").strip(),
            "token": request.form.get("token", "").strip(),
            "output_dir": request.form.get("output", "reports").strip() or "reports",
            "nvd_api_key": request.form.get("nvd_api_key", "").strip() or None,
            "agent_id": request.form.get("agent_id", "").strip() or random_agent_id(),
            "scan_profile": normalize_scan_profile(request.form.get("scan_profile", "full")),
            "max_cve_products": _optional_int(request.form.get("max_cve_products"), default=0),
            "max_cves_per_product": _optional_int(request.form.get("max_cves_per_product"), default=10),
        }

        thread = threading.Thread(target=_run_web_job, args=(job, jobs_lock, options), daemon=True)
        thread.start()
        return redirect(url_for("job_status", job_id=job_id))

    @app.get("/jobs/<job_id>")
    def job_status(job_id: str):
        with jobs_lock:
            job = dict(jobs.get(job_id, {"status": "error", "status_label": "en erreur", "error": "Audit introuvable."}))
        return render_template_string(
            AGENT_WEB_TEMPLATE,
            job=job,
            defaults=defaults,
            profiles=sorted(SCAN_PROFILES),
        )

    url = f"http://{args.web_host}:{args.web_port}"
    print(f"Interface web agent : {url}")
    if not args.no_browser:
        webbrowser.open(url)
    app.run(host=args.web_host, port=args.web_port, debug=False, use_reloader=False)
    return 0


def _run_web_job(job: dict[str, Any], lock: threading.Lock, options: dict[str, Any]) -> None:
    try:
        report, paths, response = run_agent(**options)
    except requests.RequestException as exc:
        with lock:
            job.update(
                {
                    "status": "error",
                    "status_label": "en erreur",
                    "error": f"Erreur d'envoi au collecteur: {exc}",
                }
            )
        return
    except Exception as exc:  # noqa: BLE001
        with lock:
            job.update(
                {
                    "status": "error",
                    "status_label": "en erreur",
                    "error": f"Erreur agent: {exc}",
                }
            )
        return

    with lock:
        job.update(
            {
                "status": "done",
                "status_label": "termine",
                "html": str(Path(paths["html"]).resolve()),
                "json": str(Path(paths["json"]).resolve()),
                "findings": len(report.findings),
                "collector_status": response.get("status", "ok"),
            }
        )


def _optional_int(value: str | None, default: int) -> int:
    if value is None or value == "":
        return default
    parsed = int(value)
    if parsed < 0:
        raise ValueError("La valeur numerique doit etre positive ou egale a 0.")
    return parsed


def _needs_prompt(args: argparse.Namespace) -> bool:
    return not args.collector or not args.token


def _pause_if_needed(enabled: bool) -> None:
    if not enabled:
        return
    try:
        input("Appuyez sur Entree pour fermer...")
    except EOFError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
