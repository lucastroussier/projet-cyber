from __future__ import annotations

import argparse
from pathlib import Path

from .agent import create_collector_app, run_agent
from .agent_builder import build_agent_executable
from .config import SCAN_PROFILES, ScanConfig
from .orchestrator import AssessmentEngine
from .webapp import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberAudit - audit defensif reseau et postes Windows")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Lancer une analyse")
    scan.add_argument("--network", help="Sous-reseau CIDR a analyser, ex. 192.168.1.0/24")
    scan.add_argument("--scan-profile", choices=sorted(SCAN_PROFILES), default="standard", help="Profil de ports et de decouverte")
    scan.add_argument("--ports", default="", help="Liste de ports ou plages, ex. 22,80,443,5000-5001,5985-5986")
    scan.add_argument("--timeout", type=float, default=0.35, help="Timeout TCP par port")
    scan.add_argument("--udp-timeout", type=float, default=0.4, help="Timeout UDP pour la decouverte ciblee")
    scan.add_argument("--udp-discovery-ports", default="", help="Ports UDP de decouverte, ex. 137,161,5353,5355")
    scan.add_argument("--disable-udp-discovery", action="store_true", help="Desactiver la decouverte UDP ciblee")
    scan.add_argument("--snmp-communities", default="public", help="Communautes SNMP read-only a tester, separees par virgule")
    scan.add_argument("--workers", type=int, default=192, help="Nombre de workers de scan")
    scan.add_argument("--output", default="reports", help="Repertoire de sortie")
    scan.add_argument("--audit-localhost", action="store_true", dest="audit_localhost", help="Auditer le poste local Windows")
    scan.add_argument("--skip-network", action="store_true", help="Ignorer le scan reseau")
    scan.add_argument("--allow-non-private", action="store_true", help="Autoriser des cibles hors plages privees/loopback")
    scan.add_argument("--nvd-api-key", help="Cle API NVD optionnelle")

    serve = subparsers.add_parser("serve", help="Lancer l'interface web")
    serve.add_argument("--host", default="127.0.0.1", help="Adresse d'ecoute")
    serve.add_argument("--port", type=int, default=8080, help="Port d'ecoute")
    serve.add_argument("--output", default="reports", help="Repertoire de sortie des rapports")

    collector = subparsers.add_parser("collector", help="Recevoir les rapports envoyes par les agents")
    collector.add_argument("--host", default="0.0.0.0", help="Adresse d'ecoute du collecteur")
    collector.add_argument("--port", type=int, default=8090, help="Port d'ecoute du collecteur")
    collector.add_argument("--output", default="reports", help="Repertoire de sortie des rapports recus")
    collector.add_argument("--token", required=True, help="Token partage avec les agents")

    agent = subparsers.add_parser("agent", help="Auditer localement ce poste puis envoyer le rapport au collecteur")
    agent.add_argument("--collector", required=True, help="URL du collecteur, ex. http://192.168.1.10:8090")
    agent.add_argument("--token", required=True, help="Token partage avec le collecteur")
    agent.add_argument("--output", default="reports", help="Repertoire local de sortie")
    agent.add_argument("--agent-id", help="Identifiant lisible de l'agent dans le rapport")
    agent.add_argument("--scan-profile", choices=sorted(SCAN_PROFILES), default="standard", help="Type d'analyse a inscrire dans le rapport agent")
    agent.add_argument("--nvd-api-key", help="Cle API NVD optionnelle")

    build_agent = subparsers.add_parser("build-agent", help="Generer un executable autonome pour l'agent PC distant")
    build_agent.add_argument("--output", default="dist", help="Repertoire de sortie de l'executable")
    build_agent.add_argument("--name", default="cyberaudit-agent", help="Nom de l'executable sans extension")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        config = ScanConfig.from_args(args)
        report, paths = AssessmentEngine(config).run()
        print(f"Rapport HTML : {paths['html']}")
        print(f"Rapport JSON : {paths['json']}")
        print(f"Constats    : {len(report.findings)}")
        print(f"Hotes       : {len(report.hosts)}")
        print(f"Ports testes: {len(config.ports)}")
        print(f"Profil scan : {config.scan_profile}")
        return

    if args.command == "serve":
        app = create_app(default_output=str(Path(args.output)))
        app.run(host=args.host, port=args.port, debug=False)
        return

    if args.command == "collector":
        app = create_collector_app(output_dir=args.output, token=args.token)
        app.run(host=args.host, port=args.port, debug=False)
        return

    if args.command == "agent":
        report, paths, response = run_agent(
            collector=args.collector,
            token=args.token,
            output_dir=args.output,
            nvd_api_key=args.nvd_api_key,
            agent_id=args.agent_id,
            scan_profile=args.scan_profile,
        )
        print(f"Rapport local HTML : {paths['html']}")
        print(f"Rapport local JSON : {paths['json']}")
        print(f"Constats           : {len(report.findings)}")
        print(f"Type analyse       : {args.scan_profile}")
        print(f"Collecteur         : {response.get('status', 'ok')}")
        return

    if args.command == "build-agent":
        executable = build_agent_executable(output_dir=args.output, name=args.name)
        print(f"Executable agent : {executable}")


if __name__ == "__main__":
    main()
