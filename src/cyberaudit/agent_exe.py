from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

import requests

from cyberaudit.agent import run_agent
from cyberaudit.config import SCAN_PROFILES, normalize_scan_profile


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberAudit Agent - audit local et envoi au collecteur")
    parser.add_argument("--collector", help="URL du collecteur, ex. http://192.168.1.10:8090")
    parser.add_argument("--token", help="Token partage avec le collecteur")
    parser.add_argument("--output", default="reports", help="Repertoire local de sortie")
    parser.add_argument("--agent-id", help="Identifiant lisible de l'agent dans le rapport")
    parser.add_argument("--scan-profile", choices=sorted(SCAN_PROFILES), default="standard", help="Type d'analyse a inscrire dans le rapport agent")
    parser.add_argument("--nvd-api-key", help="Cle API NVD optionnelle")
    parser.add_argument("--pause", action="store_true", help="Attendre Entree avant de fermer")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    interactive = _needs_prompt(args)

    if interactive:
        print("CyberAudit Agent")
        print("Ce programme audite ce poste puis envoie le rapport au collecteur.")
        args.collector = args.collector or input("URL du collecteur (ex. http://192.168.1.10:8090): ").strip()
        args.token = args.token or getpass.getpass("Token collecteur: ").strip()
        agent_id = input("Identifiant agent, vide pour auto: ").strip()
        args.agent_id = args.agent_id or agent_id or None
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
