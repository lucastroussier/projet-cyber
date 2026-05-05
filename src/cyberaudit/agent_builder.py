from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def build_agent_executable(output_dir: str = "dist", name: str = "cyberaudit-agent") -> Path:
    project_root = Path(__file__).resolve().parents[2]
    src_dir = project_root / "src"
    package_dir = Path(__file__).resolve().parent
    entrypoint = package_dir / "agent_exe.py"
    templates_dir = package_dir / "templates"
    static_dir = package_dir / "static"
    dist_dir = (project_root / output_dir).resolve()
    build_dir = (project_root / "build" / "pyinstaller-agent").resolve()
    build_dir.mkdir(parents=True, exist_ok=True)

    separator = ";" if os.name == "nt" else ":"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(build_dir / "work"),
        "--specpath",
        str(build_dir),
        "--paths",
        str(src_dir),
        "--add-data",
        f"{templates_dir}{separator}cyberaudit/templates",
        "--add-data",
        f"{static_dir}{separator}cyberaudit/static",
        str(entrypoint),
    ]

    try:
        subprocess.run(command, cwd=str(project_root), check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("PyInstaller est introuvable. Installez-le avec: python -m pip install pyinstaller") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"La generation de l'executable agent a echoue avec le code {exc.returncode}.") from exc

    suffix = ".exe" if os.name == "nt" else ""
    executable = dist_dir / f"{name}{suffix}"
    if not executable.exists():
        raise RuntimeError(f"Executable attendu introuvable: {executable}")
    return executable
