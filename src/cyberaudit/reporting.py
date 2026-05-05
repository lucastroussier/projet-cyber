from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import AssessmentReport, SEVERITY_LABELS_FR, compute_security_score, sort_findings, summarize_findings


class ReportWriter:
    def __init__(self) -> None:
        template_dir = Path(__file__).resolve().parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def write(self, report: AssessmentReport, output_dir: Path, overwrite: bool = False, basename: str | None = None) -> dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        if basename:
            json_path = output_dir / f"{basename}.json"
            html_path = output_dir / f"{basename}.html"
        else:
            timestamp = report.generated_at.replace(":", "-").replace("+", "_").replace("T", "_")
            json_path = output_dir / f"cyberaudit_{timestamp}.json"
            html_path = output_dir / f"cyberaudit_{timestamp}.html"
        if not overwrite:
            suffix = 1
            while json_path.exists() or html_path.exists():
                if basename:
                    json_path = output_dir / f"{basename}_{suffix}.json"
                    html_path = output_dir / f"{basename}_{suffix}.html"
                else:
                    json_path = output_dir / f"cyberaudit_{timestamp}_{suffix}.json"
                    html_path = output_dir / f"cyberaudit_{timestamp}_{suffix}.html"
                suffix += 1

        json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

        template = self.env.get_template("report.html")
        html = template.render(
            report=report,
            findings=sort_findings(report.findings),
            summary=summarize_findings(report.findings),
            labels=SEVERITY_LABELS_FR,
            score=compute_security_score(report.findings),
        )
        html_path.write_text(html, encoding="utf-8")
        return {"json": json_path, "html": html_path}
