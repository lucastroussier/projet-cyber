from __future__ import annotations

import json
import textwrap
import unicodedata
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


class PdfReportWriter:
    page_width = 595
    page_height = 842
    margin = 48
    bottom_margin = 44

    def render(self, report: AssessmentReport) -> bytes:
        lines: list[tuple[str, int, str]] = []
        summary = summarize_findings(report.findings)
        score = compute_security_score(report.findings)
        findings = sort_findings(report.findings)

        self._add(lines, "B", 18, "Rapport CyberAudit")
        self._add(lines, "R", 10, f"Genere le: {report.generated_at}")
        self._add(lines, "R", 10, f"Perimetre: {report.network or 'audit local uniquement'}")
        self._blank(lines)

        self._add(lines, "B", 13, "Synthese")
        self._add(lines, "R", 10, f"Score global: {score}/100")
        self._add(lines, "R", 10, f"Hotes detectes: {len(report.hosts)}")
        self._add(lines, "R", 10, f"Logiciels inventories: {len(report.software_inventory)}")
        self._add(lines, "R", 10, f"Constats: {len(findings)}")
        self._add(lines, "R", 10, "Severites: " + ", ".join(f"{key}={value}" for key, value in summary.items()))
        self._blank(lines)

        self._add(lines, "B", 13, "Constats detailles")
        if findings:
            for index, finding in enumerate(findings, start=1):
                self._add_wrapped(lines, "B", 10, f"{index}. [{finding.severity}] {finding.title}", width=88)
                self._add_wrapped(lines, "R", 9, f"Cible: {finding.target} | Categorie: {finding.category} | Source: {finding.source}", width=100)
                self._add_wrapped(lines, "R", 9, f"Description: {finding.description}", width=100)
                self._add_wrapped(lines, "R", 9, f"Recommandation: {finding.recommendation}", width=100)
                cve = finding.evidence.get("cve") if isinstance(finding.evidence, dict) else None
                score_value = finding.evidence.get("cvss_score") if isinstance(finding.evidence, dict) else None
                if cve:
                    self._add(lines, "R", 9, f"CVE: {cve} | CVSS: {score_value or 'N/A'}")
                self._blank(lines, size=6)
        else:
            self._add(lines, "R", 10, "Aucun constat remonte.")
        self._blank(lines)

        self._add(lines, "B", 13, "Hotes")
        if report.hosts:
            for host in report.hosts:
                label = f"{host.ip}"
                if host.hostname:
                    label += f" - {host.hostname}"
                if host.operating_system:
                    label += f" | OS: {host.operating_system}"
                self._add_wrapped(lines, "R", 9, label, width=105)
        else:
            self._add(lines, "R", 10, "Aucun hote dans ce rapport.")
        self._blank(lines)

        self._add(lines, "B", 13, "Inventaire logiciel")
        if report.software_inventory:
            for item in report.software_inventory[:300]:
                label = f"{item.host or 'local'} | {item.name}"
                if item.version:
                    label += f" | {item.version}"
                if item.vendor:
                    label += f" | {item.vendor}"
                self._add_wrapped(lines, "R", 8, label, width=115)
            if len(report.software_inventory) > 300:
                self._add(lines, "R", 9, f"... {len(report.software_inventory) - 300} logiciels non affiches dans le PDF.")
        else:
            self._add(lines, "R", 10, "Aucun logiciel inventorie.")

        return self._build_pdf(lines)

    def _add(self, lines: list[tuple[str, int, str]], font: str, size: int, text: str) -> None:
        lines.append((font, size, self._clean_text(text)))

    def _add_wrapped(self, lines: list[tuple[str, int, str]], font: str, size: int, text: str, width: int) -> None:
        cleaned = self._clean_text(text)
        wrapped = textwrap.wrap(cleaned, width=width) or [""]
        for line in wrapped:
            self._add(lines, font, size, line)

    def _blank(self, lines: list[tuple[str, int, str]], size: int = 8) -> None:
        lines.append(("R", size, ""))

    def _build_pdf(self, lines: list[tuple[str, int, str]]) -> bytes:
        pages: list[list[tuple[str, int, int, str]]] = []
        page: list[tuple[str, int, int, str]] = []
        y = self.page_height - self.margin

        for font, size, text in lines:
            line_height = max(size + 4, 10)
            if y - line_height < self.bottom_margin and page:
                pages.append(page)
                page = []
                y = self.page_height - self.margin
            page.append((font, size, y, text))
            y -= line_height
        if page:
            pages.append(page)
        if not pages:
            pages = [[("R", 10, self.page_height - self.margin, "Rapport vide")]]

        objects: list[bytes] = []
        kids: list[str] = []
        page_objects: list[tuple[int, int, bytes]] = []
        first_page_obj = 5
        for index, page_lines in enumerate(pages):
            page_obj = first_page_obj + index * 2
            content_obj = page_obj + 1
            kids.append(f"{page_obj} 0 R")
            content = self._page_content(page_lines)
            page_objects.append((page_obj, content_obj, content))

        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objects.append(f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode("ascii"))
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        for page_obj, content_obj, content in page_objects:
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.page_width} {self.page_height}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_obj} 0 R >>".encode("ascii")
            )
            objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")

        return self._serialize_pdf(objects)

    def _page_content(self, lines: list[tuple[str, int, int, str]]) -> bytes:
        chunks: list[bytes] = []
        for font, size, y, text in lines:
            font_name = "F2" if font == "B" else "F1"
            escaped = self._escape_pdf_text(text)
            chunks.append(f"BT /{font_name} {size} Tf 1 0 0 1 {self.margin} {y} Tm ({escaped}) Tj ET".encode("latin-1"))
        return b"\n".join(chunks)

    def _serialize_pdf(self, objects: list[bytes]) -> bytes:
        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{index} 0 obj\n".encode("ascii"))
            output.extend(obj)
            output.extend(b"\nendobj\n")
        xref_offset = len(output)
        output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        output.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
        )
        return bytes(output)

    def _clean_text(self, value: object) -> str:
        text = str(value or "").replace("\r", " ").replace("\n", " ")
        return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

    def _escape_pdf_text(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
