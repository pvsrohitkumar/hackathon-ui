#!/usr/bin/env python3
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "sonatype-vulnerability-report.pdf"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def _run_npm_command(args: list[str]) -> dict:
    """Run an npm command and return parsed JSON output."""
    result = subprocess.run(
        args,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        shell=True,
    )
    raw = (result.stdout or result.stderr).strip()
    if not raw:
        raise RuntimeError(f"{' '.join(args)} did not return any output.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{' '.join(args)} returned invalid JSON: {exc}") from exc


def run_npm_audit() -> dict:
    return _run_npm_command(["npm", "audit", "--json"])


def get_installed_versions() -> dict[str, str]:
    """Return a mapping of package name -> installed version using npm ls."""
    data = _run_npm_command(["npm", "ls", "--all", "--json"])

    versions: dict[str, str] = {}

    def _walk(deps: dict):
        for name, info in deps.items():
            if isinstance(info, dict):
                ver = info.get("version")
                if ver and name not in versions:
                    versions[name] = ver
                _walk(info.get("dependencies", {}))

    _walk(data.get("dependencies", {}))
    return versions


def summarize_rows(data: dict, installed_versions: dict[str, str]):
    vulnerabilities = data.get("vulnerabilities", {})
    rows = []
    for package_name, details in vulnerabilities.items():
        severity = str(details.get("severity", "unknown")).upper()
        version = installed_versions.get(package_name, "unknown")
        fix = "n/a"
        fix_data = details.get("fixAvailable")
        if isinstance(fix_data, dict):
            if fix_data.get("name"):
                fix_version = fix_data.get("version") or "latest"
                fix = f"{fix_data['name']}@{fix_version}"
            elif fix_data.get("version"):
                fix = str(fix_data["version"])
        elif isinstance(fix_data, str):
            fix = fix_data
        rows.append([severity, f"{package_name}@{version}", fix])

    rows.sort(key=lambda item: (SEVERITY_ORDER.get(item[0], 99), item[1]))
    return rows


def build_pdf(rows):
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    summary = Counter(row[0] for row in rows)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(rows)

    story = []
    story.append(Paragraph("Sonatype-Style Vulnerability Scan Report", styles["Title"]))
    story.append(Paragraph(f"Project: {ROOT.name}", styles["Heading2"]))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Spacer(1, 10))

    summary_lines = [
        f"Total findings: {total}",
        *[f"{label.title()}: {summary.get(label, 0)}" for label in ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO", "UNKNOWN"]],
    ]
    for line in summary_lines:
        story.append(Paragraph(line, styles["BodyText"]))

    story.append(Spacer(1, 14))

    table_data = [["Severity", "Package — Version", "Fix Version"]]
    table_data.extend(rows)

    table = Table(table_data, colWidths=[80, 240, 200])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.8, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
            ]
        )
    )
    story.append(table)
    document.build(story)


if __name__ == "__main__":
    try:
        audit_data = run_npm_audit()
        installed_versions = get_installed_versions()
        rows = summarize_rows(audit_data, installed_versions)
        build_pdf(rows)
        print(f"Sonatype-style vulnerability report created at: {OUTPUT_PATH}")
        print(f"Total findings: {len(rows)}")
        for severity in ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO", "UNKNOWN"]:
            count = sum(1 for row in rows if row[0] == severity)
            if count:
                print(f"{severity}: {count}")
    except Exception as exc:  # pragma: no cover - CLI error path
        raise SystemExit(f"Scan failed: {exc}")
