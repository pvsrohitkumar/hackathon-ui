"""Vulnerability scanner: clone a repo, run npm audit, generate a PDF report."""

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MODERATE": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7d1128"),
    "HIGH": colors.HexColor("#c0392b"),
    "MODERATE": colors.HexColor("#e67e22"),
    "LOW": colors.HexColor("#2980b9"),
    "INFO": colors.HexColor("#7f8c8d"),
    "UNKNOWN": colors.HexColor("#95a5a6"),
}

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str) -> Path:
    """Clone a git repo into a temp directory and return its path."""
    tmp = Path(tempfile.mkdtemp(prefix="vulnscan_"))
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(tmp / "repo")],
        check=True,
        capture_output=True,
        text=True,
    )
    return tmp / "repo"


def cleanup_repo(repo_path: Path) -> None:
    """Remove the cloned repo directory."""
    parent = repo_path.parent
    if parent.name.startswith("vulnscan_"):
        shutil.rmtree(parent, ignore_errors=True)
    else:
        shutil.rmtree(repo_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# NPM helpers
# ---------------------------------------------------------------------------

def _run_npm(args: list[str], cwd: str) -> dict:
    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        shell=True,
    )
    raw = (result.stdout or result.stderr).strip()
    if not raw:
        raise RuntimeError(f"{' '.join(args)} produced no output.")
    return json.loads(raw)


def npm_install(repo_path: Path) -> None:
    subprocess.run(
        ["npm", "install", "--ignore-scripts"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
        shell=True,
    )


def run_npm_audit(repo_path: Path) -> dict:
    return _run_npm(["npm", "audit", "--json"], cwd=str(repo_path))


def get_installed_versions(repo_path: Path) -> dict[str, str]:
    data = _run_npm(["npm", "ls", "--all", "--json"], cwd=str(repo_path))
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


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

def summarize_rows(data: dict, installed_versions: dict[str, str]):
    vulnerabilities = data.get("vulnerabilities", {})
    rows = []
    for pkg, details in vulnerabilities.items():
        severity = str(details.get("severity", "unknown")).upper()
        version = installed_versions.get(pkg, "unknown")
        fix = "n/a"
        fix_data = details.get("fixAvailable")
        if isinstance(fix_data, dict):
            if fix_data.get("name"):
                fv = fix_data.get("version") or "latest"
                fix = f"{fix_data['name']}@{fv}"
            elif fix_data.get("version"):
                fix = str(fix_data["version"])
        elif isinstance(fix_data, str):
            fix = fix_data
        rows.append([severity, f"{pkg}@{version}", fix])

    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))
    return rows


def build_pdf(rows: list, project_name: str) -> Path:
    report_id = uuid.uuid4().hex[:10]
    output = REPORTS_DIR / f"{project_name}_{report_id}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1a237e"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#37474f"),
    )

    doc = SimpleDocTemplate(
        str(output),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    summary = Counter(r[0] for r in rows)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story: list = []
    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(Paragraph(f"Project: {project_name}", subtitle_style))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Spacer(1, 12))

    labels = ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO", "UNKNOWN"]
    summary_lines = [f"<b>Total findings:</b> {len(rows)}"]
    for label in labels:
        cnt = summary.get(label, 0)
        if cnt:
            summary_lines.append(f"<b>{label.title()}:</b> {cnt}")
    for line in summary_lines:
        story.append(Paragraph(line, styles["BodyText"]))

    story.append(Spacer(1, 16))

    # Table
    header = ["Severity", "Package — Version", "Fix Version"]
    table_data = [header] + rows

    col_widths = [80, 250, 200]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    base_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#bdbdbd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    # Color-code severity cells
    for i, row in enumerate(rows, start=1):
        sev = row[0]
        bg = SEVERITY_COLORS.get(sev, colors.white)
        base_style.append(("BACKGROUND", (0, i), (0, i), bg))
        base_style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        base_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    table.setStyle(TableStyle(base_style))
    story.append(table)

    doc.build(story)
    return output


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_repo(repo_url: str, progress_callback=None) -> dict:
    """
    End-to-end scan: clone → install → audit → PDF.
    Returns a dict with summary info and the path to the PDF.
    """
    def _progress(msg):
        if progress_callback:
            progress_callback(msg)

    repo_path = None
    try:
        _progress("Cloning repository…")
        repo_path = clone_repo(repo_url)
        project_name = repo_path.name or "project"

        # Check for package.json
        if not (repo_path / "package.json").exists():
            raise RuntimeError(
                "No package.json found in the repository root. "
                "Only Node.js / npm projects are supported."
            )

        _progress("Installing dependencies…")
        npm_install(repo_path)

        _progress("Running npm audit…")
        audit_data = run_npm_audit(repo_path)

        _progress("Resolving installed versions…")
        installed_versions = get_installed_versions(repo_path)

        _progress("Building report…")
        rows = summarize_rows(audit_data, installed_versions)
        pdf_path = build_pdf(rows, project_name)

        summary = Counter(r[0] for r in rows)
        return {
            "success": True,
            "pdf_path": str(pdf_path),
            "pdf_filename": pdf_path.name,
            "project_name": project_name,
            "total": len(rows),
            "critical": summary.get("CRITICAL", 0),
            "high": summary.get("HIGH", 0),
            "moderate": summary.get("MODERATE", 0),
            "low": summary.get("LOW", 0),
            "info": summary.get("INFO", 0),
            "unknown": summary.get("UNKNOWN", 0),
            "rows": rows,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        if repo_path:
            cleanup_repo(repo_path)
