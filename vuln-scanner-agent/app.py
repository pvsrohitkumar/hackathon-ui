"""Flask web UI for the vulnerability scanner agent."""

from flask import Flask, jsonify, render_template, request, send_file
from pathlib import Path
from scanner import scan_repo, REPORTS_DIR

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    repo_url = (data.get("repo_url") or "").strip()
    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400

    result = scan_repo(repo_url)
    return jsonify(result)


@app.route("/download/<filename>")
def download(filename):
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "Report not found."}), 404
    return send_file(filepath, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
