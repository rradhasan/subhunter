from flask import Flask, flash, render_template, request, redirect, url_for, jsonify
from subhunter import SubdomainDiscovery, Prober, Fingerprinter
from datetime import datetime
from database import Database
from config import Config

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
db = Database(Config.DATABASE_PATH)


def run_subhunter(domain, threads=10):
    discovery = SubdomainDiscovery(domain, "wordlists.txt")
    targets = discovery.combine()
    prober = Prober(targets, threads=threads)
    prober.run()
    live = prober.get_live()
    fingerprints = []
    for result in live:
        fp = Fingerprinter(result)
        fingerprints.append(fp.analyze())
    return targets, live, fingerprints


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        domain = request.form.get("domain")
        return redirect(url_for("scan"))
    return render_template("home.html")


@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form.get("domain")
    if not domain or "." not in domain:
        flash("Invalid domain. Please enter a valid domain like hackerone.com")
        return redirect(url_for("home"))
    targets, live, fingerprints = run_subhunter(domain)
    dead = len(targets) - len(live)
    scan_id = db.save_scan(domain, len(targets), len(live), dead)
    for fp in fingerprints:
        db.save_finding(scan_id, fp["url"], fp["status"], fp["tech"], fp["score"])
    return render_template(
        "results.html",
        domain=domain,
        targets=targets,
        fingerprints=fingerprints
    )


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = db.get_connection().execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    findings = db.get_findings(scan_id)
    if not scan:
        flash("Scan not found")
        return redirect(url_for("history"))
    return render_template("scan_details.html", scan=scan, findings=findings)


@app.route("/history")
def history():
    scans = db.get_all_scans()
    return render_template("history.html", history=scans)


# ============================================================
# API ROUTES
# ============================================================

@app.route("/api/status")
def api_status():
    total_scans = len(db.get_all_scans())
    return jsonify({
        "tool": "SubHunter",
        "version": "1.0",
        "status": "running",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_scans": total_scans
    })


@app.route("/api/scans", methods=["GET"])
def api_get_scans():
    scans = db.get_all_scans()
    return jsonify([dict(s) for s in scans])


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    scan = db.get_connection().execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if not scan:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404
    findings = db.get_findings(scan_id)
    return jsonify({
        "scan": dict(scan),
        "findings": [dict(f) for f in findings]
    }), 200


@app.route("/api/scans/domain/<domain>", methods=["GET"])
def api_get_by_domain(domain):
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC", (domain,)
    ).fetchall()
    conn.close()
    if not rows:
        return jsonify({"error": f"No scans found for {domain}"}), 404
    return jsonify([dict(r) for r in rows])


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "domain is required"}), 400
    domain = data["domain"].strip()
    if not domain or "." not in domain:
        return jsonify({"error": "invalid domain format"}), 400
    threads = data.get("threads", 10)
    targets, live, fingerprints = run_subhunter(domain, threads=threads)
    dead = len(targets) - len(live)
    scan_id = db.save_scan(domain, len(targets), len(live), dead)
    for fp in fingerprints:
        db.save_finding(scan_id, fp["url"], fp["status"], fp["tech"], fp["score"])
    return jsonify({
        "scan_id": scan_id,
        "domain": domain,
        "total_discovered": len(targets),
        "total_live": len(live),
        "total_dead": dead,
        "findings": fingerprints
    }), 201


@app.route("/api/history")
def api_history():
    scans = db.get_all_scans()
    return jsonify([dict(s) for s in scans])

@app.route("/api/docs")
def api_docs():
    docs = {
        "tool": "SubHunter API",
        "version": "1.0",
        "base_url": "http://127.0.0.1:5000",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/status",
                "description": "Tool status and statistics"
            },
            {
                "method": "GET",
                "path": "/api/scans",
                "description": "List all scans"
            },
            {
                "method": "GET",
                "path": "/api/scans/<id>",
                "description": "Get scan details and findings"
            },
            {
                "method": "GET",
                "path": "/api/scans/domain/<domain>",
                "description": "Get all scans for a domain"
            },
            {
                "method": "POST",
                "path": "/api/scan",
                "description": "Run a new scan",
                "body": {"domain": "string", "threads": "integer (optional, default 10)"}
            }
        ]
    }
    return jsonify(docs)


if __name__ == "__main__":
    app.run(debug=True)