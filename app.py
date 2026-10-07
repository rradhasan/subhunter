from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, flash, render_template, request, redirect, url_for, jsonify, session
from subhunter import SubdomainDiscovery, Prober, Fingerprinter
from datetime import datetime
from database import Database
from config import Config
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
db = Database(Config.DATABASE_PATH)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

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


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("[!] Please login first")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        domain = request.form.get("domain")
        return redirect(url_for("scan"))
    return render_template("home.html")


@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    domain = request.form.get("domain")
    if not domain or "." not in domain:
        flash("Invalid domain. Please enter a valid domain like hackerone.com")
        return redirect(url_for("home"))
    targets, live, fingerprints = run_subhunter(domain)
    dead = len(targets) - len(live)
    scan_id = db.save_scan(domain, len(targets), len(live), dead, session["user_id"])
    for fp in fingerprints:
        db.save_finding(scan_id, fp["url"], fp["status"], fp["tech"], fp["score"])
    return render_template(
        "results.html",
        domain=domain,
        targets=targets,
        fingerprints=fingerprints
    )


@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = db.get_connection().execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,),
        (scan_id, session["user_id"])
    ).fetchone()
    findings = db.get_findings(scan_id)
    if not scan:
        flash("Scan not found or access denied")
        return redirect(url_for("history"))
    return render_template("scan_details.html", scan=scan, findings=findings)

@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete(scan_id):
    conn = db.get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"])
    ).fetchone()
    if not scan:
        flash("[!] Scan not found or access denied")
        return redirect(url_for("history"))
    conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    flash("[+] Scan Deleted")
    return redirect(url_for("history"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("[!] Username and password required")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("[!] Password must be at least 8 characters")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        saved = db.create_user(username, password_hash)
        if not saved:
            flash("[!] Username already taken")
            return redirect(url_for("register"))
        
        flash("[+] Account created - Please login")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.get_user(username)

        if not user or not check_password_hash(user["password_hash"], password):
            flash("[!] Invalid username or password")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash(f"[+] Welcome back {username}")
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/account")
@login_required
def account():
    user = db.get_user(session["username"])
    scans = db.get_user_scans(session["user_id"])
    return render_template("account.html",
                            user=user,
                            total_scans=len(scans)
                        )

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm = request.form.get("confirm_password")
        user = db.get_user(session["username"])

        if not check_password_hash(user["password_hash"], current):
            flash("[!] Current Passsword is incorrect")
            return redirect(url_for("change_password"))

        if new_password != confirm:
            flash("[!] Password didn't match")
            return redirect(url_for("change_password"))

        if len(new_password) < 8:
            flash("[!] Password is too short. It must be 8 characters")
            return redirect(url_for("change_password"))

        new_hash = generate_password_hash(new_password)
        db.update_password(session["username"], new_hash)
        flash("[+] Password changed successfully")
        return redirect(url_for("account"))

    return render_template("change_password.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("[+] Logged out successfully")
    return redirect(url_for("login"))


@app.route("/history")
@login_required
def history():
    if session["username"] == "admin":
        scans = db.get_all_scans()
    else:
        scans = db.get_user_scans(session["user_id"])
    return render_template("history.html", history=scans)


# ============================================================
# API ROUTES
# ============================================================

@app.route("/api/status")
@login_required
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
@login_required
def api_get_scans():
    scans = db.get_all_scans()
    return jsonify([dict(s) for s in scans])


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
@login_required
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
@login_required
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
@login_required
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
    scan_id = db.save_scan(domain, len(targets), len(live), dead, session["user_id"])
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
@login_required
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