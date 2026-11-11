from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from pathlib import Path
import sqlite3, logging, json, time, re
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
LOGS = BASE / "logs"
DATA.mkdir(exist_ok=True)
LOGS.mkdir(exist_ok=True)
DB_PATH = DATA / "clearbank.db"

app = Flask(__name__)
app.secret_key = "replace-this-development-secret-before-sharing"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# One structured event log: logs/security.log (JSON Lines)
logger = logging.getLogger("clearbank.security")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOGS / "security.log", maxBytes=2_000_000, backupCount=3)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

def log_event(event_type, status="INFO", detail="", endpoint=None):
    # Never log passwords, session cookies, or full form bodies.
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": request.remote_addr or "unknown",
        "event_type": event_type,
        "endpoint": endpoint or request.path,
        "method": request.method,
        "status": status,
        "user_agent": request.headers.get("User-Agent", "")[:180],
        "detail": detail[:240]
    }
    logger.info(json.dumps(record, ensure_ascii=False))

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            account_no TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            txn_date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        users = [
            ("admin", "Admin@123", "Jordan Blake", "CB-1000-0001", 98500.00),
            ("demo", "Demo@123", "Alex Morgan", "CB-2048-7712", 28450.75),
            ("j.smith", "Welcome@123", "Jamie Smith", "CB-2048-7713", 12480.20),
            ("m.taylor", "Banking@123", "Morgan Taylor", "CB-2048-7714", 6720.00),
            ("support", "Support@123", "Casey Lee", "CB-2048-7715", 4310.50),
            ("analyst", "Analyst@123", "Riley Chen", "CB-2048-7716", 15320.10),
        ]
        rows = [("Salary Credit",3200.00,"2026-10-28"),("Online Purchase",-84.50,"2026-10-26"),("Utility Payment",-126.25,"2026-10-23"),("Transfer Received",450.00,"2026-10-19"),("Grocery Store",-63.20,"2026-10-15")]
        for user in users:
            db.execute("INSERT OR IGNORE INTO users(username,password,full_name,account_no,balance) VALUES(?,?,?,?,?)", user)
            # Refresh demo identity fields so existing local databases show the correct name per account.
            db.execute("UPDATE users SET password=?, full_name=?, account_no=?, balance=? WHERE username=?",
                       (user[1], user[2], user[3], user[4], user[0]))
        for (uid,) in db.execute("SELECT id FROM users").fetchall():
            if db.execute("SELECT COUNT(*) FROM transactions WHERE user_id=?", (uid,)).fetchone()[0] == 0:
                db.executemany("INSERT INTO transactions(user_id,description,amount,txn_date) VALUES(?,?,?,?)", [(uid,*r) for r in rows])
        db.commit()

@app.before_request
def request_observer():
    # Basic request telemetry. This does not classify an attack by itself.
    if request.path.startswith("/static"):
        return
    suspicious = []
    raw = request.query_string.decode("utf-8", "ignore").lower()
    if any(x in raw for x in ("union", "select", "or%201%3d1", "<script", "%3cscript")):
        suspicious.append("suspicious_query_pattern")
    if suspicious:
        log_event("SUSPICIOUS_REQUEST_PATTERN", "REVIEW", ",".join(suspicious))
    # A small per-process request-rate observation, not a DoS verdict.
    now=time.time()
    recent=getattr(app, "_recent_requests", [])
    recent=[t for t in recent if now-t < 5]
    recent.append(now)
    app._recent_requests=recent
    if len(recent) >= 35:
        log_event("HIGH_REQUEST_RATE", "REVIEW", f"{len(recent)} requests observed in rolling 5-second window")

@app.route("/")
def home():
    log_event("PAGE_VIEW")
    return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username=request.form.get("username","")[:80]
        password=request.form.get("password","")[:120]
        # Intentionally vulnerable SQL query for an isolated training target.
        # Do not deploy this application publicly or use real credentials.
        query=f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user=get_db().execute(query).fetchone()
            if user:
                session["user_id"]=user["id"]
                session["name"]=user["full_name"]
                log_event("LOGIN_SUCCESS", "SUCCESS", f"account={user['account_no']}")
                return redirect(url_for("dashboard"))
            log_event("LOGIN_FAILURE", "FAILURE", f"username={username[:60]}")
            flash("The details you entered could not be verified.", "error")
        except sqlite3.Error as exc:
            log_event("DATABASE_ERROR", "ERROR", f"login query error: {type(exc).__name__}")
            flash("We could not process your request. Please try again.", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:40]
        password = request.form.get("password", "")[:120]
        if not username or not password:
            flash("Enter a username and password.", "error")
        else:
            # Registration is parameterized; the login route remains intentionally vulnerable for the SQLi lab.
            try:
                full_name = username
                account_no = "CB-" + str(int(time.time() * 1000))[-10:]
                get_db().execute(
                    "INSERT INTO users(username,password,full_name,account_no,balance) VALUES(?,?,?,?,?)",
                    (username, password, full_name, account_no, 1000.00)
                )
                get_db().commit()
                new_user = get_db().execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                get_db().execute(
                    "INSERT INTO transactions(user_id,description,amount,txn_date) VALUES(?,?,?,?)",
                    (new_user["id"], "Welcome to ClearBank", 1000.00, datetime.now().strftime("%Y-%m-%d"))
                )
                get_db().commit()
                log_event("ACCOUNT_REGISTERED", "SUCCESS", f"username={username}")
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username already exists. Choose another.", "error")
    return render_template("register.html")

@app.route("/logout")
def logout():
    log_event("LOGOUT")
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    user=get_db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    tx=get_db().execute("SELECT * FROM transactions WHERE user_id=? ORDER BY txn_date DESC",
                        (session["user_id"],)).fetchall()
    log_event("DASHBOARD_VIEW", "SUCCESS", f"account={user['account_no']}")
    return render_template("dashboard.html", user=user, transactions=tx, display_username=user["username"])

@app.route("/search", methods=["GET","POST"])
def search():
    results=[]
    term=request.values.get("term", request.values.get("q", ""))[:180]
    if term:
        # Intentionally vulnerable query for the local SQL injection exercise.
        query=f"SELECT id,description,amount,txn_date FROM transactions WHERE description LIKE '%{term}%'"
        try:
            results=get_db().execute(query).fetchall()
            log_event("ACCOUNT_SEARCH", "SUCCESS", f"search_length={len(term)}; results={len(results)}")
        except sqlite3.Error as exc:
            log_event("DATABASE_ERROR", "ERROR", f"search query error: {type(exc).__name__}")
            flash("Search could not be completed.", "error")
    return render_template("search.html", results=results, term=term)

@app.route("/feedback", methods=["GET","POST"])
def feedback():
    message=""
    if request.method=="POST":
        message=request.form.get("message","")[:500]
        if re.search(r"<\s*script|javascript\s*:", message, re.I):
            log_event("SUSPICIOUS_XSS_INPUT", "REVIEW", "script-like content submitted to feedback")
        else:
            log_event("FEEDBACK_SUBMITTED", "SUCCESS", f"message_length={len(message)}")
        # Intentionally rendered unescaped in this lab page to demonstrate reflected/stored-style XSS behavior.
        return render_template("feedback.html", submitted=message)
    return render_template("feedback.html", submitted=None)

@app.route("/service-status")
def service_status():
    log_event("SERVICE_STATUS_CHECK")
    return {"service":"online","status":"available"}

@app.errorhandler(404)
def not_found(_):
    log_event("HTTP_404", "NOTICE", "unmatched route")
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(_):
    log_event("HTTP_500", "ERROR", "unhandled application error")
    return render_template("404.html"), 500

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
