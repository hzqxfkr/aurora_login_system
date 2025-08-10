# app.py
import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_cors import CORS  # <-- import here

# -------------------------
# Configuration (change for production)
# -------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET", "FLASK_SECRET")   # change in prod
JWT_SECRET = os.environ.get("JWT_SECRET", "JWT-SECRET")           # change in prod
WIX_REDIRECT_URL = os.environ.get("WIX_SITE", "https://haziqfakhri21.wixsite.com/aurora-mind-verse--1")  # update to your Wix site URL
TEACHER_REG_CODE = os.environ.get("TEACHER_REG_CODE", "letmein123")  # simple gate for teacher reg

# Enable CORS for Wix API calls
CORS(app, resources={r"/api/*": {"origins": os.environ.get("WIX_ORIGIN", "*")}}, supports_credentials=True)

DATABASE = os.path.join(os.path.dirname(__file__), "aurora.db")

# -------------------------
# Database helpers
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student','teacher')),
                created_at TEXT NOT NULL
            );
        """)
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form["role"]
        teacher_code = request.form.get("teacher_code","").strip()
        if role == "teacher" and teacher_code != TEACHER_REG_CODE:
            return render_template("register.html", error="Invalid teacher registration code.")
        db = get_db()
        try:
            pw_hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username,password,role,created_at) VALUES (?, ?, ?, ?)",
                       (username, pw_hash, role, datetime.utcnow().isoformat()))
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already exists.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        next_url = request.form.get("next") or request.args.get("next") or WIX_REDIRECT_URL
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password"], password):
            # create server-side session
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]

            # JWT valid for 1 hour
            payload = {
                "sub": str(row["id"]),  # must be string
                "username": row["username"],
                "role": row["role"],
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(hours=1)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

            # Redirect to Wix with token in URL
            redirect_url = f"{next_url.rstrip('/')}/?token={token}"
            return redirect(redirect_url)

        return render_template("login.html", error="Wrong username or password.")
    return render_template("login.html", next=request.args.get("next", ""))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login", next=WIX_REDIRECT_URL))
    if session.get("role") == "teacher":
        return render_template("teacher.html", username=session.get("username"))
    return render_template("student.html", username=session.get("username"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# -------------------------
# API endpoint Wix will call to validate tokens
# -------------------------
@app.route("/api/validate_token", methods=["GET"])
def api_validate_token():
    token = request.args.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"valid": False, "reason": "no_token"}), 400
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "reason": "expired"}), 401
    except Exception as e:
        return jsonify({"valid": False, "reason": "invalid", "error": str(e)}), 400
    db = get_db()
    row = db.execute("SELECT id, username, role FROM users WHERE id = ?", (payload["sub"],)).fetchone()
    if not row:
        return jsonify({"valid": False, "reason": "user_not_found"}), 404
    return jsonify({
        "valid": True,
        "user": {"id": row["id"], "username": row["username"], "role": row["role"]}
    })

# -------------------------
# Start
# -------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
