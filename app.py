import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_cors import CORS

# -------------------------
# Flask app setup
# -------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET", "FLASK_SECRET")   # change in prod
JWT_SECRET = os.environ.get("JWT_SECRET", "JWT-SECRET")           # change in prod
WIX_REDIRECT_URL = os.environ.get("WIX_SITE", "https://haziqfakhri21.wixsite.com/aurora-mind-verse--1")
TEACHER_REG_CODE = os.environ.get("TEACHER_REG_CODE", "letmein123")

# Allow CORS for Wix
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

def create_tables():
    """Create both users and tokens tables if they don't exist."""
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
    db.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
    """)
    db.commit()

@app.before_request
def ensure_tables_exist():
    """Run before every request to make sure DB is ready."""
    create_tables()

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
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]

            expires_at = datetime.utcnow() + timedelta(hours=1)
            payload = {
                "sub": str(row["id"]),
                "username": row["username"],
                "role": row["role"],
                "iat": datetime.utcnow(),
                "exp": expires_at
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

            db.execute("INSERT OR REPLACE INTO tokens (token, user_id, issued_at, expires_at) VALUES (?, ?, ?, ?)",
                       (token, row["id"], datetime.utcnow().isoformat(), expires_at.isoformat()))
            db.commit()

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
    try:
        user_id = session.get("user_id")
        if user_id:
            db = get_db()
            # Delete user account
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            print(f"Deleted user account with ID {user_id}")
    except Exception as e:
        print(f"Logout error: {e}")  # Log error but don't crash
    finally:
        session.clear()
    return redirect(url_for("home"))


# -------------------------
# API endpoint for Wix
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
    token_row = db.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    if not token_row:
        return jsonify({"valid": False, "reason": "logged_out"}), 401

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
    create_tables()
    app.run(host="0.0.0.0", port=5000, debug=True)
