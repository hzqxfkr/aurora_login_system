# app.py
import os
from datetime import datetime, timedelta
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load .env for local
load_dotenv()

# -------------------------
# Configuration
# -------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET", "FLASK_SECRET")
JWT_SECRET = os.environ.get("JWT_SECRET", "JWT-SECRET")
WIX_REDIRECT_URL = os.environ.get("WIX_SITE", "https://haziqfakhri21.wixsite.com/aurora-mind-verse--1")
TEACHER_REG_CODE = os.environ.get("TEACHER_REG_CODE", "letmein123")

CORS(app, resources={r"/api/*": {"origins": os.environ.get("WIX_ORIGIN", "*")}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")

# -------------------------
# Database helpers
# -------------------------
def get_db():
    db_url = DATABASE_URL

    # Force SSL for Render Postgres
    if db_url and "sslmode" not in db_url:
        if "?" in db_url:
            db_url += "&sslmode=require"
        else:
            db_url += "?sslmode=require"

    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'teacher')),
            created_at TIMESTAMP NOT NULL
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

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

        conn = get_db()
        cur = conn.cursor()

        try:
            pw_hash = generate_password_hash(password)
            cur.execute(
                "INSERT INTO users (username,password,role,created_at) VALUES (%s, %s, %s, %s)",
                (username, pw_hash, role, datetime.utcnow())
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("login"))
        except psycopg2.Error:
            cur.close()
            conn.close()
            return render_template("register.html", error="Username already exists.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        next_url = request.form.get("next") or request.args.get("next") or WIX_REDIRECT_URL

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row and check_password_hash(row["password"], password):
            # Session
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]

            # JWT token (10 min)
            payload = {
                "sub": str(row["id"]),  # must be string for PyJWT
                "username": row["username"],
                "role": row["role"],
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(minutes=10)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

            # Redirect to Wix
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
# API for Wix to validate token
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

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE id = %s", (payload["sub"],))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"valid": False, "reason": "user_not_found"}), 404

    return jsonify({"valid": True, "user": row})

# -------------------------
# Start
# -------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
