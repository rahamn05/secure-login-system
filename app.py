from flask import Flask, render_template, request, redirect, url_for, session, flash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import sqlite3
import secrets
import re
from datetime import timedelta

# ============================================================
# SECURE LOGIN SYSTEM
# ============================================================

app = Flask(__name__)

# Secret key for secure Flask sessions
app.secret_key = secrets.token_hex(32)

# Session configuration
app.permanent_session_lifetime = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Database
DATABASE = "secure_login.db"

# Argon2 password hashing
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

    print("✅ Database ready")
    print("✅ Users table ready")
    print("🔐 Argon2 password hashing enabled")


# ============================================================
# INPUT VALIDATION
# ============================================================

def validate_username(username):

    if not username:
        return "Username is required."

    if len(username) < 3:
        return "Username must contain at least 3 characters."

    if len(username) > 30:
        return "Username must not exceed 30 characters."

    if not re.match(r"^[A-Za-z0-9_.]+$", username):
        return "Username can contain only letters, numbers, underscore and dot."

    return None


def validate_email(email):

    if not email:
        return "Email is required."

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(pattern, email):
        return "Please enter a valid email address."

    return None


def validate_password(password):

    if not password:
        return "Password is required."

    if len(password) < 8:
        return "Password must contain at least 8 characters."

    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."

    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."

    return None


# ============================================================
# HOME / LOGIN PAGE
# ============================================================

@app.route("/")
def login():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ============================================================
# REGISTER PAGE
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # -----------------------------
        # VALIDATE USERNAME
        # -----------------------------

        error = validate_username(username)

        if error:
            flash(error, "error")
            return render_template("register.html")

        # -----------------------------
        # VALIDATE EMAIL
        # -----------------------------

        error = validate_email(email)

        if error:
            flash(error, "error")
            return render_template("register.html")

        # -----------------------------
        # VALIDATE PASSWORD
        # -----------------------------

        error = validate_password(password)

        if error:
            flash(error, "error")
            return render_template("register.html")

        # -----------------------------
        # CONFIRM PASSWORD
        # -----------------------------

        if password != confirm_password:

            flash("Passwords do not match.", "error")

            return render_template("register.html")

        connection = get_db()

        cursor = connection.cursor()

        try:

            # Check whether username/email already exists
            cursor.execute("""
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
            """, (username, email))

            existing_user = cursor.fetchone()

            if existing_user:

                flash(
                    "Username or email already exists.",
                    "error"
                )

                connection.close()

                return render_template("register.html")

            # -----------------------------
            # HASH PASSWORD USING ARGON2
            # -----------------------------

            password_hash = password_hasher.hash(password)

            # -----------------------------
            # INSERT USER
            # -----------------------------

            cursor.execute("""
                INSERT INTO users
                (username, email, password_hash)
                VALUES (?, ?, ?)
            """, (
                username,
                email,
                password_hash
            ))

            connection.commit()

            connection.close()

            flash(
                "Account created successfully. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            connection.rollback()
            connection.close()

            flash(
                "Username or email already exists.",
                "error"
            )

            return render_template("register.html")

        except Exception as error:

            connection.rollback()
            connection.close()

            print("Registration error:", error)

            flash(
                "Something went wrong. Please try again.",
                "error"
            )

            return render_template("register.html")


    return render_template("register.html")


# ============================================================
# LOGIN PROCESS
# ============================================================

@app.route("/login", methods=["POST"])
def login_user():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:

        flash(
            "Username and password are required.",
            "error"
        )

        return redirect(url_for("login"))

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, username, email, password_hash
        FROM users
        WHERE username = ? OR email = ?
    """, (
        username,
        username.lower()
    ))

    user = cursor.fetchone()

    connection.close()

    if not user:

        flash(
            "Invalid username or password.",
            "error"
        )

        return redirect(url_for("login"))

    # ========================================================
    # VERIFY ARGON2 PASSWORD
    # ========================================================

    try:

        password_hasher.verify(
            user["password_hash"],
            password
        )

        # Regenerate session after successful authentication
        session.clear()

        session.permanent = True

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]

        return redirect(url_for("dashboard"))

    except (VerifyMismatchError, VerificationError):

        flash(
            "Invalid username or password.",
            "error"
        )

        return redirect(url_for("login"))

    except Exception as error:

        print("Login error:", error)

        flash(
            "Login failed. Please try again.",
            "error"
        )

        return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash(
            "Please login first.",
            "error"
        )

        return redirect(url_for("login"))

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>Secure Dashboard</title>

        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">

        <style>

            * {{
                box-sizing: border-box;
                font-family: Arial, sans-serif;
            }}

            body {{
                margin: 0;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background:
                    linear-gradient(
                        135deg,
                        #0f172a,
                        #1e3a8a
                    );
            }}

            .card {{
                width: 450px;
                background: white;
                padding: 45px;
                border-radius: 20px;
                text-align: center;
                box-shadow:
                    0 20px 60px
                    rgba(0,0,0,0.3);
            }}

            .icon {{
                font-size: 55px;
                margin-bottom: 10px;
            }}

            h1 {{
                color: #111827;
                margin-bottom: 10px;
            }}

            p {{
                color: #6b7280;
            }}

            .username {{
                color: #2563eb;
                font-weight: bold;
            }}

            .security {{
                margin-top: 25px;
                padding: 15px;
                background: #eff6ff;
                color: #1e40af;
                border-radius: 10px;
            }}

            .logout {{
                display: inline-block;
                margin-top: 25px;
                padding: 13px 25px;
                background: #dc2626;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: bold;
            }}

            .logout:hover {{
                background: #b91c1c;
            }}

        </style>

    </head>

    <body>

        <div class="card">

            <div class="icon">🛡️</div>

            <h1>Welcome!</h1>

            <p>
                Hello,
                <span class="username">
                    {session["username"]}
                </span>
            </p>

            <div class="security">

                🔐 Your session is protected.

                <br><br>

                Passwords are stored using
                <strong>Argon2 hashing</strong>.

            </div>

            <a
                class="logout"
                href="/logout">

                Logout

            </a>

        </div>

    </body>

    </html>
    """


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(url_for("login"))


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    """, 404


@app.errorhandler(500)
def internal_server_error(error):

    return """
    <h1>500 - Internal Server Error</h1>
    <p>Something went wrong on the server.</p>
    """, 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    create_database()

    print()
    print("=" * 55)
    print("🔐 SECURE LOGIN SYSTEM")
    print("=" * 55)
    print("🌐 Starting Flask server...")
    print("🔒 Argon2 password hashing: ENABLED")
    print("🗄️ SQLite database: ENABLED")
    print("🛡️ Input validation: ENABLED")
    print("👤 Registration: ENABLED")
    print("🔑 Login: ENABLED")
    print("🚪 Logout: ENABLED")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )