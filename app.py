from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    redirect,
    url_for,
    session
)

import mysql.connector
import re

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


app = Flask(__name__)

app.secret_key = "ai_fake_email_detector_secret"


# =========================================================
# DATABASE
# =========================================================

# =========================================================
# DATABASE - XAMPP MYSQL
# =========================================================

class MySQLConnection:

    def __init__(self):

        self.connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="ai_fake_email_detector"
        )

    def execute(self, query, params=()):

        # Convert SQLite ? placeholders to MySQL %s
        query = query.replace("?", "%s")

        cursor = self.connection.cursor(
            dictionary=True
        )

        cursor.execute(query, params)

        return cursor

    def commit(self):

        self.connection.commit()

    def close(self):

        self.connection.close()


def get_db():

    return MySQLConnection()


def init_db():

    conn = get_db()

    # =====================================================
    # USERS
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)

    # =====================================================
    # EMAIL HISTORY
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            email_text TEXT NOT NULL,
            result VARCHAR(100) NOT NULL,
            risk VARCHAR(20) NOT NULL,
            score INT NOT NULL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    # =====================================================
    # REPORTED EMAILS
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            sender VARCHAR(150),
            subject VARCHAR(255),
            reason VARCHAR(100) NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    conn.commit()

    conn.close()

    print("====================================")
    print("MySQL Database Connected Successfully")
    print("Database: ai_fake_email_detector")
    print("Tables: users, history, reports")
    print("====================================")
# =========================================================
# LOGIN REQUIRED HELPER
# =========================================================

def logged_in():

    return "user_id" in session


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def home():

    if not logged_in():

        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = get_db()

    total = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
    """, (user_id,)).fetchone()["count"]

    high = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'HIGH'
    """, (user_id,)).fetchone()["count"]

    medium = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'MEDIUM'
    """, (user_id,)).fetchone()["count"]

    low = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'LOW'
    """, (user_id,)).fetchone()["count"]

    average = conn.execute("""
        SELECT AVG(score) AS average
        FROM history
        WHERE user_id = ?
    """, (user_id,)).fetchone()["average"]

    average_score = round(average or 0)

    recent_scans = conn.execute("""
        SELECT *
        FROM history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    """, (user_id,)).fetchall()

    conn.close()

    return render_template_string(
        DASHBOARD_HTML,
        name=session.get("name"),
        total=total,
        high=high,
        medium=medium,
        low=low,
        average_score=average_score,
        recent_scans=recent_scans
    )


# =========================================================
# NORMAL EMAIL CHECK
# =========================================================

@app.route("/check-email")
def check_email():

    if not logged_in():

        return redirect(url_for("login"))

    return render_template(
        "index.html",
        name=session.get("name")
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not name or not email or not password:

            return render_template(
                "register.html",
                error="Please fill all fields."
            )

        email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        if not re.match(email_pattern, email):

            return render_template(
                "register.html",
                error="Please enter a valid email address."
            )

        conn = get_db()

        try:

            existing_user = conn.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing_user:

                return render_template(
                    "register.html",
                    error="This account is already registered."
                )

            hashed_password = generate_password_hash(
                password
            )

            conn.execute("""
                INSERT INTO users
                (name, email, password)
                VALUES (?, ?, ?)
            """, (
                name,
                email,
                hashed_password
            ))

            conn.commit()

        finally:

            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# EMAIL ANALYSIS ENGINE
# =========================================================

def analyze_email(email):

    text = email.lower()

    detected = []

    score = 0

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_words = {

        "urgent": 7,
        "immediately": 7,
        "click here": 7,
        "click the link": 7,

        "verify your account": 8,
        "account suspended": 8,
        "account blocked": 8,

        "password": 6,
        "otp": 8,

        "bank account": 9,
        "credit card": 9,

        "won": 6,
        "winner": 6,
        "prize": 6,
        "lottery": 7,

        "free money": 8,
        "claim now": 7,

        "limited time": 5,

        "confirm your identity": 7,
        "send money": 9,
        "payment required": 8,

        "login": 5,
        "security alert": 6,

        "reward": 5,
        "insecure link": 8
    }

    for word, points in suspicious_words.items():

        if word in text:

            detected.append(word)

            score += points

    # -----------------------------------------------------
    # URL DETECTION
    # -----------------------------------------------------

    urls = re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        text
    )

    if urls:

        score += 10

        detected.append("suspicious link")

    # -----------------------------------------------------
    # HTTP
    # -----------------------------------------------------

    if "http://" in text:

        score += 8

        detected.append("non-secure link")

    # -----------------------------------------------------
    # IP ADDRESS URL
    # -----------------------------------------------------

    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'

    if re.search(ip_pattern, text):

        score += 15

        detected.append("IP address link")

    # -----------------------------------------------------
    # EXCESSIVE EXCLAMATION
    # -----------------------------------------------------

    if text.count("!") >= 3:

        score += 5

        detected.append(
            "excessive exclamation marks"
        )

    # -----------------------------------------------------
    # MONEY
    # -----------------------------------------------------

    money_symbols = [
        "₹",
        "$",
        "€",
        "£"
    ]

    if any(symbol in email for symbol in money_symbols):

        score += 5

        detected.append(
            "money-related content"
        )

    # -----------------------------------------------------
    # PERSONAL INFORMATION
    # -----------------------------------------------------

    personal_words = [

        "date of birth",
        "social security",
        "pan card",
        "aadhaar",
        "address",
        "phone number",
        "personal information"

    ]

    for word in personal_words:

        if word in text:

            score += 8

            detected.append(word)

    # -----------------------------------------------------
    # PASSWORD / OTP
    # -----------------------------------------------------

    password_patterns = [

        "enter your password",
        "send your password",
        "share your password",
        "enter otp",
        "share otp",
        "send otp"

    ]

    for phrase in password_patterns:

        if phrase in text:

            score += 10

            detected.append(phrase)

    # -----------------------------------------------------
    # ACCOUNT THREATS
    # -----------------------------------------------------

    account_threats = [

        "account will be closed",
        "account will be deleted",
        "account will be locked",
        "your account is at risk",
        "failure to verify",
        "action required"

    ]

    for phrase in account_threats:

        if phrase in text:

            score += 8

            detected.append(phrase)

    # -----------------------------------------------------
    # INVALID EMAIL FORMAT
    # -----------------------------------------------------

    if "@" not in email:

        score += 5

        detected.append(
            "invalid email format"
        )

    # -----------------------------------------------------
    # REMOVE DUPLICATES
    # -----------------------------------------------------

    detected = list(
        dict.fromkeys(detected)
    )

    # -----------------------------------------------------
    # SCORE LIMIT
    # -----------------------------------------------------

    score = min(score, 100)

    # -----------------------------------------------------
    # CLASSIFICATION
    # -----------------------------------------------------

    if score >= 40:

        result = "SUSPICIOUS EMAIL"

        risk = "HIGH"

        message = (
            "This email contains several "
            "characteristics commonly associated "
            "with phishing or suspicious messages."
        )

    elif score >= 20:

        result = "POSSIBLY SUSPICIOUS"

        risk = "MEDIUM"

        message = (
            "This email contains some suspicious "
            "characteristics. Be careful before "
            "clicking links or sharing information."
        )

    else:

        result = "LIKELY GENUINE"

        risk = "LOW"

        message = (
            "No major suspicious patterns were "
            "detected in this email."
        )

    if detected:

        reasons = ", ".join(detected)

    else:

        reasons = (
            "No suspicious characteristics detected"
        )

    return {

        "result": result,
        "risk": risk,
        "score": score,
        "message": message,
        "detected": detected,
        "reasons": reasons

    }


# =========================================================
# NORMAL PREDICTION
# =========================================================

@app.route("/predict", methods=["POST"])
def predict():

    if not logged_in():

        return redirect(url_for("login"))

    email = request.form.get(
        "email",
        ""
    ).strip()

    if not email:

        return redirect(
            url_for("check_email")
        )

    analysis = analyze_email(email)

    save_scan(
        email,
        analysis
    )

    return render_template(
        "result.html",
        result=analysis["result"],
        risk=analysis["risk"],
        score=analysis["score"],
        message=analysis["message"],
        detected=analysis["detected"]
    )


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(email, analysis):

    conn = get_db()

    conn.execute("""
        INSERT INTO history
        (
            user_id,
            email_text,
            result,
            risk,
            score,
            reasons
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (

        session["user_id"],
        email,
        analysis["result"],
        analysis["risk"],
        analysis["score"],
        analysis["reasons"]

    ))

    conn.commit()

    conn.close()


# =========================================================
# ADVANCED EMAIL SCAN
# =========================================================

@app.route(
    "/advanced-scan",
    methods=["GET", "POST"]
)
def advanced_scan():

    if not logged_in():

        return redirect(url_for("login"))

    if request.method == "POST":

        sender = request.form.get(
            "sender",
            ""
        ).strip()

        subject = request.form.get(
            "subject",
            ""
        ).strip()

        body = request.form.get(
            "body",
            ""
        ).strip()

        links = request.form.get(
            "links",
            ""
        ).strip()

        combined = f"""
        Sender: {sender}
        Subject: {subject}
        Email Body: {body}
        Links: {links}
        """

        analysis = analyze_email(combined)

        save_scan(
            combined,
            analysis
        )

        return render_template(
            "result.html",
            result=analysis["result"],
            risk=analysis["risk"],
            score=analysis["score"],
            message=analysis["message"],
            detected=analysis["detected"]
        )

    return render_template_string(
        ADVANCED_SCAN_HTML
    )


# =========================================================
# HISTORY
# =========================================================

# =========================================================
# HISTORY WITH PAGINATION
# =========================================================

@app.route("/history")
def history():

    if not logged_in():
        return redirect(url_for("login"))

    # Records per page
    per_page = 10

    # Current page
    page = request.args.get(
        "page",
        1,
        type=int
    )

    if page < 1:
        page = 1

    user_id = session["user_id"]

    conn = get_db()

    # -----------------------------------------------------
    # TOTAL RECORDS
    # -----------------------------------------------------

    total_records = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
    """, (
        user_id,
    )).fetchone()["count"]

    # -----------------------------------------------------
    # TOTAL PAGES
    # -----------------------------------------------------

    total_pages = (
        (total_records + per_page - 1)
        // per_page
    )

    # -----------------------------------------------------
    # FIX INVALID PAGE
    # -----------------------------------------------------

    if total_pages > 0 and page > total_pages:
        page = total_pages

    # -----------------------------------------------------
    # OFFSET
    # -----------------------------------------------------

    offset = (page - 1) * per_page

    # -----------------------------------------------------
    # GET CURRENT PAGE RECORDS
    # -----------------------------------------------------

    records = conn.execute("""
        SELECT *
        FROM history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, (
        user_id,
        per_page,
        offset
    )).fetchall()

    conn.close()

    return render_template(
        "history.html",
        records=records,
        page=page,
        total_pages=total_pages,
        total_records=total_records
    )


# =========================================================
# ANALYTICS
# =========================================================

@app.route("/analytics")
def analytics():

    if not logged_in():

        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = get_db()

    total = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
    """, (user_id,)).fetchone()["count"]

    high = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'HIGH'
    """, (user_id,)).fetchone()["count"]

    medium = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'MEDIUM'
    """, (user_id,)).fetchone()["count"]

    low = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
        AND risk = 'LOW'
    """, (user_id,)).fetchone()["count"]

    average = conn.execute("""
        SELECT AVG(score) AS average
        FROM history
        WHERE user_id = ?
    """, (user_id,)).fetchone()["average"]

    average_score = round(
        average or 0
    )

    conn.close()

    return render_template_string(
        ANALYTICS_HTML,
        total=total,
        high=high,
        medium=medium,
        low=low,
        average_score=average_score
    )


# =========================================================
# REPORT SUSPICIOUS EMAIL
# =========================================================

@app.route(
    "/report-email",
    methods=["GET", "POST"]
)
def report_email():

    if not logged_in():

        return redirect(url_for("login"))

    message = None

    if request.method == "POST":

        sender = request.form.get(
            "sender",
            ""
        ).strip()

        subject = request.form.get(
            "subject",
            ""
        ).strip()

        reason = request.form.get(
            "reason",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not reason:

            message = "Please select a reason."

        else:

            conn = get_db()

            conn.execute("""
                INSERT INTO reports
                (
                    user_id,
                    sender,
                    subject,
                    reason,
                    description
                )
                VALUES (?, ?, ?, ?, ?)
            """, (

                session["user_id"],
                sender,
                subject,
                reason,
                description

            ))

            conn.commit()

            conn.close()

            message = (
                "Suspicious email report submitted successfully."
            )

    return render_template_string(
        REPORT_HTML,
        message=message
    )


# =========================================================
# ALERTS
# =========================================================

@app.route("/alerts")
def alerts():

    if not logged_in():

        return redirect(url_for("login"))

    conn = get_db()

    high_scans = conn.execute("""
        SELECT *
        FROM history
        WHERE user_id = ?
        AND risk = 'HIGH'
        ORDER BY created_at DESC
        LIMIT 10
    """, (
        session["user_id"],
    )).fetchall()

    reports = conn.execute("""
        SELECT *
        FROM reports
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template_string(
        ALERTS_HTML,
        high_scans=high_scans,
        reports=reports
    )


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
def profile():

    if not logged_in():

        return redirect(url_for("login"))

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    total = conn.execute("""
        SELECT COUNT(*) AS count
        FROM history
        WHERE user_id = ?
    """, (
        session["user_id"],
    )).fetchone()["count"]

    conn.close()

    return render_template_string(
        PROFILE_HTML,
        user=user,
        total=total
    )


# =========================================================
# SETTINGS
# =========================================================

@app.route(
    "/settings",
    methods=["GET", "POST"]
)
def settings():

    if not logged_in():

        return redirect(url_for("login"))

    message = None

    error = None

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
        """, (
            session["user_id"],
        )).fetchone()

        if not check_password_hash(
            user["password"],
            current_password
        ):

            error = "Current password is incorrect."

        elif len(new_password) < 6:

            error = (
                "New password must contain at least 6 characters."
            )

        elif new_password != confirm_password:

            error = "Passwords do not match."

        else:

            hashed = generate_password_hash(
                new_password
            )

            conn.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (
                hashed,
                session["user_id"]
            ))

            conn.commit()

            message = (
                "Password changed successfully."
            )

        conn.close()

    return render_template_string(
        SETTINGS_HTML,
        message=message,
        error=error
    )


# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route(
    "/clear-history",
    methods=["POST"]
)
def clear_history():

    if not logged_in():

        return redirect(url_for("login"))

    conn = get_db()

    conn.execute("""
        DELETE FROM history
        WHERE user_id = ?
    """, (
        session["user_id"],
    ))

    conn.commit()

    conn.close()

    return redirect(
        url_for("settings")
    )


# =========================================================
# SECURITY TIPS
# =========================================================

@app.route("/security-tips")
def security_tips():

    if not logged_in():

        return redirect(url_for("login"))

    return render_template_string(
        SECURITY_TIPS_HTML
    )


# =========================================================
# SECURITY GUIDE
# =========================================================

@app.route("/security-guide")
def security_guide():

    if not logged_in():

        return redirect(url_for("login"))

    return render_template_string(
        SECURITY_GUIDE_HTML
    )


# =========================================================
# HELP / FAQ
# =========================================================

@app.route("/help")
def help_page():

    if not logged_in():

        return redirect(url_for("login"))

    return render_template_string(
        HELP_HTML
    )


# =========================================================
# DASHBOARD HTML
# =========================================================

DASHBOARD_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>AI Fake Email Detector</title>

<style>

* {
    box-sizing: border-box;
    font-family: Arial, sans-serif;
}

body {
    margin: 0;
    background: #f4f7fb;
    color: #172033;
}

.sidebar {
    position: fixed;
    left: 0;
    top: 0;
    width: 250px;
    height: 100vh;
    background: #101828;
    color: white;
    padding: 25px 15px;
    overflow-y: auto;
}

.logo {
    text-align: center;
    font-size: 20px;
    font-weight: bold;
    margin-bottom: 30px;
}

.logo span {
    color: #4f9cff;
}

.menu-title {
    color: #8b98aa;
    font-size: 11px;
    margin: 20px 12px 8px;
    text-transform: uppercase;
}

.nav-item {
    display: block;
    padding: 11px 13px;
    margin: 4px 0;
    border-radius: 8px;
    color: #d7deea;
    text-decoration: none;
}

.nav-item:hover {
    background: #2563eb;
    color: white;
}

.logout {
    margin-top: 15px;
    background: #1d2939;
}

.main {
    margin-left: 250px;
    padding: 30px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 25px;
}

.welcome h1 {
    margin-bottom: 5px;
}

.welcome p {
    color: #667085;
}

.profile {
    background: white;
    padding: 10px 16px;
    border-radius: 25px;
}

.check-button {
    display: inline-block;
    background: #2563eb;
    color: white;
    text-decoration: none;
    padding: 13px 20px;
    border-radius: 8px;
    font-weight: bold;
    margin-bottom: 25px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(4,1fr);
    gap: 16px;
    margin-bottom: 25px;
}

.card,
.section {
    background: white;
    padding: 20px;
    border-radius: 14px;
    box-shadow: 0 3px 15px rgba(0,0,0,.05);
}

.card-title {
    color: #667085;
    font-size: 13px;
}

.number {
    font-size: 28px;
    font-weight: bold;
    margin-top: 10px;
}

.blue { color: #2563eb; }
.red { color: #dc2626; }
.orange { color: #ea580c; }
.green { color: #16a34a; }

.content-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    padding: 12px 8px;
    text-align: left;
    border-bottom: 1px solid #eaecf0;
}

th {
    color: #667085;
    font-size: 13px;
}

.badge {
    padding: 5px 8px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: bold;
}

.high {
    color: #b91c1c;
    background: #fee2e2;
}

.medium {
    color: #c2410c;
    background: #ffedd5;
}

.low {
    color: #15803d;
    background: #dcfce7;
}

.link {
    color: #2563eb;
    text-decoration: none;
    font-weight: bold;
}

@media(max-width:1000px) {

    .stats {
        grid-template-columns: repeat(2,1fr);
    }

    .content-grid {
        grid-template-columns: 1fr;
    }

}

@media(max-width:700px) {

    .sidebar {
        width: 70px;
    }

    .logo {
        font-size: 0;
    }

    .logo span {
        font-size: 22px;
    }

    .nav-item {
        font-size: 0;
        text-align: center;
    }

    .menu-title {
        display: none;
    }

    .main {
        margin-left: 70px;
        padding: 18px;
    }

}

</style>

</head>

<body>


<div class="sidebar">

<div class="logo">
🛡️ AI <span>Detector</span>
</div>


<div class="menu-title">
MAIN
</div>

<a class="nav-item"
href="{{ url_for('home') }}">
🏠 Dashboard
</a>

<a class="nav-item"
href="{{ url_for('check_email') }}">
📧 Check Email
</a>

<a class="nav-item"
href="{{ url_for('advanced_scan') }}">
🔍 Advanced Scan
</a>

<a class="nav-item"
href="{{ url_for('analytics') }}">
📊 Analytics
</a>

<a class="nav-item"
href="{{ url_for('history') }}">
🕒 Scan History
</a>


<div class="menu-title">
SECURITY
</div>

<a class="nav-item"
href="{{ url_for('alerts') }}">
🚨 Alerts
</a>

<a class="nav-item"
href="{{ url_for('report_email') }}">
📝 Report Email
</a>

<a class="nav-item"
href="{{ url_for('security_tips') }}">
🛡️ Security Tips
</a>

<a class="nav-item"
href="{{ url_for('security_guide') }}">
📚 Security Guide
</a>


<div class="menu-title">
ACCOUNT
</div>

<a class="nav-item"
href="{{ url_for('profile') }}">
👤 Profile
</a>

<a class="nav-item"
href="{{ url_for('settings') }}">
⚙️ Settings
</a>

<a class="nav-item"
href="{{ url_for('help_page') }}">
❓ Help & FAQ
</a>

<a class="nav-item logout"
href="{{ url_for('logout') }}">
🚪 Logout
</a>

</div>


<div class="main">


<div class="topbar">

<div class="welcome">

<h1>
Welcome, {{ name }} 👋
</h1>

<p>
AI-powered email security dashboard
</p>

</div>

<div class="profile">
👤 {{ name }}
</div>

</div>


<a class="check-button"
href="{{ url_for('check_email') }}">
📧 Analyze New Email →
</a>


<div class="stats">

<div class="card">
<div class="card-title">
Total Scans
</div>

<div class="number blue">
{{ total }}
</div>
</div>


<div class="card">
<div class="card-title">
High Risk
</div>

<div class="number red">
{{ high }}
</div>
</div>


<div class="card">
<div class="card-title">
Medium Risk
</div>

<div class="number orange">
{{ medium }}
</div>
</div>


<div class="card">
<div class="card-title">
Low Risk
</div>

<div class="number green">
{{ low }}
</div>
</div>

</div>


<div class="content-grid">


<div class="section">

<h2>
🕒 Recent Scans
</h2>

{% if recent_scans %}

<table>

<tr>
<th>Result</th>
<th>Risk</th>
<th>Score</th>
<th>Date</th>
</tr>

{% for scan in recent_scans %}

<tr>

<td>
{{ scan["result"] }}
</td>

<td>

{% if scan["risk"] == "HIGH" %}

<span class="badge high">
HIGH
</span>

{% elif scan["risk"] == "MEDIUM" %}

<span class="badge medium">
MEDIUM
</span>

{% else %}

<span class="badge low">
LOW
</span>

{% endif %}

</td>

<td>
{{ scan["score"] }}%
</td>

<td>
{{ scan["created_at"] }}
</td>

</tr>

{% endfor %}

</table>

{% else %}

<p>
No scans yet.
</p>

{% endif %}

<br>

<a class="link"
href="{{ url_for('history') }}">
View Complete History →
</a>

</div>


<div class="section">

<h2>
🛡️ Security
</h2>

<div style="text-align:center;">

<div style="font-size:50px;">
🔐
</div>

<h3>
Average Risk Score
</h3>

<div class="number blue">
{{ average_score }}%
</div>

<p style="color:#667085;">
Stay alert when emails request
passwords, OTPs or payments.
</p>

<a class="link"
href="{{ url_for('security_tips') }}">
Security Tips →
</a>

</div>

</div>


</div>

</div>

</body>

</html>
"""


# =========================================================
# ADVANCED SCAN HTML
# =========================================================

ADVANCED_SCAN_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Advanced Email Scan</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
    color:#172033;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:850px;
    margin:35px auto;
    padding:20px;
}

.card {
    background:white;
    padding:30px;
    border-radius:16px;
    box-shadow:0 4px 18px rgba(0,0,0,.06);
}

label {
    display:block;
    margin-top:18px;
    margin-bottom:7px;
    font-weight:bold;
}

input,
textarea {
    width:100%;
    padding:13px;
    border:1px solid #d0d5dd;
    border-radius:8px;
    box-sizing:border-box;
}

textarea {
    min-height:180px;
    resize:vertical;
}

button {
    margin-top:22px;
    padding:14px 25px;
    background:#2563eb;
    color:white;
    border:0;
    border-radius:8px;
    font-weight:bold;
    cursor:pointer;
}

.back {
    display:inline-block;
    margin-top:20px;
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
🛡️ AI Fake Email Detector
</div>

<div class="container">

<div class="card">

<h1>
🔍 Advanced Email Scan
</h1>

<p>
Provide additional email information for a more detailed analysis.
</p>


<form method="POST">

<label>
Sender Email
</label>

<input
type="email"
name="sender"
placeholder="example@email.com"
>


<label>
Email Subject
</label>

<input
type="text"
name="subject"
placeholder="Enter email subject"
>


<label>
Email Body
</label>

<textarea
name="body"
placeholder="Paste the complete email message here..."
required
></textarea>


<label>
Links Found In Email
</label>

<textarea
name="links"
placeholder="Paste suspicious links here, if any"
></textarea>


<button type="submit">
🔍 Analyze Email
</button>

</form>


<a class="back"
href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</div>

</body>

</html>
"""


# =========================================================
# ANALYTICS HTML
# =========================================================

ANALYTICS_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Analytics</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
    color:#172033;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:1000px;
    margin:35px auto;
    padding:20px;
}

.grid {
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:18px;
}

.card {
    background:white;
    padding:22px;
    border-radius:14px;
    text-align:center;
    box-shadow:0 3px 15px rgba(0,0,0,.05);
}

.number {
    font-size:30px;
    font-weight:bold;
    margin-top:10px;
}

.chart {
    margin-top:25px;
    background:white;
    padding:30px;
    border-radius:14px;
}

.bar {
    margin:18px 0;
}

.bar-label {
    margin-bottom:6px;
}

.track {
    height:25px;
    background:#eaecf0;
    border-radius:20px;
    overflow:hidden;
}

.fill {
    height:100%;
    border-radius:20px;
}

.high-fill {
    background:#dc2626;
}

.medium-fill {
    background:#f97316;
}

.low-fill {
    background:#16a34a;
}

.back {
    display:inline-block;
    margin-top:25px;
    color:#2563eb;
    text-decoration:none;
}

@media(max-width:700px) {
    .grid {
        grid-template-columns:repeat(2,1fr);
    }
}

</style>

</head>

<body>

<div class="header">
📊 AI Fake Email Detector — Analytics
</div>

<div class="container">

<h1>
Detection Analytics
</h1>

<p>
Overview of your email security activity.
</p>


<div class="grid">

<div class="card">
Total Scans
<div class="number">
{{ total }}
</div>
</div>

<div class="card">
High Risk
<div class="number" style="color:#dc2626;">
{{ high }}
</div>
</div>

<div class="card">
Medium Risk
<div class="number" style="color:#f97316;">
{{ medium }}
</div>
</div>

<div class="card">
Low Risk
<div class="number" style="color:#16a34a;">
{{ low }}
</div>
</div>

</div>


<div class="chart">

<h2>
Risk Distribution
</h2>


{% if total > 0 %}

<div class="bar">

<div class="bar-label">
High Risk — {{ high }}
</div>

<div class="track">

<div class="fill high-fill"
style="width: {{ (high / total * 100)|round }}%;">
</div>

</div>

</div>


<div class="bar">

<div class="bar-label">
Medium Risk — {{ medium }}
</div>

<div class="track">

<div class="fill medium-fill"
style="width: {{ (medium / total * 100)|round }}%;">
</div>

</div>

</div>


<div class="bar">

<div class="bar-label">
Low Risk — {{ low }}
</div>

<div class="track">

<div class="fill low-fill"
style="width: {{ (low / total * 100)|round }}%;">
</div>

</div>

</div>

{% else %}

<p>
No scan data available yet.
</p>

{% endif %}


<h3>
Average Risk Score:
{{ average_score }}%
</h3>

</div>


<a class="back"
href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# REPORT HTML
# =========================================================

REPORT_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Report Email</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:750px;
    margin:35px auto;
    padding:20px;
}

.card {
    background:white;
    padding:30px;
    border-radius:15px;
    box-shadow:0 4px 18px rgba(0,0,0,.06);
}

label {
    display:block;
    margin-top:16px;
    margin-bottom:7px;
    font-weight:bold;
}

input,
select,
textarea {
    width:100%;
    padding:12px;
    box-sizing:border-box;
    border:1px solid #d0d5dd;
    border-radius:8px;
}

textarea {
    min-height:130px;
}

button {
    margin-top:20px;
    padding:13px 22px;
    background:#dc2626;
    color:white;
    border:0;
    border-radius:8px;
    font-weight:bold;
}

.success {
    background:#dcfce7;
    color:#15803d;
    padding:12px;
    border-radius:8px;
}

.back {
    display:inline-block;
    margin-top:20px;
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
📝 Report Suspicious Email
</div>

<div class="container">

<div class="card">

<h1>
Report an Email
</h1>

<p>
Use this form to record an email that you believe may be suspicious.
</p>

{% if message %}

<div class="success">
{{ message }}
</div>

{% endif %}


<form method="POST">

<label>
Sender Email
</label>

<input
type="text"
name="sender"
placeholder="sender@example.com"
>


<label>
Subject
</label>

<input
type="text"
name="subject"
placeholder="Email subject"
>


<label>
Reason
</label>

<select name="reason" required>

<option value="">
Select a reason
</option>

<option>
Phishing
</option>

<option>
Suspicious Link
</option>

<option>
OTP Request
</option>

<option>
Password Request
</option>

<option>
Payment Scam
</option>

<option>
Fake Prize / Reward
</option>

<option>
Unknown Sender
</option>

<option>
Other
</option>

</select>


<label>
Description
</label>

<textarea
name="description"
placeholder="Describe why you think this email is suspicious..."
></textarea>


<button type="submit">
Submit Report
</button>

</form>


<a class="back"
href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</div>

</body>

</html>
"""


# =========================================================
# ALERTS HTML
# =========================================================

ALERTS_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Alerts</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
    color:#172033;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:900px;
    margin:35px auto;
    padding:20px;
}

.alert {
    background:white;
    border-left:5px solid #dc2626;
    padding:20px;
    margin:15px 0;
    border-radius:10px;
    box-shadow:0 3px 12px rgba(0,0,0,.05);
}

.report {
    background:white;
    border-left:5px solid #2563eb;
    padding:20px;
    margin:15px 0;
    border-radius:10px;
}

.back {
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
🚨 Security Alerts
</div>

<div class="container">

<h1>
Security Alerts
</h1>

<p>
Recent high-risk detections from your account.
</p>


{% if high_scans %}

{% for scan in high_scans %}

<div class="alert">

<strong>
🚨 High Risk Email Detected
</strong>

<p>
{{ scan["result"] }}
</p>

<p>
Risk Score:
<strong>
{{ scan["score"] }}%
</strong>
</p>

<p>
Detected:
{{ scan["reasons"] }}
</p>

<small>
{{ scan["created_at"] }}
</small>

</div>

{% endfor %}

{% else %}

<div class="alert">
No high-risk alerts found.
</div>

{% endif %}


<h2>
📝 Your Reports
</h2>


{% if reports %}

{% for report in reports %}

<div class="report">

<strong>
{{ report["reason"] }}
</strong>

<p>
{{ report["description"] }}
</p>

<small>
{{ report["created_at"] }}
</small>

</div>

{% endfor %}

{% else %}

<p>
You have not submitted any reports.
</p>

{% endif %}


<a class="back"
href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# PROFILE HTML
# =========================================================

PROFILE_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Profile</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:800px;
    margin:40px auto;
    padding:20px;
}

.card {
    background:white;
    padding:30px;
    border-radius:16px;
    box-shadow:0 4px 18px rgba(0,0,0,.05);
}

.avatar {
    width:85px;
    height:85px;
    border-radius:50%;
    background:#2563eb;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    font-size:35px;
}

.info {
    background:#f8fafc;
    padding:15px;
    margin-top:12px;
    border-radius:8px;
}

.info strong {
    display:block;
    color:#667085;
    font-size:12px;
    margin-bottom:5px;
}

.button {
    display:inline-block;
    margin-top:20px;
    background:#2563eb;
    color:white;
    padding:12px 18px;
    text-decoration:none;
    border-radius:8px;
}

</style>

</head>

<body>

<div class="header">
👤 Profile
</div>

<div class="container">

<div class="card">

<div class="avatar">
👤
</div>

<h1>
{{ user["name"] }}
</h1>

<p>
AI Fake Email Detector account
</p>


<div class="info">

<strong>
NAME
</strong>

{{ user["name"] }}

</div>


<div class="info">

<strong>
EMAIL
</strong>

{{ user["email"] }}

</div>


<div class="info">

<strong>
ACCOUNT ID
</strong>

#{{ user["id"] }}

</div>


<div class="info">

<strong>
TOTAL EMAIL SCANS
</strong>

{{ total }}

</div>


<a class="button"
href="{{ url_for('home') }}">
← Dashboard
</a>

</div>

</div>

</body>

</html>
"""


# =========================================================
# SETTINGS HTML
# =========================================================

SETTINGS_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Settings</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:750px;
    margin:35px auto;
    padding:20px;
}

.card {
    background:white;
    padding:28px;
    border-radius:15px;
    margin-bottom:20px;
    box-shadow:0 4px 15px rgba(0,0,0,.05);
}

label {
    display:block;
    margin-top:15px;
    margin-bottom:6px;
    font-weight:bold;
}

input {
    width:100%;
    padding:12px;
    box-sizing:border-box;
    border:1px solid #d0d5dd;
    border-radius:8px;
}

button {
    margin-top:18px;
    padding:12px 20px;
    border:0;
    border-radius:8px;
    background:#2563eb;
    color:white;
    font-weight:bold;
}

.danger {
    background:#dc2626;
}

.success {
    background:#dcfce7;
    color:#15803d;
    padding:12px;
    border-radius:8px;
}

.error {
    background:#fee2e2;
    color:#b91c1c;
    padding:12px;
    border-radius:8px;
}

a {
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
⚙️ Settings
</div>

<div class="container">


<div class="card">

<h1>
Account Settings
</h1>

<p>
Manage your account security and data.
</p>

</div>


<div class="card">

<h2>
🔐 Change Password
</h2>

{% if message %}

<div class="success">
{{ message }}
</div>

{% endif %}

{% if error %}

<div class="error">
{{ error }}
</div>

{% endif %}


<form method="POST">

<label>
Current Password
</label>

<input
type="password"
name="current_password"
required
>


<label>
New Password
</label>

<input
type="password"
name="new_password"
minlength="6"
required
>


<label>
Confirm Password
</label>

<input
type="password"
name="confirm_password"
minlength="6"
required
>


<button>
Change Password
</button>

</form>

</div>


<div class="card">

<h2>
🗑️ Delete Scan History
</h2>

<p>
Delete all email scans from your account.
</p>

<form
method="POST"
action="{{ url_for('clear_history') }}"
onsubmit="return confirm('Delete all scan history?');">

<button class="danger">
Delete All History
</button>

</form>

</div>


<a href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# SECURITY TIPS HTML
# =========================================================

SECURITY_TIPS_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Security Tips</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:950px;
    margin:35px auto;
    padding:20px;
}

.hero {
    background:#2563eb;
    color:white;
    padding:30px;
    border-radius:15px;
}

.grid {
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:18px;
    margin-top:20px;
}

.card {
    background:white;
    padding:25px;
    border-radius:14px;
    box-shadow:0 3px 12px rgba(0,0,0,.05);
}

.icon {
    font-size:35px;
}

p {
    color:#667085;
    line-height:1.6;
}

a {
    color:#2563eb;
    text-decoration:none;
}

@media(max-width:700px) {
    .grid {
        grid-template-columns:1fr;
    }
}

</style>

</head>

<body>

<div class="header">
🛡️ Security Tips
</div>

<div class="container">

<div class="hero">

<h1>
Stay Safe From Phishing
</h1>

<p style="color:white;">
Simple security practices can help protect
your accounts and personal information.
</p>

</div>


<div class="grid">

<div class="card">
<div class="icon">🔗</div>
<h2>Check Links</h2>
<p>
Don't click unexpected links.
Check the domain before entering information.
</p>
</div>


<div class="card">
<div class="icon">🔐</div>
<h2>Protect Passwords</h2>
<p>
Never send passwords through email or messages.
</p>
</div>


<div class="card">
<div class="icon">🔢</div>
<h2>Never Share OTP</h2>
<p>
Keep one-time passwords private.
</p>
</div>


<div class="card">
<div class="icon">💳</div>
<h2>Verify Payments</h2>
<p>
Be careful with unexpected payment requests.
</p>
</div>

</div>

<br>

<a href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# SECURITY GUIDE HTML
# =========================================================

SECURITY_GUIDE_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Security Guide</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
    color:#172033;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:850px;
    margin:35px auto;
    padding:20px;
}

.card {
    background:white;
    padding:25px;
    border-radius:14px;
    margin-bottom:18px;
    box-shadow:0 3px 12px rgba(0,0,0,.05);
}

p {
    color:#667085;
    line-height:1.7;
}

a {
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
📚 Email Security Guide
</div>

<div class="container">

<h1>
Email Security Guide
</h1>


<div class="card">

<h2>
🎣 What is Phishing?
</h2>

<p>
Phishing is a type of social engineering attack
where an attacker attempts to trick someone into
revealing information or performing an unsafe action.
</p>

</div>


<div class="card">

<h2>
🌐 Suspicious Links
</h2>

<p>
Attackers may use misleading or unusual links.
Always inspect the destination before opening
a link or entering credentials.
</p>

</div>


<div class="card">

<h2>
🔐 Credential Theft
</h2>

<p>
Unexpected requests for passwords, OTPs or
authentication information should be treated
with caution.
</p>

</div>


<div class="card">

<h2>
💰 Payment Scams
</h2>

<p>
Unexpected requests for money, gift cards,
bank transfers or payment details can be warning
signs of fraud.
</p>

</div>


<a href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# HELP / FAQ HTML
# =========================================================

HELP_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Help & FAQ</title>

<style>

body {
    margin:0;
    background:#f4f7fb;
    font-family:Arial;
}

.header {
    background:#101828;
    color:white;
    padding:20px 35px;
}

.container {
    max-width:850px;
    margin:35px auto;
    padding:20px;
}

.card {
    background:white;
    padding:25px;
    border-radius:14px;
    margin-bottom:15px;
    box-shadow:0 3px 12px rgba(0,0,0,.05);
}

.answer {
    color:#667085;
    line-height:1.7;
}

a {
    color:#2563eb;
    text-decoration:none;
}

</style>

</head>

<body>

<div class="header">
❓ Help & FAQ
</div>

<div class="container">

<h1>
Frequently Asked Questions
</h1>


<div class="card">

<h2>
What does the detector do?
</h2>

<div class="answer">
The system analyzes an email for patterns associated
with suspicious or potentially phishing messages.
</div>

</div>


<div class="card">

<h2>
What does the risk score mean?
</h2>

<div class="answer">
The score represents how many suspicious indicators
were detected by the current analysis rules.
</div>

</div>


<div class="card">

<h2>
Is a LOW risk result a guarantee?
</h2>

<div class="answer">
No. The detector is a security aid and cannot guarantee
that an email is completely safe.
</div>

</div>


<div class="card">

<h2>
Where can I see previous scans?
</h2>

<div class="answer">
Open Scan History from the dashboard sidebar.
</div>

</div>


<div class="card">

<h2>
What is Advanced Scan?
</h2>

<div class="answer">
Advanced Scan lets you provide the sender,
subject, body and links separately for analysis.
</div>

</div>


<a href="{{ url_for('home') }}">
← Back to Dashboard
</a>

</div>

</body>

</html>
"""


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )