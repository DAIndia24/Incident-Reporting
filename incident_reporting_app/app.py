import os
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ------------------------------------------------------------------------------
# App & Config
# ------------------------------------------------------------------------------
app = Flask(__name__)

# Strong secret key (override via environment in production)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# SQLite DB under instance/
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "incident_reporting.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Uploads
UPLOAD_DIR = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "pdf", "txt", "csv",
    "doc", "docx", "xls", "xlsx"
}

# Token serializer (used for password reset + download tokens)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

db = SQLAlchemy(app)

# Allowed statuses for filtering / display
STATUSES = ["New", "In Review", "Resolved"]

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, index=True, nullable=False)
    email = db.Column(db.String(255), unique=False)  # optional
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    incidents = db.relationship("Incident", backref="user", lazy=True)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_code = db.Column(db.String(16), unique=True, index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # null for anonymous
    department = db.Column(db.String(120))
    nature = db.Column(db.String(120))
    description = db.Column(db.Text)
    status = db.Column(db.String(32), default="New")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    attachments = db.relationship("Attachment", backref="incident", lazy=True, cascade="all, delete-orphan")


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=False)
    filename_original = db.Column(db.String(255), nullable=False)
    filename_stored = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100))
    size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def rand_code(n=8):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "warning")
            return redirect(url_for("admin_login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def sign_download_token(incident_id: int, attachment_id: int) -> str:
    payload = {"incident_id": incident_id, "attachment_id": attachment_id}
    return serializer.dumps(payload, salt="download")

def verify_download_token(token: str, max_age=3600) -> dict:
    try:
        return serializer.loads(token, salt="download", max_age=max_age)
    except (BadSignature, SignatureExpired):
        return {}

def parse_date_yyyy_mm_dd(s: str):
    """Parse 'YYYY-MM-DD' to a datetime at start of day; returns None if blank/invalid."""
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None

# ------------------------------------------------------------------------------
# DB Init / Seed
# ------------------------------------------------------------------------------
def ensure_db_and_seed():
    db.create_all()
    # seed an admin if none exists
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", email=None, is_admin=True)
        admin.set_password("adminpassword")
        db.session.add(admin)
        db.session.commit()

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------------------- Auth: Register/Login/Logout ---------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip() or None
        pw = request.form.get("password") or ""
        pwc = request.form.get("password_confirm") or ""
        if not username or not pw:
            flash("Username and password are required.", "danger")
            return render_template("register.html")
        if pw != pwc:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("register.html")
        u = User(username=username, email=email)
        u.set_password(pw)
        db.session.add(u)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(pw):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")
        session["user_id"] = user.id
        session["is_admin"] = bool(user.is_admin)
        flash("Logged in.", "success")
        if user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))

# ----------------------------- Admin Login ------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_admin or not user.check_password(pw):
            flash("Invalid admin credentials.", "danger")
            return render_template("admin_login.html")
        session["user_id"] = user.id
        session["is_admin"] = True
        flash("Welcome, admin.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")

# ------------------------------ Report Incident -------------------------------
@app.route("/report", methods=["GET", "POST"])
def report_incident():
    """
    Allows anonymous or logged-in users to submit a report.
    Supports multiple file uploads via input name="evidence" (multiple).
    """
    if request.method == "POST":
        department = (request.form.get("department") or "").strip()
        nature = (request.form.get("nature") or "").strip()
        description = (request.form.get("description") or "").strip()

        # Create ticket code
        ticket_code = rand_code(10)
        while Incident.query.filter_by(ticket_code=ticket_code).first():
            ticket_code = rand_code(10)

        uid = session.get("user_id")
        inc = Incident(
            ticket_code=ticket_code,
            user_id=uid,
            department=department or None,
            nature=nature or None,
            description=description or None,
            status="New",
        )
        db.session.add(inc)
        db.session.flush()  # get inc.id

        # Handle multiple files
        files = request.files.getlist("evidence")
        saved_count = 0
        for f in files:
            if not f or not getattr(f, "filename", ""):
                continue
            if not allowed_file(f.filename):
                flash(f"File type not allowed: {f.filename}", "warning")
                continue

            original = secure_filename(f.filename)
            # Randomize stored name to prevent guessing
            rand = secrets.token_hex(16)
            _, ext = os.path.splitext(original)
            stored = f"{rand}{ext.lower()}"
            stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored)

            f.save(stored_path)
            size = os.path.getsize(stored_path)
            mime = f.mimetype or "application/octet-stream"

            att = Attachment(
                incident_id=inc.id,
                filename_original=original,
                filename_stored=stored,
                mime_type=mime,
                size=size,
            )
            db.session.add(att)
            saved_count += 1

        db.session.commit()

        if saved_count:
            flash(f"Report submitted with {saved_count} attachment(s). Your ticket: {ticket_code}", "success")
        else:
            flash(f"Report submitted. Your ticket: {ticket_code}", "success")

        # Redirect to ticket page so anonymous users can bookmark it
        return redirect(url_for("ticket_view", ticket_code=ticket_code))

    return render_template("report.html")

# ------------------------------- Ticket View ----------------------------------
@app.route("/ticket/<ticket_code>")
def ticket_view(ticket_code):
    inc = Incident.query.filter_by(ticket_code=ticket_code).first()
    if not inc:
        abort(404)

    # Build signed download tokens for each attachment so anonymous viewers can download
    tokens = {}
    for att in inc.attachments:
        tokens[att.id] = sign_download_token(incident_id=inc.id, attachment_id=att.id)

    return render_template("ticket.html", incident=inc, download_tokens=tokens)

# ------------------------- Attachment Download (secured) ----------------------
@app.route("/attachment/<int:attachment_id>/download")
def download_attachment(attachment_id):
    """
    Admins may download directly if logged in.
    Non-admins require a valid signed token (?token=...).
    """
    att = Attachment.query.get_or_404(attachment_id)
    inc = att.incident

    # Admin path
    if session.get("user_id"):
        u = User.query.get(session["user_id"])
        if u and u.is_admin:
            return _send_attachment(att)

    # Non-admin: require token
    token = request.args.get("token", "")
    data = verify_download_token(token)
    if not data:
        abort(403)
    if data.get("attachment_id") != attachment_id or data.get("incident_id") != inc.id:
        abort(403)

    return _send_attachment(att)

def _send_attachment(att: Attachment):
    path = os.path.join(app.config["UPLOAD_FOLDER"], att.filename_stored)
    if not os.path.isfile(path):
        abort(404)
    # Use original filename for the download prompt
    return send_file(path, as_attachment=True, download_name=att.filename_original, mimetype=att.mime_type)

# ------------------------------ My Reports ------------------------------------
@app.route("/my-reports")
@login_required
def my_reports():
    incs = Incident.query.filter_by(user_id=session["user_id"]).order_by(Incident.created_at.desc()).all()
    return render_template("my_reports.html", incidents=incs)

# ------------------------------ Admin Dashboard -------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    """
    Admin dashboard with server-side filters:
      - department: exact match
      - status: exact match
      - date_from / date_to: inclusive range on created_at
    """
    # Read filters from query string
    department = (request.args.get("department") or "").strip()
    status = (request.args.get("status") or "").strip()
    date_from_str = (request.args.get("date_from") or "").strip()
    date_to_str = (request.args.get("date_to") or "").strip()

    # Build base query
    q = Incident.query

    if department:
        q = q.filter(Incident.department == department)

    if status:
        q = q.filter(Incident.status == status)

    start_dt = parse_date_yyyy_mm_dd(date_from_str)
    end_dt = parse_date_yyyy_mm_dd(date_to_str)

    # Normalize dates: inclusive [start, end_of_day]
    if start_dt:
        q = q.filter(Incident.created_at >= start_dt)
    if end_dt:
        end_of_day = end_dt + timedelta(days=1)  # next day 00:00 (exclusive upper bound)
        q = q.filter(Incident.created_at < end_of_day)

    incs = q.order_by(Incident.created_at.desc()).all()

    # Build department list for dropdown (distinct non-null)
    raw_depts = db.session.query(Incident.department).distinct().all()
    departments = sorted({d[0] for d in raw_depts if d and d[0]})

    return render_template(
        "admin_dashboard.html",
        incidents=incs,
        departments=departments,
        statuses=STATUSES,
        # echo current filters back to template
        selected_department=department,
        selected_status=status,
        date_from=date_from_str,
        date_to=date_to_str,
    )

# ------------------------ Forgot / Reset Password Flow ------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        user = None
        if identifier:
            user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and user.email:
            token = serializer.dumps({"uid": user.id}, salt="pwreset")
            # TODO: send email with this link; for now, flash it (dev only)
            reset_link = url_for("reset_password", token=token, _external=True)
            flash(f"A password reset link has been generated: {reset_link}", "info")
        else:
            flash("If an account exists, a reset link will be sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # token contains user id
    try:
        data = serializer.loads(token, salt="pwreset", max_age=3600)
    except SignatureExpired:
        flash("Reset link expired. Please request a new one.", "warning")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        abort(400)

    user = User.query.get_or_404(data.get("uid"))

    if request.method == "POST":
        pw = request.form.get("password") or ""
        pwc = request.form.get("password_confirm") or ""
        if not pw or pw != pwc:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token, username=user.username)
        user.set_password(pw)
        db.session.commit()
        flash("Your password has been reset. You may now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token, username=user.username)

# ------------------------------- Security Headers -----------------------------
@app.after_request
def set_headers(resp):
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # Basic CSP (adjust as you add CDNs/features)
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; font-src https://cdn.jsdelivr.net; connect-src 'self';"
    )
    return resp

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        ensure_db_and_seed()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
