import os
import random
import string
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# NEW: token signing for password reset
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# -----------------------------------------------------------------------------
# App / DB setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///incident_reporting.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Show reset link in flash when app.debug=True (dev convenience)
SHOW_RESET_LINK_IN_DEV = True

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    incidents = db.relationship('Incident', backref='user', lazy=True)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.Integer, primary_key=True)
    ticket_code = db.Column(db.String(32), nullable=True, index=True)
    department = db.Column(db.String(120), nullable=False)
    nature = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(32), default='Pending', nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

# -----------------------------------------------------------------------------
# Lightweight migration helpers (SQLite-friendly)
# -----------------------------------------------------------------------------
def column_exists_sqlite(table: str, column: str) -> bool:
    engine = db.engine
    if not engine.url.drivername.startswith("sqlite"):
        return True
    with engine.connect() as conn:
        res = conn.exec_driver_sql(f'PRAGMA table_info({table});').fetchall()
        cols = [r[1] for r in res]
        return column in cols

def add_ticket_column_if_missing():
    engine = db.engine  # updated: deprecated db.get_engine() -> db.engine
    if engine.url.drivername.startswith("sqlite") and not column_exists_sqlite('incidents', 'ticket_code'):
        with engine.connect() as conn:
            conn.exec_driver_sql('ALTER TABLE incidents ADD COLUMN ticket_code VARCHAR(32);')
        for inc in Incident.query.filter(Incident.ticket_code.is_(None)).all():
            inc.ticket_code = generate_unique_ticket()
        db.session.commit()

# -----------------------------------------------------------------------------
# Auth / decorators
# -----------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Administrator access required.', 'danger')
            return redirect(url_for('index'))
        return view(*args, **kwargs)
    return wrapped

# -----------------------------------------------------------------------------
# Seed admin (dev convenience)
# -----------------------------------------------------------------------------
def ensure_db_and_seed():
    db.create_all()
    add_ticket_column_if_missing()
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', email=None, is_admin=True)
        admin.set_password('ChangeMe123!')
        db.session.add(admin)
        db.session.commit()
        print('[seed] Created default admin: username="admin" password="ChangeMe123!"')

# -----------------------------------------------------------------------------
# Password sanity (server-side)
# -----------------------------------------------------------------------------
def is_password_reasonable(pw: str, username: str = '') -> bool:
    if not pw or len(pw) < 8:
        return False
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digit = any(c.isdigit() for c in pw)
    special = any(not c.isalnum() for c in pw)
    if sum([lower, upper, digit, special]) < 2:
        return False
    if username and username.lower() in pw.lower():
        return False
    return True

# -----------------------------------------------------------------------------
# Ticket generation & lookup
# -----------------------------------------------------------------------------
def generate_ticket_code(date: Optional[datetime] = None, suffix_len: int = 4) -> str:
    d = (date or datetime.utcnow()).strftime("%Y%m%d")
    hex_chars = "0123456789ABCDEF"
    suffix = ''.join(random.choices(hex_chars, k=suffix_len))
    return f"IR-{d}-{suffix}"

def generate_unique_ticket(max_attempts: int = 10) -> str:
    for _ in range(max_attempts):
        code = generate_ticket_code()
        if not Incident.query.filter_by(ticket_code=code).first():
            return code
    return generate_ticket_code(suffix_len=6)

def get_incident_by_ticket(ticket_code: str) -> Optional[Incident]:
    if not ticket_code:
        return None
    return Incident.query.filter_by(ticket_code=ticket_code).first()

# -----------------------------------------------------------------------------
# Password reset tokens (itsdangerous)
# -----------------------------------------------------------------------------
def get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')

def generate_reset_token(user: User) -> str:
    s = get_serializer()
    return s.dumps({'uid': user.id})

def verify_reset_token(token: str, max_age_seconds: int = 3600) -> Optional[User]:
    s = get_serializer()
    try:
        data = s.loads(token, max_age=max_age_seconds)
        uid = data.get('uid')
        if not uid:
            return None
        # updated: Model.query.get -> db.session.get
        return db.session.get(User, uid)
    except SignatureExpired:
        return None
    except BadSignature:
        return None

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        password_confirm = request.form.get('password_confirm') or ''

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        if password != password_confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if not is_password_reasonable(password, username=username):
            flash('Please choose a stronger password.', 'warning')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken. Choose another.', 'warning')
            return render_template('register.html')

        user = User(username=username, is_admin=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        flash('Registration successful. Welcome!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        flash('Logged in successfully.', 'success')
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '')
        user = User.query.filter_by(username=username, is_admin=True).first()
        if not user or not user.check_password(password):
            flash('Invalid admin credentials.', 'danger')
            return render_template('admin_login.html')

        session['user_id'] = user.id
        session['is_admin'] = True
        flash('Welcome, Admin.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        status = request.form.get('status')
        if not incident_id or not status:
            flash('Invalid update request.', 'danger')
            return redirect(url_for('admin_dashboard'))
        # updated: Incident.query.get -> db.session.get
        incident = db.session.get(Incident, int(incident_id)) if incident_id else None
        if not incident:
            flash('Incident not found.', 'warning')
            return redirect(url_for('admin_dashboard'))
        incident.status = status
        if not incident.ticket_code:
            incident.ticket_code = generate_unique_ticket()
        db.session.commit()
        flash(f'Incident #{incident.id} updated to "{status}".', 'success')
        return redirect(url_for('admin_dashboard'))

    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    return render_template('admin_dashboard.html', incidents=incidents)

@app.route('/report', methods=['GET', 'POST'])
def report_incident():
    if request.method == 'POST':
        department = (request.form.get('department') or '').strip()
        nature = (request.form.get('nature') or '').strip()
        description = (request.form.get('description') or '').strip()

        if not department or not nature:
            flash('Department and Nature are required.', 'danger')
            return render_template('report.html')

        ticket_code = generate_unique_ticket()
        inc = Incident(
            department=department,
            nature=nature,
            description=description or None,
            user_id=session.get('user_id'),
            ticket_code=ticket_code
        )
        db.session.add(inc)
        db.session.commit()

        flash(f'Incident submitted. Your ticket: {ticket_code}', 'success')
        return redirect(url_for('ticket_status', ticket_code=ticket_code))

    return render_template('report.html')

@app.route('/my-reports')
@login_required
def my_reports():
    if session.get('is_admin'):
        flash('Admins can review all reports on the dashboard.', 'info')
        return redirect(url_for('admin_dashboard'))

    user_id = session['user_id']
    incidents = Incident.query.filter_by(user_id=user_id).order_by(Incident.timestamp.desc()).all()
    return render_template('my_reports.html', incidents=incidents)

@app.route('/ticket/<ticket_code>')
def ticket_status(ticket_code):
    inc = get_incident_by_ticket(ticket_code)
    if not inc:
        flash('Ticket not found.', 'warning')
        return redirect(url_for('index'))
    return render_template('ticket.html', incident=inc)

@app.route('/ticket/<ticket_code>/pdf')
def ticket_pdf(ticket_code):
    inc = get_incident_by_ticket(ticket_code)
    if not inc:
        flash('Ticket not found.', 'warning')
        return redirect(url_for('index'))

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
        from io import BytesIO

        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        def draw_line(y): c.line(20*mm, y, (width-20*mm), y)

        y = height - 30*mm
        c.setFont("Helvetica-Bold", 16); c.drawString(20*mm, y, "Incident Report Ticket"); y -= 10*mm
        c.setFont("Helvetica", 11)

        fields = [
            ("Ticket", inc.ticket_code or ""),
            ("Internal ID", str(inc.id)),
            ("Department", inc.department),
            ("Nature", inc.nature),
            ("Status", inc.status),
            ("Submitted On (UTC)", inc.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            ("Submitted By", inc.user.username if inc.user else "Anonymous"),
        ]
        for label, value in fields:
            c.drawString(20*mm, y, f"{label}: {value}")
            y -= 8*mm

        draw_line(y); y -= 8*mm
        c.setFont("Helvetica-Bold", 12); c.drawString(20*mm, y, "Description"); y -= 8*mm
        c.setFont("Helvetica", 11)
        text = c.beginText(20*mm, y)
        desc = inc.description or "N/A"
        for line in desc.splitlines() or ["N/A"]:
            text.textLine(line[:120])
        c.drawText(text)

        c.showPage(); c.save()
        buf.seek(0)
        filename = f"{inc.ticket_code}.pdf" if inc.ticket_code else f"incident-{inc.id}.pdf"
        return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")

    except Exception as e:
        print("[ticket_pdf] PDF generation unavailable:", e)
        abort(501, description="PDF generation not available on this server.")

# -------------------------- Password Reset Flow ------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Accepts username OR email. Always responds generically.
    In dev, we show the reset link so you can click it directly.
    """
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        user = None
        if identifier:
            user = User.query.filter(
                (User.username == identifier) | (User.email == identifier)
            ).first()
        if user:
            token = generate_reset_token(user)
            reset_url = url_for('reset_password', token=token, _external=True)
            # TODO: send email with reset_url
            print(f"[dev] Password reset link for {user.username}: {reset_url}")
            if app.debug and SHOW_RESET_LINK_IN_DEV:
                flash(f'Dev reset link: {reset_url}', 'secondary')

        flash('If an account exists for that identifier, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """
    Accepts token via query string (?token=...). On POST, updates password.
    Token expires after 1 hour by default.
    """
    token = request.args.get('token', '', type=str)
    user = verify_reset_token(token)

    if not token or not user:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password') or ''
        password_confirm = request.form.get('password_confirm') or ''
        if password != password_confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token, username=user.username)

        if not is_password_reasonable(password, username=user.username):
            flash('Please choose a stronger password.', 'warning')
            return render_template('reset_password.html', token=token, username=user.username)

        user.set_password(password)
        db.session.commit()
        session.clear()  # ensure any sessions are invalidated
        flash('Your password has been reset. You may now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, username=user.username)

# -----------------------------------------------------------------------------
# Optional: harden some headers quickly
# -----------------------------------------------------------------------------
@app.after_request
def set_headers(resp):
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    return resp

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        ensure_db_and_seed()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
