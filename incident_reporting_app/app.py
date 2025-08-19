import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

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
    department = db.Column(db.String(120), nullable=False)
    nature = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(32), default='Pending', nullable=False)

    # Nullable for anonymous reports
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)


# -----------------------------------------------------------------------------
# Helpers / Decorators
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


def ensure_db_seed_admin():
    """Create tables and seed a default admin (one-time) if none exists."""
    db.create_all()
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', email=None, is_admin=True)
        admin.set_password('ChangeMe123!')
        db.session.add(admin)
        db.session.commit()
        print('[seed] Created default admin: username="admin" password="ChangeMe123!"')


# -----------------------------------------------------------------------------
# Password strength (basic server-side sanity to complement client checks)
# -----------------------------------------------------------------------------
def is_password_reasonable(pw: str, username: str = '') -> bool:
    """Very light sanity check; client-side does the rich guidance."""
    if not pw or len(pw) < 8:
        return False
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digit = any(c.isdigit() for c in pw)
    special = any(not c.isalnum() for c in pw)
    if sum([lower, upper, digit, special]) < 2:
        return False
    # avoid trivial username-in-password
    if username and username.lower() in pw.lower():
        return False
    return True


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Client-side already enforces:
      - strength meter (min score)
      - confirm password match
    We still validate server-side for security.
    """
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

        # Log them in
        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        flash('Registration successful. Welcome!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Regular user login (non-admin).
    Admins can also use this, but we have a separate /admin/login page too.
    """
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
        # If admin, nudge to dashboard; else to home
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
    """
    Admin-only login page (uses same user table, but enforces is_admin).
    """
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
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
    """
    Shows all incidents; admin can update status via POST.
    """
    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        status = request.form.get('status')
        if not incident_id or not status:
            flash('Invalid update request.', 'danger')
            return redirect(url_for('admin_dashboard'))
        incident = Incident.query.get(incident_id)
        if not incident:
            flash('Incident not found.', 'warning')
            return redirect(url_for('admin_dashboard'))
        incident.status = status
        db.session.commit()
        flash(f'Incident #{incident.id} updated to "{status}".', 'success')
        return redirect(url_for('admin_dashboard'))

    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    return render_template('admin_dashboard.html', incidents=incidents)


@app.route('/report', methods=['GET', 'POST'])
def report_incident():
    """
    Allow anonymous reports (no user_id) or associate with logged-in user.
    """
    if request.method == 'POST':
        department = (request.form.get('department') or '').strip()
        nature = (request.form.get('nature') or '').strip()
        description = (request.form.get('description') or '').strip()

        if not department or not nature:
            flash('Department and Nature are required.', 'danger')
            return render_template('report.html')

        inc = Incident(
            department=department,
            nature=nature,
            description=description or None,
            user_id=session.get('user_id')  # None if anonymous
        )
        db.session.add(inc)
        db.session.commit()
        flash('Incident submitted successfully.', 'success')
        # If admin is submitting, go back to dashboard; else home
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))

    return render_template('report.html')


@app.route('/my-reports')
@login_required
def my_reports():
    """
    Non-admin users can view their own submitted incidents.
    Admins should use the dashboard.
    """
    if session.get('is_admin'):
        flash('Admins can review all reports on the dashboard.', 'info')
        return redirect(url_for('admin_dashboard'))

    user_id = session['user_id']
    incidents = Incident.query.filter_by(user_id=user_id).order_by(Incident.timestamp.desc()).all()
    return render_template('my_reports.html', incidents=incidents)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Minimal placeholder to resolve BuildError.
    For security, we do not reveal whether an email/username exists.
    Extend later with email + token-based reset.
    """
    if request.method == 'POST':
        # You can accept either email or username. For now, just take email.
        email = (request.form.get('email') or '').strip()
        # TODO: Look up user & send reset link with a signed token.
        flash('If an account with that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        ensure_db_seed_admin()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
