from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Replace with a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), nullable=False)
    nature = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Pending') # e.g., Pending, In Progress, Resolved
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Create database tables
with app.app_context():
    db.create_all()

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('report_incident'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/report', methods=['GET', 'POST'])
def report_incident():
    if request.method == 'POST':
        department = request.form['department']
        nature = request.form['nature']
        description = request.form.get('description')

        new_incident = Incident(department=department, nature=nature, description=description)
        db.session.add(new_incident)
        db.session.commit()
        flash('Incident report submitted successfully!', 'success')
        return redirect(url_for('report_incident'))
    return render_template('report.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_user = User.query.filter_by(username=username, is_admin=True).first()

        if admin_user and admin_user.check_password(password):
            session['user_id'] = admin_user.id
            session['username'] = admin_user.username
            session['is_admin'] = True
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'is_admin' not in session or not session['is_admin']:
        flash('Unauthorized access. Please log in as an administrator.', 'danger')
        return redirect(url_for('admin_login'))

    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()

    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        new_status = request.form.get('status')
        incident = Incident.query.get(incident_id)
        if incident:
            incident.status = new_status
            db.session.commit()
            flash(f'Status for incident {incident_id} updated to {new_status}.', 'success')
        else:
            flash('Incident not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', incidents=incidents)

if __name__ == '__main__':
    # Create an admin user if not exists (for initial setup)
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword') # **Change this in production!**
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user 'admin' created with password 'adminpassword'")
    app.run(debug=True)