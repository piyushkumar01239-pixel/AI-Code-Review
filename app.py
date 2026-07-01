from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
import os

ALLOWED_EXTENSIONS = {'py', 'js', 'php', 'java', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///codeguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ── Models ──────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    language = db.Column(db.String(50), nullable=False)
    code_snippet = db.Column(db.Text, nullable=False)
    security_score = db.Column(db.Integer, default=100)
    ai_summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    line_number = db.Column(db.Integer, nullable=True)
    fix_suggestion = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Routes ──────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Account created! Welcome.', 'success')
            return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id)\
                      .order_by(Scan.created_at.desc()).limit(5).all()
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_findings = db.session.query(Finding)\
        .join(Scan).filter(Scan.user_id == current_user.id).count()
    critical_count = db.session.query(Finding)\
        .join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'critical').count()
    return render_template('dashboard.html',
                           scans=scans,
                           total_scans=total_scans,
                           total_findings=total_findings,
                           critical_count=critical_count)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        language = request.form.get('language', 'python')
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join('uploads', filename)
                file.save(filepath)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                ext = filename.rsplit('.', 1)[1].lower()
                language = {
                    'py': 'python',
                    'js': 'javascript',
                    'php': 'php',
                    'java': 'java'
                }.get(ext, 'other')
        if not code:
            flash('Please paste code or upload a file.', 'error')
            return render_template('scan.html')
        from scanner.analyzer import scan_code, calculate_score, get_ai_summary
        findings_data = scan_code(code)
        score = calculate_score(findings_data)
        ai_summary = get_ai_summary(code, findings_data, language)
        new_scan = Scan(user_id=current_user.id,
                language=language,
                code_snippet=code,
                security_score=score,
                ai_summary=ai_summary)
        db.session.add(new_scan)
        db.session.commit()
        for f in findings_data:
            finding = Finding(
                scan_id=new_scan.id,
                severity=f['severity'],
                title=f['title'],
                description=f['description'],
                line_number=f.get('line_number'),
                fix_suggestion=f['fix'],
            )
            db.session.add(finding)
        db.session.commit()
        return redirect(url_for('result', scan_id=new_scan.id))
    return render_template('scan.html')

@app.route('/result/<int:scan_id>')
@login_required
def result(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template('result.html', scan=scan)

@app.route('/history')
@login_required
def history():
    scans = Scan.query.filter_by(user_id=current_user.id)\
                      .order_by(Scan.created_at.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    user_message = data.get('message', '').strip()
    language = data.get('language', 'python')
    code = data.get('code', '')
    findings = data.get('findings', '')
    if not user_message:
        return jsonify({'reply': 'Please type a message.'})
    try:
        from groq import Groq
        client = Groq(api_key=os.getenv('GROQ_API_KEY'))
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=1000,
            messages=[
                {
                    'role': 'system',
                    'content': (
                        f"You are a security code review assistant. "
                        f"The user has scanned the following {language} code:\n\n"
                        f"```{language}\n{code}\n```\n\n"
                        f"Security findings:\n{findings}\n\n"
                        f"Help the user fix their code, explain vulnerabilities, "
                        f"or rewrite code securely. Be concise and friendly. "
                        f"When showing code, use code blocks."
                    )
                },
                {
                    'role': 'user',
                    'content': user_message
                }
            ]
        )
        reply = response.choices[0].message.content
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'reply': f'AI error: {str(e)}'})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_findings = db.session.query(Finding)\
        .join(Scan).filter(Scan.user_id == current_user.id).count()
    critical_count = db.session.query(Finding)\
        .join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'critical').count()
    recent_scans = Scan.query.filter_by(user_id=current_user.id)\
                        .order_by(Scan.created_at.desc()).limit(3).all()
    return render_template('profile.html',
                           total_scans=total_scans,
                           total_findings=total_findings,
                           critical_count=critical_count,
                           recent_scans=recent_scans)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)