import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import json
from web3 import Web3
from eth_account import Account
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificate_verifier.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple in-memory blockchain (replace with Ethereum in production)
class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_certificates = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': str(datetime.now(timezone.utc)),
            'certificates': [],
            'previous_hash': '0'
        }
        self.chain.append(genesis_block)
    
    def add_certificate(self, certificate_data):
        self.pending_certificates.append(certificate_data)
        return len(self.chain)
    
    def mine_pending_certificates(self):
        if not self.pending_certificates:
            return False
        
        last_block = self.chain[-1]
        new_block = {
            'index': len(self.chain),
            'timestamp': str(datetime.now(timezone.utc)),
            'certificates': self.pending_certificates,
            'previous_hash': self.hash_block(last_block)
        }
        
        self.pending_certificates = []
        self.chain.append(new_block)
        return new_block
    
    @staticmethod
    def hash_block(block):
        return Web3.keccak(text=json.dumps(block, sort_keys=True)).hex()

# Initialize blockchain
blockchain = Blockchain()

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # super_admin, admin, user
    institution = db.Column(db.String(100))
    is_approved = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

class Certificate(db.Model):
    __tablename__ = 'certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.String(100), unique=True, nullable=False)
    recipient_name = db.Column(db.String(100), nullable=False)
    course_name = db.Column(db.String(200), nullable=False)
    issue_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    issuer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    block_index = db.Column(db.Integer, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f"<Certificate {self.certificate_id} for {self.recipient_name}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        institution = request.form.get('institution', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
            role=role,
            institution=institution,
            is_approved=(role == 'user')  # Auto-approve users, admins need approval
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.role in ['super_admin', 'admin'] and not user.is_approved:
                flash('Your account is pending approval from the super admin.')
                return redirect(url_for('login'))
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'super_admin':
        pending_admins = User.query.filter_by(role='admin', is_approved=False).all()
        return render_template('super_admin_dashboard.html', pending_admins=pending_admins)
    elif current_user.role == 'admin':
        certificates = Certificate.query.filter_by(issuer_id=current_user.id).all()
        return render_template('admin_dashboard.html', certificates=certificates)
    else:
        return redirect(url_for('index'))

@app.route('/approve_admin/<int:admin_id>')
@login_required
def approve_admin(admin_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('dashboard'))
    
    admin = User.query.get_or_404(admin_id)
    if admin.role != 'admin':
        return redirect(url_for('dashboard'))
    
    admin.is_approved = True
    db.session.commit()
    flash(f'Admin {admin.username} has been approved')
    return redirect(url_for('dashboard'))

@app.route('/issue_certificate', methods=['GET', 'POST'])
@login_required
def issue_certificate():
    if current_user.role not in ['super_admin', 'admin']:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        recipient_name = request.form.get('recipient_name')
        course_name = request.form.get('course_name')
        
        # Generate a unique certificate ID
        cert_id = f"CERT-{secrets.token_hex(8).upper()}"
        
        certificate = Certificate(
            certificate_id=cert_id,
            recipient_name=recipient_name,
            course_name=course_name,
            issuer_id=current_user.id,
            institution=current_user.institution,
            is_verified=True
        )
        
        # Add to blockchain
        cert_data = {
            'certificate_id': cert_id,
            'recipient_name': recipient_name,
            'course_name': course_name,
            'issuer': current_user.username,
            'institution': current_user.institution,
            'timestamp': str(datetime.utcnow())
        }
        
        block_index = blockchain.add_certificate(cert_data)
        certificate.block_index = block_index
        
        db.session.add(certificate)
        db.session.commit()
        
        flash(f'Certificate issued successfully! Certificate ID: {cert_id}')
        return redirect(url_for('dashboard'))
    
    return render_template('issue_certificate.html')

@app.route('/verify_certificate', methods=['GET', 'POST'])
def verify_certificate():
    if request.method == 'POST':
        certificate_id = request.form.get('certificate_id')
        if not certificate_id:
            flash('Please enter a certificate ID')
            return redirect(url_for('verify_certificate'))
            
        certificate = Certificate.query.filter_by(certificate_id=certificate_id.strip()).first()
        
        if certificate:
            # In a real implementation, you would verify against the blockchain
            is_valid = True
            # Update verification timestamp
            certificate.verification_date = datetime.now(timezone.utc)
            db.session.commit()
            
            return render_template('verification_result.html', 
                                 certificate=certificate, 
                                 is_valid=is_valid,
                                 now=datetime.now(timezone.utc))
        
        # If certificate not found, render the template with error message
        return render_template('verification_result.html', 
                             certificate=None, 
                             is_valid=False,
                             now=datetime.now(timezone.utc))
    
    # Handle GET request
    certificate_id = request.args.get('certificate_id')
    if certificate_id:
        certificate = Certificate.query.filter_by(certificate_id=certificate_id.strip()).first()
        if certificate:
            is_valid = True
            return render_template('verification_result.html',
                                 certificate=certificate,
                                 is_valid=is_valid,
                                 now=datetime.now(timezone.utc))
    
    return render_template('verify_certificate.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def init_db():
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create a default super admin if none exists
        if not User.query.filter_by(role='super_admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
                role='super_admin',
                institution='System',
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user")

# Initialize the database when the application starts
init_db()

if __name__ == '__main__':
    app.run(debug=True)
