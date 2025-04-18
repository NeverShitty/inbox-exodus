#!/usr/bin/env python3
"""
Inbox Exodus - AI-Driven File Migration Tool
Main entry point for the application
"""
import os
import sys
import logging
import json

from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from config import Config

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "inbox_exodus_secret_key")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Configure Microsoft and Google OAuth
app.config["MS_CLIENT_ID"] = os.environ.get("MS_CLIENT_ID")
app.config["MS_CLIENT_SECRET"] = os.environ.get("MS_CLIENT_SECRET")
app.config["MS_TENANT_ID"] = os.environ.get("MS_TENANT_ID")
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

# Initialize SQLAlchemy with Flask
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]"
)
logger = logging.getLogger("inbox_exodus")

# Load configuration
config = Config()

# Import models after db initialization to avoid circular imports
import models

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return models.User.query.get(int(user_id))

# Import auth modules
from microsoft_auth import microsoft_auth
from google_auth import google_auth

# Register blueprints
app.register_blueprint(microsoft_auth)
app.register_blueprint(google_auth)

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    """Main page of the web application"""
    return render_template('index.html', app_name="Inbox Exodus")

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([email, username, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html', app_name="Inbox Exodus")
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', app_name="Inbox Exodus")
        
        # Check if user exists
        existing_user = models.User.query.filter(
            (models.User.email == email) | (models.User.username == username)
        ).first()
        
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return render_template('register.html', app_name="Inbox Exodus")
        
        # Create new user
        user = models.User(email=email, username=username)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', app_name="Inbox Exodus")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        # Find user by username or email
        user = models.User.query.filter(
            (models.User.username == username_or_email) | (models.User.email == username_or_email)
        ).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username/email or password.', 'danger')
            return render_template('login.html', app_name="Inbox Exodus")
        
        # Log in user
        login_user(user, remember=remember)
        
        # Update last login time
        user.last_login = db.func.now()
        db.session.commit()
        
        # Redirect to requested page or dashboard
        next_page = request.args.get('next')
        if not next_page or url_for('index') in next_page:
            next_page = url_for('dashboard')
            
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_page)
    
    return render_template('login.html', app_name="Inbox Exodus")

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get user's migration jobs
    migration_jobs = models.MigrationJob.query.filter_by(user_id=current_user.id).order_by(models.MigrationJob.created_at.desc()).limit(5).all()
    
    # Get Microsoft and Google account status
    ms_account = models.MicrosoftAccount.query.filter_by(user_id=current_user.id).first()
    google_account = models.GoogleAccount.query.filter_by(user_id=current_user.id).first()
    
    return render_template(
        'dashboard.html', 
        app_name="Inbox Exodus",
        migration_jobs=migration_jobs,
        ms_connected=bool(ms_account),
        google_connected=bool(google_account)
    )

@app.route('/status')
def status():
    """API status endpoint"""
    return jsonify({
        "status": "operational",
        "version": "1.0.0",
        "api_integration": {
            "microsoft": bool(config.ms_client_id and config.ms_client_secret and config.ms_tenant_id),
            "google": bool(config.google_client_id and config.google_client_secret),
            "openai": bool(config.openai_api_key)
        }
    })

# Run the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
