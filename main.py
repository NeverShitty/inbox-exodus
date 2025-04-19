#!/usr/bin/env python3
"""
Inbox Exodus - AI-Driven File Migration Tool
Main entry point for the application
"""
import os
import sys
import logging
import json
import base64
import tempfile
from datetime import datetime

from flask import request, render_template, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

from config import Config
from app import create_app, db, login_manager
import models
from processors.litigation_detector import LitigationDetector

# Create Flask application
app = create_app()

# Configure logging
logger = logging.getLogger("inbox_exodus")

# Load configuration
config = Config()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return models.User.query.get(int(user_id))

# Import auth modules and register blueprints
from microsoft_auth import microsoft_auth
from google_auth import google_auth

app.register_blueprint(microsoft_auth)
app.register_blueprint(google_auth)

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
            "openai": bool(config.openai_api_key),
            "anthropic": bool(os.environ.get('ANTHROPIC_API_KEY'))
        }
    })

@app.route('/litigation-analyzer', methods=['GET'])
@login_required
def litigation_analyzer_page():
    """Litigation analyzer page"""
    return render_template(
        'litigation_analyzer.html', 
        app_name="Inbox Exodus",
        litigation_terms=config.litigation_terms
    )
    
@app.route('/api/analyze-text', methods=['POST'])
@login_required
def analyze_text():
    """Analyze text for litigation indicators"""
    data = request.get_json()
    
    if not data or 'text' not in data:
        return jsonify({
            'success': False,
            'error': 'No text provided'
        }), 400
        
    text = data.get('text', '')
    document_name = data.get('document_name', 'Custom Text')
    metadata = data.get('metadata', {})
    
    try:
        # Initialize the litigation detector
        detector = LitigationDetector(config)
        
        # Analyze the document
        analysis = detector.analyze_document(text, document_name, metadata)
        
        # Create an audit log
        log = models.AuditLog(
            user_id=current_user.id,
            action='litigation_analysis',
            status='success',
            source='text_input',
            details={
                'document_name': document_name,
                'is_litigation_related': analysis.get('is_litigation_related', False),
                'risk_level': analysis.get('risk_level', 'none'),
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
    except Exception as e:
        logger.error(f"Error analyzing text: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }), 500
        
@app.route('/api/analyze-file', methods=['POST'])
@login_required
def analyze_file():
    """Analyze file(s) for litigation indicators"""
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file provided'
        }), 400
    
    uploaded_files = request.files.getlist('file')
    
    if not uploaded_files or uploaded_files[0].filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    
    # Import the file extractor
    from extractors.file_extractor import FileExtractor
    
    # If there's just one file, process it normally
    if len(uploaded_files) == 1:
        file = uploaded_files[0]
        filename = secure_filename(file.filename)
        file_extension = os.path.splitext(filename)[1].lower()
        temp_file_path = None
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp:
                file.save(temp.name)
                temp_file_path = temp.name
                
                # Use our file extractor to handle different file formats
                extractor = FileExtractor(config)
                extraction_result = extractor.extract_text(temp_file_path, filename)
                
                # Check if extraction was successful
                if 'error' in extraction_result and extraction_result['error']:
                    return jsonify({
                        'success': False,
                        'error': extraction_result['error']
                    }), 400
                    
                # Get extracted text and metadata
                text = extraction_result.get('text', '')
                metadata = extraction_result.get('metadata', {})
                
                if not text.strip():
                    return jsonify({
                        'success': False,
                        'error': 'No text content could be extracted from the file.'
                    }), 400
                    
                # Initialize the litigation detector
                detector = LitigationDetector(config)
                
                # Analyze the document
                analysis = detector.analyze_document(text, filename, metadata)
                
                # For ZIP files with multiple documents, add individual file analyses
                if metadata.get('file_type') == 'ZIP Archive' and 'individual_results' in metadata:
                    individual_analyses = []
                    for file_result in metadata.get('individual_results', []):
                        if not file_result.get('error') and file_result.get('text'):
                            file_text = file_result.get('text', '')
                            file_metadata = file_result.get('metadata', {})
                            file_name = file_metadata.get('file_name', 'Unknown')
                            
                            # Analyze individual file
                            file_analysis = detector.analyze_document(file_text, file_name, file_metadata)
                            individual_analyses.append({
                                'file': file_name,
                                'analysis': file_analysis
                            })
                    
                    # Add individual analyses to the main analysis result
                    analysis['individual_analyses'] = individual_analyses
                
                # Create an audit log
                log = models.AuditLog(
                    user_id=current_user.id,
                    action='litigation_analysis',
                    status='success',
                    source='file_upload',
                    details={
                        'filename': filename,
                        'file_type': metadata.get('file_type', 'Unknown'),
                        'is_litigation_related': analysis.get('is_litigation_related', False),
                        'risk_level': analysis.get('risk_level', 'none'),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                )
                db.session.add(log)
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'analysis': analysis
                })
        except Exception as e:
            logger.error(f"Error analyzing file: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Analysis failed: {str(e)}'
            }), 500
        finally:
            # Clean up temporary file
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    # If multiple files, create a ZIP in memory and process it
    else:
        temp_zip_path = None
        try:
            # Create a temporary ZIP file
            temp_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
            os.close(temp_fd)
            
            # Write files to the ZIP
            with zipfile.ZipFile(temp_zip_path, 'w') as zip_file:
                for file in uploaded_files:
                    filename = secure_filename(file.filename)
                    temp_file_path = None
                    
                    try:
                        # Save file to temporary location
                        with tempfile.NamedTemporaryFile(delete=False) as temp:
                            file.save(temp.name)
                            temp_file_path = temp.name
                            # Add file to ZIP
                            zip_file.write(temp_file_path, filename)
                    finally:
                        # Clean up temporary file
                        if temp_file_path and os.path.exists(temp_file_path):
                            os.unlink(temp_file_path)
            
            # Process the ZIP file
            extractor = FileExtractor(config)
            extraction_result = extractor.extract_text(temp_zip_path, "Multiple Files.zip")
            
            # Check if extraction was successful
            if 'error' in extraction_result and extraction_result['error']:
                return jsonify({
                    'success': False,
                    'error': extraction_result['error']
                }), 400
                
            # Get extracted text and metadata
            text = extraction_result.get('text', '')
            metadata = extraction_result.get('metadata', {})
            
            if not text.strip():
                return jsonify({
                    'success': False,
                    'error': 'No text content could be extracted from the files.'
                }), 400
                
            # Initialize the litigation detector
            detector = LitigationDetector(config)
            
            # Analyze the collective document
            analysis = detector.analyze_document(text, "Multiple Files", metadata)
            
            # Process individual files in the ZIP
            if 'individual_results' in metadata:
                individual_analyses = []
                for file_result in metadata.get('individual_results', []):
                    if not file_result.get('error') and file_result.get('text'):
                        file_text = file_result.get('text', '')
                        file_metadata = file_result.get('metadata', {})
                        file_name = file_metadata.get('file_name', 'Unknown')
                        
                        # Analyze individual file
                        file_analysis = detector.analyze_document(file_text, file_name, file_metadata)
                        individual_analyses.append({
                            'file': file_name,
                            'analysis': file_analysis
                        })
                
                # Add individual analyses to the main analysis result
                analysis['individual_analyses'] = individual_analyses
            
            # Create an audit log
            log = models.AuditLog(
                user_id=current_user.id,
                action='litigation_analysis',
                status='success',
                source='multiple_files_upload',
                details={
                    'filename': "Multiple Files",
                    'file_count': len(uploaded_files),
                    'filenames': [secure_filename(f.filename) for f in uploaded_files],
                    'is_litigation_related': analysis.get('is_litigation_related', False),
                    'risk_level': analysis.get('risk_level', 'none'),
                    'timestamp': datetime.utcnow().isoformat()
                }
            )
            db.session.add(log)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'analysis': analysis
            })
        except Exception as e:
            logger.error(f"Error analyzing file: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Analysis failed: {str(e)}'
            }), 500
        finally:
            # Clean up temporary file
            if temp_zip_path and os.path.exists(temp_zip_path):
                os.unlink(temp_zip_path)

# Run the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
