"""
Database models for Inbox Exodus application
"""
from datetime import datetime
from main import db

class User(db.Model):
    """User model for authentication and tracking"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    microsoft_accounts = db.relationship('MicrosoftAccount', backref='user', lazy=True)
    google_accounts = db.relationship('GoogleAccount', backref='user', lazy=True)
    migration_jobs = db.relationship('MigrationJob', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.email}>'

class MicrosoftAccount(db.Model):
    """Microsoft 365 account information"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=True)
    access_token = db.Column(db.Text, nullable=True)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<MicrosoftAccount {self.email}>'

class GoogleAccount(db.Model):
    """Google Workspace account information"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=True)
    access_token = db.Column(db.Text, nullable=True)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<GoogleAccount {self.email}>'

class MigrationJob(db.Model):
    """Represents a file migration job"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, in_progress, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Job details
    source_type = db.Column(db.String(50), nullable=False)  # outlook, onedrive, both
    target_type = db.Column(db.String(50), nullable=False)  # gmail, drive, both
    total_files = db.Column(db.Integer, default=0)
    processed_files = db.Column(db.Integer, default=0)
    failed_files = db.Column(db.Integer, default=0)
    
    # Relationships
    file_items = db.relationship('FileItem', backref='migration_job', lazy=True)
    
    def __repr__(self):
        return f'<MigrationJob {self.name} ({self.status})>'

class FileItem(db.Model):
    """Represents a file or email in a migration job"""
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('migration_job.id'), nullable=False)
    
    # File information
    name = db.Column(db.String(255), nullable=False)
    source_path = db.Column(db.Text, nullable=False)
    target_path = db.Column(db.Text, nullable=True)
    file_type = db.Column(db.String(50), nullable=True)  # email, document, image, etc.
    size_bytes = db.Column(db.Integer, nullable=True)
    
    # Processing information
    status = db.Column(db.String(50), default='pending')  # pending, processed, failed
    processed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # Classification and hashing
    content_hash = db.Column(db.String(64), nullable=True)  # SHA-256 hash
    classification = db.Column(db.JSON, nullable=True)  # GPT classification result
    has_litigation_terms = db.Column(db.Boolean, default=False)
    litigation_terms_found = db.Column(db.JSON, nullable=True)  # List of found terms
    
    def __repr__(self):
        return f'<FileItem {self.name} ({self.status})>'

class AuditLog(db.Model):
    """Audit log for tracking all operations"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file_item.id'), nullable=True)
    job_id = db.Column(db.Integer, db.ForeignKey('migration_job.id'), nullable=True)
    
    # Action details
    action = db.Column(db.String(50), nullable=False)  # extract, classify, migrate, etc.
    status = db.Column(db.String(50), nullable=False)  # success, failure
    source = db.Column(db.Text, nullable=True)
    destination = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True)  # Additional details in JSON format
    
    def __repr__(self):
        return f'<AuditLog {self.action} ({self.status})>'

class FolderStructure(db.Model):
    """Proposed folder structure for a migration job"""
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('migration_job.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Structure information
    structure_data = db.Column(db.JSON, nullable=False)  # Folder structure in JSON format
    is_approved = db.Column(db.Boolean, default=False)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<FolderStructure {self.id} (Approved: {self.is_approved})>'