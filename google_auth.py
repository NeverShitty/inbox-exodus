"""
Google Authentication Module for Inbox Exodus
Handles Google Workspace authentication and token management
"""
import json
import os
import time
from datetime import datetime, timedelta

import requests
from flask import Blueprint, redirect, request, url_for, session, flash, current_app
from flask_login import login_required, current_user
from oauthlib.oauth2 import WebApplicationClient

from main import db
import models

# Create blueprint
google_auth = Blueprint('google_auth', __name__)

# Google OAuth API endpoints
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Google OAuth scopes
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/drive.metadata.readonly'
]

# Print setup instructions
DEV_REDIRECT_URL = f'https://{os.environ["REPLIT_DEV_DOMAIN"]}/google/callback'
print(f"""
To make Google authentication work:
1. Go to https://console.cloud.google.com/apis/credentials
2. Create a new OAuth 2.0 Client ID
3. Add {DEV_REDIRECT_URL} to Authorized redirect URIs
4. Add your Replit domain to Authorized JavaScript origins

For detailed instructions, see:
https://docs.replit.com/additional-resources/google-auth-in-flask#set-up-your-oauth-app--client
""")

def _get_google_provider_cfg():
    """Get Google's configuration from discovery document"""
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def _get_client():
    """Get OAuth client"""
    return WebApplicationClient(current_app.config['GOOGLE_OAUTH_CLIENT_ID'])

def _build_auth_url(redirect_uri=None):
    """
    Build the Google authentication URL
    
    Args:
        redirect_uri: Optional redirect URI (defaults to callback URL)
        
    Returns:
        str: Authorization URL
    """
    if redirect_uri is None:
        redirect_uri = url_for('google_auth.callback', _external=True)
    
    # Get discovery document to find auth endpoint
    google_provider_cfg = _get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Build request URI
    client = _get_client()
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=SCOPES
    )
    
    return request_uri

def _get_token_from_code(auth_code, redirect_uri=None):
    """
    Exchange authorization code for access token
    
    Args:
        auth_code: Authorization code from callback
        redirect_uri: Optional redirect URI (defaults to callback URL)
        
    Returns:
        dict: Token response or None if failed
    """
    if redirect_uri is None:
        redirect_uri = url_for('google_auth.callback', _external=True)
    
    # Get discovery document to find token endpoint
    google_provider_cfg = _get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    
    # Prepare token request
    client = _get_client()
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=redirect_uri,
        code=auth_code
    )
    
    # Get tokens
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(current_app.config['GOOGLE_OAUTH_CLIENT_ID'], current_app.config['GOOGLE_OAUTH_CLIENT_SECRET']),
    )
    
    # Parse the tokens
    client.parse_request_body_response(json.dumps(token_response.json()))
    
    return token_response.json() if token_response.ok else None

def _get_user_info(token_response):
    """
    Get user information from Google
    
    Args:
        token_response: Token response from Google
        
    Returns:
        dict: User information
    """
    # Get the user info endpoint
    google_provider_cfg = _get_google_provider_cfg()
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    
    # Get user info
    client = _get_client()
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    
    return userinfo_response.json() if userinfo_response.ok else {}

def _save_google_token(token_response, user_info):
    """
    Save Google token to database
    
    Args:
        token_response: Token response from Google
        user_info: User information
        
    Returns:
        models.GoogleAccount: Google account record
    """
    # Check if account already exists
    google_account = models.GoogleAccount.query.filter_by(user_id=current_user.id).first()
    
    # Get user info
    email = user_info.get('email', 'unknown@example.com')
    name = user_info.get('name', '')
    
    # Calculate token expiry time
    expires_in = token_response.get('expires_in', 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    if not google_account:
        # Create new account
        google_account = models.GoogleAccount(
            user_id=current_user.id,
            email=email,
            display_name=name,
            access_token=token_response.get('access_token'),
            refresh_token=token_response.get('refresh_token'),
            token_expiry=token_expiry
        )
        db.session.add(google_account)
    else:
        # Update existing account
        google_account.email = email
        google_account.display_name = name
        google_account.access_token = token_response.get('access_token')
        if 'refresh_token' in token_response:
            google_account.refresh_token = token_response.get('refresh_token')
        google_account.token_expiry = token_expiry
        google_account.connected_at = datetime.utcnow()
    
    db.session.commit()
    return google_account

def _refresh_token_if_needed(google_account):
    """
    Refresh token if it's expired or about to expire
    
    Args:
        google_account: GoogleAccount instance
        
    Returns:
        bool: True if token was refreshed or is still valid
    """
    # Check if token is about to expire (within 5 minutes)
    if google_account.token_expiry is None or google_account.token_expiry <= datetime.utcnow() + timedelta(minutes=5):
        # Token is expired or about to expire, refresh it
        if not google_account.refresh_token:
            return False
        
        # Get token endpoint
        google_provider_cfg = _get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare refresh token request
        refresh_params = {
            'client_id': current_app.config['GOOGLE_OAUTH_CLIENT_ID'],
            'client_secret': current_app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
            'refresh_token': google_account.refresh_token,
            'grant_type': 'refresh_token'
        }
        
        # Get new access token
        response = requests.post(token_endpoint, data=refresh_params)
        
        if not response.ok:
            return False
        
        result = response.json()
        
        # Update token in database
        google_account.access_token = result.get('access_token')
        if 'refresh_token' in result:
            google_account.refresh_token = result.get('refresh_token')
        
        # Calculate new expiry time
        expires_in = result.get('expires_in', 3600)
        google_account.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        
        db.session.commit()
    
    return True

# Routes
@google_auth.route('/google/connect')
@login_required
def connect():
    """
    Redirect to Google OAuth login page
    """
    auth_url = _build_auth_url()
    return redirect(auth_url)

@google_auth.route('/google/callback')
@login_required
def callback():
    """
    Handle Google OAuth callback
    """
    # Check for error
    if 'error' in request.args:
        error = request.args.get('error')
        error_description = request.args.get('error_description', 'Unknown error')
        flash(f"Google authentication failed: {error_description}", 'danger')
        return redirect(url_for('dashboard'))
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        flash("No authorization code received from Google", 'danger')
        return redirect(url_for('dashboard'))
    
    # Exchange code for token
    token_response = _get_token_from_code(code)
    if not token_response:
        flash("Failed to get access token from Google", 'danger')
        return redirect(url_for('dashboard'))
    
    # Get user info
    user_info = _get_user_info(token_response)
    if not user_info:
        flash("Failed to get user information from Google", 'danger')
        return redirect(url_for('dashboard'))
    
    # Verify email
    if not user_info.get('email_verified', False):
        flash("Google email not verified", 'danger')
        return redirect(url_for('dashboard'))
    
    # Save token to database
    google_account = _save_google_token(token_response, user_info)
    
    flash(f"Successfully connected to Google Workspace as {google_account.email}", 'success')
    return redirect(url_for('dashboard'))

@google_auth.route('/google/disconnect')
@login_required
def disconnect():
    """
    Disconnect Google account
    """
    google_account = models.GoogleAccount.query.filter_by(user_id=current_user.id).first()
    
    if google_account:
        db.session.delete(google_account)
        db.session.commit()
        
        flash("Google Workspace account disconnected", 'info')
    else:
        flash("No Google Workspace account connected", 'warning')
    
    return redirect(url_for('dashboard'))

@google_auth.route('/google/status')
@login_required
def status():
    """
    Check Google account connection status
    """
    google_account = models.GoogleAccount.query.filter_by(user_id=current_user.id).first()
    
    if not google_account:
        return {'status': 'disconnected'}
    
    # Check if token is valid
    token_valid = _refresh_token_if_needed(google_account)
    
    if not token_valid:
        return {'status': 'expired'}
    
    return {
        'status': 'connected',
        'email': google_account.email,
        'name': google_account.display_name,
        'connected_at': google_account.connected_at.isoformat() if google_account.connected_at else None,
        'expires_at': google_account.token_expiry.isoformat() if google_account.token_expiry else None
    }