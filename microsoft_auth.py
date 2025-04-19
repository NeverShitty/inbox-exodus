"""
Microsoft Authentication Module for Inbox Exodus
Handles Microsoft 365 authentication and token management
"""
import os
import time
from datetime import datetime, timedelta
import msal

from flask import Blueprint, redirect, request, url_for, session, flash, current_app
from flask_login import login_required, current_user

from app import db
import models

# Create blueprint
microsoft_auth = Blueprint('microsoft_auth', __name__)

# Microsoft Graph API scopes
# These scopes determine what our application can access
SCOPES = [
    'User.Read',
    'Mail.Read',
    'Mail.ReadBasic',
    'Files.Read',
    'Files.Read.All',
    'offline_access'  # Required for refresh tokens
]

def _get_msal_app(cache=None):
    """
    Initialize the MSAL application
    
    Args:
        cache: Optional token cache
        
    Returns:
        msal.ConfidentialClientApplication instance
    """
    return msal.ConfidentialClientApplication(
        current_app.config['MS_CLIENT_ID'],
        authority=f"https://login.microsoftonline.com/{current_app.config['MS_TENANT_ID']}",
        client_credential=current_app.config['MS_CLIENT_SECRET'],
        token_cache=cache
    )

def _build_auth_url(state=None, redirect_uri=None):
    """
    Build the Microsoft authentication URL
    
    Args:
        state: Optional state parameter for OAuth flow
        redirect_uri: Optional redirect URI (defaults to callback URL)
        
    Returns:
        str: Authorization URL
    """
    if redirect_uri is None:
        redirect_uri = url_for('microsoft_auth.callback', _external=True)
    
    return _get_msal_app().get_authorization_request_url(
        SCOPES,
        state=state,
        redirect_uri=redirect_uri
    )

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
        redirect_uri = url_for('microsoft_auth.callback', _external=True)
    
    result = _get_msal_app().acquire_token_by_authorization_code(
        auth_code,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    
    return result if 'error' not in result else None

def _save_microsoft_token(token_response):
    """
    Save Microsoft token to database
    
    Args:
        token_response: Token response from MSAL
        
    Returns:
        models.MicrosoftAccount: Microsoft account record
    """
    # Check if account already exists
    ms_account = models.MicrosoftAccount.query.filter_by(user_id=current_user.id).first()
    
    # Get user info from token
    user_info = token_response.get('id_token_claims', {})
    email = user_info.get('preferred_username', user_info.get('email', 'unknown@example.com'))
    name = user_info.get('name', '')
    
    # Calculate token expiry time
    expires_in = token_response.get('expires_in', 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    if not ms_account:
        # Create new account
        ms_account = models.MicrosoftAccount(
            user_id=current_user.id,
            email=email,
            display_name=name,
            access_token=token_response.get('access_token'),
            refresh_token=token_response.get('refresh_token'),
            token_expiry=token_expiry
        )
        db.session.add(ms_account)
    else:
        # Update existing account
        ms_account.email = email
        ms_account.display_name = name
        ms_account.access_token = token_response.get('access_token')
        if 'refresh_token' in token_response:
            ms_account.refresh_token = token_response.get('refresh_token')
        ms_account.token_expiry = token_expiry
        ms_account.connected_at = datetime.utcnow()
    
    db.session.commit()
    return ms_account

def _refresh_token_if_needed(ms_account):
    """
    Refresh token if it's expired or about to expire
    
    Args:
        ms_account: MicrosoftAccount instance
        
    Returns:
        bool: True if token was refreshed or is still valid
    """
    # Check if token is about to expire (within 5 minutes)
    if ms_account.token_expiry is None or ms_account.token_expiry <= datetime.utcnow() + timedelta(minutes=5):
        # Token is expired or about to expire, refresh it
        if not ms_account.refresh_token:
            return False
        
        app = _get_msal_app()
        result = app.acquire_token_by_refresh_token(
            ms_account.refresh_token,
            scopes=SCOPES
        )
        
        if 'error' in result:
            return False
        
        # Update token in database
        ms_account.access_token = result.get('access_token')
        if 'refresh_token' in result:
            ms_account.refresh_token = result.get('refresh_token')
        
        # Calculate new expiry time
        expires_in = result.get('expires_in', 3600)
        ms_account.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        
        db.session.commit()
    
    return True

# Routes
@microsoft_auth.route('/microsoft/connect')
@login_required
def connect():
    """
    Redirect to Microsoft OAuth login page
    """
    auth_url = _build_auth_url()
    return redirect(auth_url)

@microsoft_auth.route('/microsoft/callback')
@login_required
def callback():
    """
    Handle Microsoft OAuth callback
    """
    # Check for error
    if 'error' in request.args:
        error = request.args.get('error')
        error_description = request.args.get('error_description', 'Unknown error')
        flash(f"Microsoft authentication failed: {error_description}", 'danger')
        return redirect(url_for('dashboard'))
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        flash("No authorization code received from Microsoft", 'danger')
        return redirect(url_for('dashboard'))
    
    # Exchange code for token
    token_response = _get_token_from_code(code)
    if not token_response:
        flash("Failed to get access token from Microsoft", 'danger')
        return redirect(url_for('dashboard'))
    
    # Save token to database
    ms_account = _save_microsoft_token(token_response)
    
    flash(f"Successfully connected to Microsoft 365 as {ms_account.email}", 'success')
    return redirect(url_for('dashboard'))

@microsoft_auth.route('/microsoft/disconnect')
@login_required
def disconnect():
    """
    Disconnect Microsoft account
    """
    ms_account = models.MicrosoftAccount.query.filter_by(user_id=current_user.id).first()
    
    if ms_account:
        db.session.delete(ms_account)
        db.session.commit()
        
        flash("Microsoft 365 account disconnected", 'info')
    else:
        flash("No Microsoft 365 account connected", 'warning')
    
    return redirect(url_for('dashboard'))

@microsoft_auth.route('/microsoft/status')
@login_required
def status():
    """
    Check Microsoft account connection status
    """
    ms_account = models.MicrosoftAccount.query.filter_by(user_id=current_user.id).first()
    
    if not ms_account:
        return {'status': 'disconnected'}
    
    # Check if token is valid
    token_valid = _refresh_token_if_needed(ms_account)
    
    if not token_valid:
        return {'status': 'expired'}
    
    return {
        'status': 'connected',
        'email': ms_account.email,
        'name': ms_account.display_name,
        'connected_at': ms_account.connected_at.isoformat() if ms_account.connected_at else None,
        'expires_at': ms_account.token_expiry.isoformat() if ms_account.token_expiry else None
    }