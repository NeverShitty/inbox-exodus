#!/usr/bin/env python3
"""
Inbox Exodus - AI-Driven File Migration Tool
Main entry point for the application
"""
import os
import sys
import logging
import json

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

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

# Initialize SQLAlchemy with Flask
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

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

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    """Main page of the web application"""
    return render_template('index.html', app_name="Inbox Exodus")

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
