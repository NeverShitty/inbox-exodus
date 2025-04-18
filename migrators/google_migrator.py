"""
Google Migrator for Inbox Exodus
Handles migration of files to Google Workspace (Gmail and Drive)
"""
import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import google.oauth2.credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from utils.logger import AuditLogger
from utils.file_hasher import FileHasher

logger = logging.getLogger("inbox_exodus.google_migrator")

class GoogleMigrator:
    """Handles migration of files to Google Workspace"""
    
    def __init__(self, config):
        """
        Initialize Google Migrator
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.credentials = None
        self.drive_service = None
        self.gmail_service = None
        self.temp_dir = config.temp_dir
        self.audit_logger = AuditLogger(config)
        self.file_hasher = FileHasher()
        
        # Define OAuth2 scopes
        self.scopes = [
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/gmail.compose'
        ]
    
    def authenticate(self) -> bool:
        """
        Authenticate with Google Workspace
        
        Returns:
            bool: True if authentication was successful
        """
        try:
            # Create client config dictionary from environment variables
            client_config = {
                "installed": {
                    "client_id": self.config.google_client_id,
                    "client_secret": self.config.google_client_secret,
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", self.config.google_redirect_uri],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            }
            
            # Create flow
            flow = InstalledAppFlow.from_client_config(
                client_config=client_config,
                scopes=self.scopes
            )
            
            # Run the flow
            self.credentials = flow.run_local_server(port=8000)
            
            # Build services
            self.drive_service = build('drive', 'v3', credentials=self.credentials)
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            
            # Get user info to verify authentication
            user_info = self.gmail_service.users().getProfile(userId='me').execute()
            email = user_info.get('emailAddress', 'Unknown')
            logger.info(f"Successfully authenticated with Google as: {email}")
            
            return True
            
        except Exception as e:
            logger.error(f"Google authentication failed: {str(e)}")
            return False
    
    def refresh_token_if_needed(self):
        """Refresh the access token if it's expired"""
        if not self.credentials:
            logger.error("No credentials available. Please authenticate first.")
            return False
        
        if self.credentials.expired:
            try:
                self.credentials.refresh(Request())
                
                # Rebuild services with refreshed credentials
                self.drive_service = build('drive', 'v3', credentials=self.credentials)
                self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
                
                logger.debug("Google credentials refreshed successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to refresh Google credentials: {str(e)}")
                return False
        
        return True
    
    def create_folder_structure(self, folder_structure: Dict[str, Any], parent_id: str = None) -> Dict[str, str]:
        """
        Create folder structure in Google Drive
        
        Args:
            folder_structure: Folder structure to create
            parent_id: Optional parent folder ID
            
        Returns:
            Dict[str, str]: Mapping of folder paths to Drive folder IDs
        """
        if not self.drive_service:
            logger.error("Drive service not initialized. Please authenticate first.")
            return {}
        
        # Create mapping of folder paths to IDs
        folder_id_map = {}
        
        # Process folder structure
        self._create_folders_recursive(folder_structure, "", parent_id, folder_id_map)
        
        return folder_id_map
    
    def _create_folders_recursive(self, structure: Dict[str, Any], current_path: str, parent_id: str, folder_id_map: Dict[str, str]):
        """
        Recursively create folders in Google Drive
        
        Args:
            structure: Current folder structure
            current_path: Current path in the structure
            parent_id: Parent folder ID
            folder_id_map: Mapping of folder paths to Drive folder IDs
        """
        for folder_name, children in structure.items():
            # Create folder path
            folder_path = folder_name if not current_path else f"{current_path}/{folder_name}"
            
            # Create or find folder
            folder_id = self._create_or_find_folder(folder_name, parent_id)
            
            if folder_id:
                # Add to folder ID map
                folder_id_map[folder_path] = folder_id
                
                # Create children
                if children:
                    self._create_folders_recursive(children, folder_path, folder_id, folder_id_map)
    
    def _create_or_find_folder(self, folder_name: str, parent_id: str = None) -> Optional[str]:
        """
        Create or find a folder in Google Drive
        
        Args:
            folder_name: Name of the folder
            parent_id: Optional parent folder ID
            
        Returns:
            str: Folder ID
        """
        try:
            # Check if folder already exists
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            
            if parent_id:
                query += f" and '{parent_id}' in parents"
            
            results = self.drive_service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name)'
            ).execute()
            
            items = results.get('files', [])
            
            # If folder exists, return its ID
            if items:
                logger.debug(f"Found existing folder '{folder_name}' with ID {items[0]['id']}")
                return items[0]['id']
            
            # Otherwise, create folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_id:
                folder_metadata['parents'] = [parent_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            logger.debug(f"Created folder '{folder_name}' with ID {folder_id}")
            
            return folder_id
            
        except Exception as e:
            logger.error(f"Failed to create or find folder '{folder_name}': {str(e)}")
            return None
    
    def upload_file(self, file_path: str, folder_id: str = None) -> Dict[str, Any]:
        """
        Upload a file to Google Drive
        
        Args:
            file_path: Path to the file
            folder_id: Optional folder ID to upload to
            
        Returns:
            Dict: Metadata about the uploaded file
        """
        if not self.drive_service:
            logger.error("Drive service not initialized. Please authenticate first.")
            return None
        
        try:
            file_name = os.path.basename(file_path)
            
            # Calculate file hash before upload
            file_hash = self.file_hasher.calculate_hash(file_path)
            
            # Prepare file metadata
            file_metadata = {
                'name': file_name
            }
            
            if folder_id:
                file_metadata['parents'] = [folder_id]
            
            # Upload file
            media = MediaFileUpload(
                file_path,
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, mimeType, webViewLink, createdTime'
            ).execute()
            
            # Create result
            result = {
                "drive_id": file.get('id'),
                "name": file.get('name'),
                "mime_type": file.get('mimeType'),
                "web_link": file.get('webViewLink'),
                "created_time": file.get('createdTime'),
                "source_path": file_path,
                "source_hash": file_hash,
                "folder_id": folder_id
            }
            
            # Log the migration
            self.audit_logger.log_migration(
                source_path=file_path,
                destination_type="drive",
                destination_id=file.get('id'),
                source_hash=file_hash,
                metadata=result
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to upload file {file_path}: {str(e)}")
            return None
    
    def upload_email(self, eml_path: str, folder_id: str = None) -> Dict[str, Any]:
        """
        Upload an email file (.eml) to both Gmail and Drive
        
        Args:
            eml_path: Path to the .eml file
            folder_id: Optional folder ID to upload to in Drive
            
        Returns:
            Dict: Metadata about the uploaded email
        """
        if not self.gmail_service or not self.drive_service:
            logger.error("Services not initialized. Please authenticate first.")
            return None
        
        try:
            # Calculate file hash before upload
            file_hash = self.file_hasher.calculate_hash(eml_path)
            
            # Create result dictionary
            result = {
                "source_path": eml_path,
                "source_hash": file_hash
            }
            
            # Upload to Drive
            drive_result = self.upload_file(eml_path, folder_id)
            if drive_result:
                result["drive_id"] = drive_result.get("drive_id")
                result["drive_web_link"] = drive_result.get("web_link")
            
            # Import to Gmail (as a draft)
            try:
                # Read .eml file
                with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
                    eml_content = f.read()
                
                # Parse headers
                headers = {}
                body = ""
                in_headers = True
                
                for line in eml_content.split('\n'):
                    if in_headers:
                        if not line.strip():
                            in_headers = False
                            continue
                        
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
                    else:
                        body += line + '\n'
                
                # Create message
                message = MIMEMultipart()
                message['to'] = headers.get('to', '')
                message['from'] = headers.get('from', '')
                message['subject'] = headers.get('subject', 'Imported Email')
                
                # Add body
                message.attach(MIMEText(body, 'html'))
                
                # Encode message
                encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                
                # Create draft
                draft = self.gmail_service.users().drafts().create(
                    userId='me',
                    body={'message': {'raw': encoded_message}}
                ).execute()
                
                # Add to result
                result["gmail_draft_id"] = draft.get('id')
                
                # Log the migration
                self.audit_logger.log_migration(
                    source_path=eml_path,
                    destination_type="gmail",
                    destination_id=draft.get('id'),
                    source_hash=file_hash,
                    metadata=result
                )
                
            except Exception as e:
                logger.error(f"Failed to import email to Gmail: {str(e)}")
                result["gmail_error"] = str(e)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to upload email {eml_path}: {str(e)}")
            return None
    
    def migrate_files(self, file_placements: Dict[str, str], folder_id_map: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Migrate files to Google Drive based on file placements
        
        Args:
            file_placements: Mapping of file paths to target locations
            folder_id_map: Mapping of folder paths to Drive folder IDs
            
        Returns:
            List[Dict]: Results of migrated files
        """
        results = []
        
        for file_path, target_path in file_placements.items():
            # Get folder ID for target path
            folder_id = folder_id_map.get(target_path)
            
            if not folder_id:
                logger.warning(f"Target folder '{target_path}' not found in Drive. Using root folder.")
                folder_id = None
            
            # Check if it's an email file
            if file_path.lower().endswith('.eml'):
                result = self.upload_email(file_path, folder_id)
            else:
                result = self.upload_file(file_path, folder_id)
            
            if result:
                results.append(result)
        
        return results
