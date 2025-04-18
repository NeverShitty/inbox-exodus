"""
Microsoft Extractor for Inbox Exodus
Extracts emails and files from Microsoft 365 (Outlook and OneDrive)
"""
import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import msal
import requests
from urllib.parse import urljoin

from utils.logger import AuditLogger
from utils.file_hasher import FileHasher

logger = logging.getLogger("inbox_exodus.microsoft_extractor")

class MicrosoftExtractor:
    """Handles extraction from Microsoft 365 (Outlook and OneDrive)"""

    def __init__(self, config):
        """
        Initialize Microsoft Extractor
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.auth_app = None
        self.access_token = None
        self.token_expires_at = 0
        self.user_email = None
        self.temp_dir = config.temp_dir
        self.audit_logger = AuditLogger(config)
        self.file_hasher = FileHasher()
        
        # Initialize MSAL app
        self._init_auth_app()
        
    def _init_auth_app(self):
        """Initialize the MSAL application"""
        self.auth_app = msal.ConfidentialClientApplication(
            client_id=self.config.ms_client_id,
            client_credential=self.config.ms_client_secret,
            authority=f"https://login.microsoftonline.com/{self.config.ms_tenant_id}",
        )
    
    def get_auth_url(self) -> str:
        """
        Get the authorization URL for user to authenticate
        
        Returns:
            str: Authorization URL
        """
        auth_url = self.auth_app.get_authorization_request_url(
            scopes=["Mail.Read", "Files.Read.All", "User.Read", "offline_access"],
            redirect_uri=self.config.ms_redirect_uri,
        )
        return auth_url
    
    def get_token_from_code(self, auth_code: str) -> bool:
        """
        Exchange authorization code for access token
        
        Args:
            auth_code: Authorization code from callback
            
        Returns:
            bool: True if token was acquired successfully
        """
        result = self.auth_app.acquire_token_by_authorization_code(
            code=auth_code,
            scopes=["Mail.Read", "Files.Read.All", "User.Read", "offline_access"],
            redirect_uri=self.config.ms_redirect_uri,
        )
        
        if "access_token" not in result:
            logger.error(f"Failed to get token: {result.get('error_description', 'Unknown error')}")
            return False
        
        self.access_token = result["access_token"]
        # Set token expiration (subtract 5 minutes for safety margin)
        self.token_expires_at = time.time() + result.get("expires_in", 3600) - 300
        
        # Get user information
        self._get_user_info()
        return True
    
    def _refresh_token_if_needed(self):
        """Check if token is about to expire and refresh if needed"""
        if time.time() >= self.token_expires_at:
            result = self.auth_app.acquire_token_by_refresh_token(
                refresh_token=self.auth_app.token_cache._cache["refresh_tokens"],
                scopes=["Mail.Read", "Files.Read.All", "User.Read", "offline_access"],
            )
            
            if "access_token" in result:
                self.access_token = result["access_token"]
                # Set token expiration (subtract 5 minutes for safety margin)
                self.token_expires_at = time.time() + result.get("expires_in", 3600) - 300
                logger.debug("Access token refreshed successfully")
            else:
                logger.error(f"Failed to refresh token: {result.get('error_description', 'Unknown error')}")
                return False
        
        return True
    
    def _get_user_info(self):
        """Get user information from Microsoft Graph API"""
        if not self._refresh_token_if_needed():
            return None
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers=headers
        )
        
        if response.status_code == 200:
            user_info = response.json()
            self.user_email = user_info.get("userPrincipalName")
            logger.info(f"Connected to Microsoft 365 as: {self.user_email}")
            return user_info
        else:
            logger.error(f"Failed to get user info: {response.text}")
            return None
    
    def analyze_storage(self) -> Dict[str, Any]:
        """
        Analyze Outlook and OneDrive storage
        
        Returns:
            Dict: Statistics about the data sources
        """
        stats = {
            "outlook": {
                "folder_count": 0,
                "email_count": 0,
                "total_size_bytes": 0
            },
            "onedrive": {
                "folder_count": 0,
                "file_count": 0,
                "total_size_bytes": 0
            }
        }
        
        # Analyze Outlook
        logger.info("Analyzing Outlook storage...")
        folders = self.get_mail_folders()
        if folders:
            stats["outlook"]["folder_count"] = len(folders)
            
            for folder in folders:
                folder_stats = self.get_email_stats(folder["id"])
                if folder_stats:
                    stats["outlook"]["email_count"] += folder_stats["email_count"]
                    stats["outlook"]["total_size_bytes"] += folder_stats["total_size_bytes"]
        
        # Analyze OneDrive
        logger.info("Analyzing OneDrive storage...")
        onedrive_stats = self.get_onedrive_stats()
        if onedrive_stats:
            stats["onedrive"] = onedrive_stats
        
        return stats
    
    def get_mail_folders(self) -> List[Dict[str, Any]]:
        """
        Get list of mail folders from Outlook
        
        Returns:
            List[Dict]: List of mail folders
        """
        if not self._refresh_token_if_needed():
            return []
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders",
            headers=headers
        )
        
        if response.status_code == 200:
            folders = response.json().get("value", [])
            logger.debug(f"Found {len(folders)} mail folders")
            return folders
        else:
            logger.error(f"Failed to get mail folders: {response.text}")
            return []
    
    def get_email_stats(self, folder_id: str) -> Dict[str, Any]:
        """
        Get statistics about emails in a folder
        
        Args:
            folder_id: ID of the mail folder
            
        Returns:
            Dict: Statistics about emails in the folder
        """
        if not self._refresh_token_if_needed():
            return None
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        # Get message count in folder
        response = requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            folder_info = response.json()
            return {
                "email_count": folder_info.get("totalItemCount", 0),
                "total_size_bytes": folder_info.get("sizeInBytes", 0)
            }
        else:
            logger.error(f"Failed to get folder stats: {response.text}")
            return None
    
    def get_onedrive_stats(self) -> Dict[str, Any]:
        """
        Get statistics about OneDrive files
        
        Returns:
            Dict: Statistics about OneDrive
        """
        if not self._refresh_token_if_needed():
            return None
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        # Get root folder information
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me/drive/root",
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get OneDrive root: {response.text}")
            return None
        
        # Get children count recursively
        stats = {
            "folder_count": 0,
            "file_count": 0,
            "total_size_bytes": 0
        }
        
        # Queue for BFS traversal
        queue = ["root"]
        
        while queue:
            current_item = queue.pop(0)
            
            # Get children of current item
            children_url = f"https://graph.microsoft.com/v1.0/me/drive/{current_item}/children"
            if current_item == "root":
                children_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
            
            response = requests.get(children_url, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get children: {response.text}")
                continue
            
            children = response.json().get("value", [])
            
            for child in children:
                if child.get("folder"):
                    stats["folder_count"] += 1
                    # Add to queue for traversal
                    queue.append(f"items/{child['id']}")
                else:
                    stats["file_count"] += 1
                    stats["total_size_bytes"] += child.get("size", 0)
        
        return stats
    
    def extract_emails(self, output_dir: str, folder_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Extract emails from Outlook
        
        Args:
            output_dir: Directory to save extracted emails
            folder_id: Optional folder ID to extract from (None for all folders)
            
        Returns:
            List[Dict]: Metadata about extracted emails
        """
        if not self._refresh_token_if_needed():
            return []
        
        extracted_emails = []
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        # Get folders to process
        folders = []
        if folder_id:
            # Get specific folder
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                folders = [response.json()]
            else:
                logger.error(f"Failed to get folder {folder_id}: {response.text}")
                return []
        else:
            # Get all folders
            folders = self.get_mail_folders()
        
        # Process each folder
        for folder in folders:
            folder_name = folder.get("displayName", "Unknown")
            logger.info(f"Processing folder: {folder_name}")
            
            # Create folder-specific directory
            folder_dir = os.path.join(output_dir, self._sanitize_filename(folder_name))
            os.makedirs(folder_dir, exist_ok=True)
            
            # Get messages in folder
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder['id']}/messages?$top=100",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get messages: {response.text}")
                continue
            
            messages = response.json().get("value", [])
            next_link = response.json().get("@odata.nextLink")
            
            while True:
                # Process current batch of messages
                for message in messages:
                    email_metadata = self._save_email(message, folder_dir)
                    if email_metadata:
                        extracted_emails.append(email_metadata)
                
                # Check if there are more messages
                if not next_link:
                    break
                
                # Get next batch of messages
                response = requests.get(next_link, headers=headers)
                
                if response.status_code != 200:
                    logger.error(f"Failed to get messages: {response.text}")
                    break
                
                messages = response.json().get("value", [])
                next_link = response.json().get("@odata.nextLink")
        
        return extracted_emails
    
    def _save_email(self, message: Dict[str, Any], folder_dir: str) -> Dict[str, Any]:
        """
        Save an email to disk
        
        Args:
            message: Email message from Microsoft Graph API
            folder_dir: Directory to save the email
            
        Returns:
            Dict: Metadata about the saved email
        """
        message_id = message.get("id")
        subject = message.get("subject", "No Subject")
        received_datetime = message.get("receivedDateTime", "")
        
        # Generate a filename with date and subject
        date_str = ""
        if received_datetime:
            try:
                dt = datetime.strptime(received_datetime, "%Y-%m-%dT%H:%M:%SZ")
                date_str = dt.strftime("%Y%m%d_%H%M%S")
            except:
                date_str = "unknown_date"
        
        filename = f"{date_str}_{self._sanitize_filename(subject)[:50]}.eml"
        filepath = os.path.join(folder_dir, filename)
        
        # Save email as .eml file
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                # Write basic email headers
                f.write(f"From: {message.get('from', {}).get('emailAddress', {}).get('address', 'unknown')}\n")
                f.write(f"To: {'; '.join([recipient.get('emailAddress', {}).get('address', '') for recipient in message.get('toRecipients', [])])}\n")
                f.write(f"Subject: {subject}\n")
                f.write(f"Date: {received_datetime}\n")
                f.write(f"Message-ID: {message_id}\n\n")
                
                # Write body
                body_content = message.get("body", {}).get("content", "")
                f.write(body_content)
        except Exception as e:
            logger.error(f"Failed to save email {message_id}: {str(e)}")
            return None
        
        # Calculate file hash
        file_hash = self.file_hasher.calculate_hash(filepath)
        
        # Log the extraction
        email_metadata = {
            "source": "outlook",
            "message_id": message_id,
            "subject": subject,
            "from": message.get("from", {}).get("emailAddress", {}).get("address", ""),
            "received_date": received_datetime,
            "file_path": filepath,
            "file_hash": file_hash,
            "has_attachments": message.get("hasAttachments", False)
        }
        
        self.audit_logger.log_extraction(
            source_type="outlook",
            source_id=message_id,
            destination=filepath,
            file_hash=file_hash,
            metadata=email_metadata
        )
        
        return email_metadata
    
    def extract_onedrive_files(self, output_dir: str, folder_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Extract files from OneDrive
        
        Args:
            output_dir: Directory to save extracted files
            folder_path: Optional folder path to extract from (None for all files)
            
        Returns:
            List[Dict]: Metadata about extracted files
        """
        if not self._refresh_token_if_needed():
            return []
        
        extracted_files = []
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        # Determine the starting point
        drive_path = "root"
        if folder_path:
            # Get the item ID for the specified path
            path_encoded = folder_path.replace("/", ":")
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/drive/root:/{path_encoded}",
                headers=headers
            )
            
            if response.status_code == 200:
                drive_path = f"items/{response.json().get('id')}"
            else:
                logger.error(f"Failed to find OneDrive folder {folder_path}: {response.text}")
                return []
        
        # Queue for BFS traversal with relative path
        queue = [(drive_path, "")]
        
        while queue:
            current_item, relative_path = queue.pop(0)
            
            # Get children of current item
            children_url = f"https://graph.microsoft.com/v1.0/me/drive/{current_item}/children"
            if current_item == "root":
                children_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
            
            response = requests.get(children_url, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get children: {response.text}")
                continue
            
            children = response.json().get("value", [])
            
            for child in children:
                child_name = child.get("name", "Unknown")
                child_path = os.path.join(relative_path, child_name)
                
                if child.get("folder"):
                    # Create folder in output directory
                    folder_dir = os.path.join(output_dir, child_path)
                    os.makedirs(folder_dir, exist_ok=True)
                    
                    # Add to queue for traversal
                    queue.append((f"items/{child['id']}", child_path))
                else:
                    # Download file
                    file_metadata = self._download_file(child, os.path.join(output_dir, child_path))
                    if file_metadata:
                        extracted_files.append(file_metadata)
        
        return extracted_files
    
    def _download_file(self, file_item: Dict[str, Any], output_path: str) -> Dict[str, Any]:
        """
        Download a file from OneDrive
        
        Args:
            file_item: File item from Microsoft Graph API
            output_path: Path to save the file
            
        Returns:
            Dict: Metadata about the downloaded file
        """
        if not self._refresh_token_if_needed():
            return None
        
        file_id = file_item.get("id")
        file_name = file_item.get("name")
        file_size = file_item.get("size", 0)
        
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Get download URL
        response = requests.get(
            f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content",
            headers=headers,
            allow_redirects=False
        )
        
        if response.status_code == 302:
            download_url = response.headers.get("Location")
            if not download_url:
                logger.error(f"Failed to get download URL for {file_name}")
                return None
            
            # Download file
            try:
                file_dir = os.path.dirname(output_path)
                os.makedirs(file_dir, exist_ok=True)
                
                response = requests.get(download_url, stream=True)
                
                if response.status_code == 200:
                    with open(output_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=1024):
                            if chunk:
                                f.write(chunk)
                    
                    # Calculate file hash
                    file_hash = self.file_hasher.calculate_hash(output_path)
                    
                    # Create file metadata
                    file_metadata = {
                        "source": "onedrive",
                        "file_id": file_id,
                        "name": file_name,
                        "size": file_size,
                        "mime_type": file_item.get("file", {}).get("mimeType", ""),
                        "created_date": file_item.get("createdDateTime", ""),
                        "modified_date": file_item.get("lastModifiedDateTime", ""),
                        "file_path": output_path,
                        "file_hash": file_hash
                    }
                    
                    # Log the extraction
                    self.audit_logger.log_extraction(
                        source_type="onedrive",
                        source_id=file_id,
                        destination=output_path,
                        file_hash=file_hash,
                        metadata=file_metadata
                    )
                    
                    return file_metadata
                else:
                    logger.error(f"Failed to download {file_name}: {response.text}")
                    return None
                
            except Exception as e:
                logger.error(f"Failed to download {file_name}: {str(e)}")
                return None
        else:
            logger.error(f"Failed to get download URL for {file_name}: {response.text}")
            return None
    
    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename by removing invalid characters
        
        Args:
            filename: Original filename
            
        Returns:
            str: Sanitized filename
        """
        # Replace invalid characters with underscore
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Trim whitespace
        filename = filename.strip()
        
        # If filename is empty, use a placeholder
        if not filename:
            filename = "unnamed"
        
        return filename
