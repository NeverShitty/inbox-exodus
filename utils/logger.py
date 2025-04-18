"""
Audit Logger for Inbox Exodus
Provides comprehensive logging for audit trail and chain-of-custody
"""
import os
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("inbox_exodus.audit_logger")

class AuditLogger:
    """
    Provides comprehensive logging for audit trail and chain-of-custody
    All logs are stored in JSONL format for easy parsing and analysis
    """
    
    def __init__(self, config):
        """
        Initialize Audit Logger
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.log_dir = config.log_dir
        
        # Create log directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Define log files
        self.extraction_log = os.path.join(self.log_dir, "extraction_log.jsonl")
        self.classification_log = os.path.join(self.log_dir, "classification_log.jsonl")
        self.litigation_log = os.path.join(self.log_dir, "litigation_log.jsonl")
        self.migration_log = os.path.join(self.log_dir, "migration_log.jsonl")
        self.error_log = os.path.join(self.log_dir, "error_log.jsonl")
        self.total_recall_log = os.path.join(self.log_dir, "TOTAL_RECALL_LOG.jsonl")
        self.failure_log = os.path.join(self.log_dir, "TOTAL_RECALL_FAILURE_LOG.jsonl")
    
    def log_extraction(self, source_type: str, source_id: str, destination: str, file_hash: str, metadata: Dict[str, Any] = None):
        """
        Log file extraction from source
        
        Args:
            source_type: Type of source (outlook, onedrive)
            source_id: ID of the source item
            destination: Destination file path
            file_hash: SHA-256 hash of the file
            metadata: Additional metadata about the extraction
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "extraction",
            "source_type": source_type,
            "source_id": source_id,
            "destination": destination,
            "file_hash": file_hash
        }
        
        if metadata:
            entry["metadata"] = metadata
        
        # Log to extraction log
        self._append_to_log(self.extraction_log, entry)
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def log_classification(self, file_path: str, classification: Dict[str, Any]):
        """
        Log file classification
        
        Args:
            file_path: Path to the classified file
            classification: Classification results
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "classification",
            "file_path": file_path,
            "classification": classification
        }
        
        # Log to classification log
        self._append_to_log(self.classification_log, entry)
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def log_litigation_scan(self, file_path: str, litigation_risk: bool, terms_found: list):
        """
        Log litigation scan results
        
        Args:
            file_path: Path to the scanned file
            litigation_risk: Whether the file has litigation risk
            terms_found: List of litigation terms found
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "litigation_scan",
            "file_path": file_path,
            "litigation_risk": litigation_risk,
            "terms_found": terms_found
        }
        
        # Log to litigation log
        self._append_to_log(self.litigation_log, entry)
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def log_migration(self, source_path: str, destination_type: str, destination_id: str, source_hash: str, metadata: Dict[str, Any] = None):
        """
        Log file migration to destination
        
        Args:
            source_path: Path to the source file
            destination_type: Type of destination (drive, gmail)
            destination_id: ID of the destination item
            source_hash: SHA-256 hash of the source file
            metadata: Additional metadata about the migration
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "migration",
            "source_path": source_path,
            "destination_type": destination_type,
            "destination_id": destination_id,
            "source_hash": source_hash
        }
        
        if metadata:
            entry["metadata"] = metadata
        
        # Log to migration log
        self._append_to_log(self.migration_log, entry)
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def log_error(self, module: str, action: str, error_message: str, details: Dict[str, Any] = None):
        """
        Log an error
        
        Args:
            module: Module where the error occurred
            action: Action being performed when the error occurred
            error_message: Error message
            details: Additional details about the error
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "error",
            "module": module,
            "error_action": action,
            "error_message": error_message
        }
        
        if details:
            entry["details"] = details
        
        # Log to error log
        self._append_to_log(self.error_log, entry)
        
        # Log to failure log
        self._append_to_log(self.failure_log, entry)
    
    def log_commit_intent(self, action: str, status: str, source: str, destination: str, reason: str, approved_by: Optional[str] = None):
        """
        Log commit intent for an action
        
        Args:
            action: Action to be performed (move, copy, etc.)
            status: Status of the action (PENDING, EXECUTED, FAILED)
            source: Source of the action
            destination: Destination of the action
            reason: Reason for the action
            approved_by: User who approved the action
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "status": status,
            "source": source,
            "destination": destination,
            "reason": reason,
            "approved_by": approved_by
        }
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def log_execution_result(self, status: str, timestamp: str, verified_by: str):
        """
        Log execution result for a committed action
        
        Args:
            status: Status of the execution (EXECUTED, FAILED)
            timestamp: Timestamp of the execution
            verified_by: User who verified the execution
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "execution_result",
            "status": status,
            "execution_timestamp": timestamp,
            "verified_by": verified_by
        }
        
        # Log to total recall log
        self._append_to_log(self.total_recall_log, entry)
    
    def _append_to_log(self, log_file: str, entry: Dict[str, Any]):
        """
        Append an entry to a log file
        
        Args:
            log_file: Path to the log file
            entry: Log entry to append
        """
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to log file {log_file}: {str(e)}")
