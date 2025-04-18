"""
File Hasher for Inbox Exodus
Calculates SHA-256 hashes for files
"""
import hashlib
import logging
from typing import Optional

logger = logging.getLogger("inbox_exodus.file_hasher")

class FileHasher:
    """Calculates SHA-256 hashes for files"""
    
    def __init__(self):
        """Initialize File Hasher"""
        pass
    
    def calculate_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: SHA-256 hash in hexadecimal
        """
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Read and update hash in chunks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {str(e)}")
            return None
    
    def verify_hash(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify if a file's hash matches an expected hash
        
        Args:
            file_path: Path to the file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            bool: True if the hash matches
        """
        actual_hash = self.calculate_hash(file_path)
        
        if not actual_hash:
            return False
        
        return actual_hash.lower() == expected_hash.lower()
