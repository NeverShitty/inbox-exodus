"""
Litigation Scanner for Inbox Exodus
Scans files for litigation-related terms and flags them
"""
import os
import re
import logging
from typing import Dict, List, Any, Set

from utils.logger import AuditLogger

logger = logging.getLogger("inbox_exodus.litigation_scanner")

class LitigationScanner:
    """Scans files for litigation-related terms"""
    
    def __init__(self, config):
        """
        Initialize Litigation Scanner
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.litigation_terms = config.litigation_terms
        self.audit_logger = AuditLogger(config)
        
        # Compile regex patterns for faster scanning
        self.patterns = [re.compile(rf'\b{re.escape(term)}\b', re.IGNORECASE) for term in self.litigation_terms]
    
    def scan_file(self, file_path: str, content: str = None) -> Dict[str, Any]:
        """
        Scan a file for litigation-related terms
        
        Args:
            file_path: Path to the file
            content: Optional pre-extracted content
            
        Returns:
            Dict: Scan results
        """
        try:
            # Read file content if not provided
            if content is None:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                except Exception as e:
                    logger.error(f"Failed to read file {file_path}: {str(e)}")
                    return {
                        "file_path": file_path,
                        "litigation_risk": False,
                        "terms_found": [],
                        "error": str(e)
                    }
            
            # Scan for litigation terms
            terms_found = self._find_litigation_terms(content)
            
            # Create result
            result = {
                "file_path": file_path,
                "litigation_risk": len(terms_found) > 0,
                "terms_found": list(terms_found)
            }
            
            # Log scan result
            self.audit_logger.log_litigation_scan(
                file_path=file_path,
                litigation_risk=result["litigation_risk"],
                terms_found=result["terms_found"]
            )
            
            return result
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {
                "file_path": file_path,
                "litigation_risk": False,
                "terms_found": [],
                "error": str(e)
            }
    
    def _find_litigation_terms(self, content: str) -> Set[str]:
        """
        Find litigation-related terms in content
        
        Args:
            content: Text content to scan
            
        Returns:
            Set[str]: Set of found terms
        """
        terms_found = set()
        
        # Scan for each term
        for i, pattern in enumerate(self.patterns):
            if pattern.search(content):
                terms_found.add(self.litigation_terms[i])
        
        return terms_found
    
    def scan_multiple_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple files for litigation-related terms
        
        Args:
            file_paths: List of file paths
            
        Returns:
            List[Dict]: List of scan results
        """
        results = []
        
        for file_path in file_paths:
            result = self.scan_file(file_path)
            results.append(result)
        
        return results
    
    def get_flagged_files(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get files flagged as having litigation risk
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List[Dict]: List of flagged files
        """
        return [result for result in scan_results if result.get("litigation_risk", False)]
