"""
GPT Classifier for Inbox Exodus
Uses OpenAI GPT to classify files based on content
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional

from openai import OpenAI
import magic
import textract

from utils.logger import AuditLogger

logger = logging.getLogger("inbox_exodus.gpt_classifier")

class GPTClassifier:
    """Uses GPT to classify files based on content"""
    
    def __init__(self, config):
        """
        Initialize GPT Classifier
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.openai_api_key = config.openai_api_key
        self.openai_model = config.openai_model  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
        self.audit_logger = AuditLogger(config)
        
        # Initialize OpenAI client
        self.client = OpenAI(api_key=self.openai_api_key)
    
    def classify_file(self, file_path: str) -> Dict[str, Any]:
        """
        Classify a file using GPT
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dict: Classification results
        """
        try:
            # Extract text content from file
            file_content = self._extract_text(file_path)
            
            if not file_content:
                logger.warning(f"Could not extract text from file: {file_path}")
                return {
                    "entity": "Unknown",
                    "type": "Unknown",
                    "purpose": "Unknown",
                    "confidence": 0.0,
                    "litigation_risk": False,
                    "litigation_terms": []
                }
            
            # Truncate content if too long (GPT has token limits)
            max_length = 15000  # Truncate to ~3,000 tokens
            if len(file_content) > max_length:
                file_content = file_content[:max_length] + "..."
            
            # Classify with GPT
            classification = self._classify_with_gpt(file_content)
            
            # Add file path to classification results
            classification["file_path"] = file_path
            
            # Log classification
            self.audit_logger.log_classification(
                file_path=file_path,
                classification=classification
            )
            
            return classification
        
        except Exception as e:
            logger.error(f"Error classifying file {file_path}: {str(e)}")
            return {
                "entity": "Error",
                "type": "Error",
                "purpose": "Error",
                "confidence": 0.0,
                "litigation_risk": False,
                "litigation_terms": [],
                "error": str(e)
            }
    
    def _extract_text(self, file_path: str) -> Optional[str]:
        """
        Extract text content from a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: Extracted text content
        """
        try:
            # Get MIME type
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            
            # Extract text using textract
            text = textract.process(file_path).decode('utf-8', errors='replace')
            return text
        
        except Exception as e:
            logger.error(f"Failed to extract text from {file_path}: {str(e)}")
            return None
    
    def _classify_with_gpt(self, content: str) -> Dict[str, Any]:
        """
        Classify content using GPT
        
        Args:
            content: Text content to classify
            
        Returns:
            Dict: Classification results
        """
        # Create prompt for GPT
        system_prompt = """
        You are a document classification expert. You need to classify the provided document based on its content.
        Analyze the document and return a JSON object with the following fields:
        
        - entity: The business entity the document belongs to (e.g., ARIBIA LLC, Jean Arlene Venturing LLC, etc.). Use "Personal" if it's a personal document not related to a business entity.
        - type: The document type (e.g., Lease, Contract, Receipt, Statement, Creative, Email, etc.)
        - purpose: The document usage/purpose (e.g., Legal, Tax, Trust, Rental, Archive, etc.)
        - confidence: A number between 0 and 1 indicating your confidence in this classification
        - litigation_risk: Boolean indicating if this document contains content that might be relevant to litigation
        - litigation_terms: List of litigation-related terms found in the document
        
        Do NOT include any explanation, just return the JSON object.
        """
        
        user_prompt = f"Classify this document content: {content}"
        
        try:
            response = self.client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            
            # Parse response
            result = json.loads(response.choices[0].message.content)
            
            # Ensure all expected fields exist
            return {
                "entity": result.get("entity", "Unknown"),
                "type": result.get("type", "Unknown"),
                "purpose": result.get("purpose", "Unknown"),
                "confidence": float(result.get("confidence", 0.0)),
                "litigation_risk": bool(result.get("litigation_risk", False)),
                "litigation_terms": result.get("litigation_terms", [])
            }
            
        except Exception as e:
            logger.error(f"GPT classification error: {str(e)}")
            return {
                "entity": "Error",
                "type": "Error",
                "purpose": "Error",
                "confidence": 0.0,
                "litigation_risk": False,
                "litigation_terms": []
            }
    
    def generate_folder_structure(self, classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate folder structure proposal based on classifications
        
        Args:
            classifications: List of file classifications
            
        Returns:
            Dict: Proposed folder structure
        """
        # Start with base structure from config
        structure = self.config.base_folder_structure.copy()
        
        # Track where each file should go
        file_placements = {}
        
        # Process each classification
        for classification in classifications:
            file_path = classification.get("file_path")
            if not file_path:
                continue
                
            entity = classification.get("entity", "Unknown")
            purpose = classification.get("purpose", "Unknown")
            file_type = classification.get("type", "Unknown")
            litigation_risk = classification.get("litigation_risk", False)
            
            # Determine target location
            if litigation_risk:
                # Put in litigation hold folder
                target_path = "SOURCE_OF_TRUTH/LITIGATION_HOLD"
                
                # Create folder for entity if it doesn't exist
                if entity != "Unknown":
                    target_path = f"{target_path}/{entity}"
                    self._ensure_path_in_structure(structure, target_path)
                
                # Create folder for type if it doesn't exist
                if file_type != "Unknown":
                    target_path = f"{target_path}/{file_type}"
                    self._ensure_path_in_structure(structure, target_path)
                
            else:
                # Determine main category based on purpose
                if purpose in ["Legal", "Contract", "Agreement"]:
                    main_category = "Legal"
                elif purpose in ["Rental", "Lease", "Property"]:
                    main_category = "Rentals"
                elif purpose in ["Trust", "Estate", "Will"]:
                    main_category = "EstatePlanning"
                elif purpose in ["Archive", "Historical"]:
                    main_category = "OldEntities"
                elif purpose in ["Personal", "Private"]:
                    main_category = "Personal"
                else:
                    # Default to entity-based organization
                    if entity.lower().startswith("client"):
                        main_category = "Clients"
                    else:
                        main_category = "Personal"
                
                target_path = f"SOURCE_OF_TRUTH/{main_category}"
                
                # Add entity subfolder if applicable
                if entity != "Unknown" and not entity.lower().startswith("personal"):
                    target_path = f"{target_path}/{entity}"
                    self._ensure_path_in_structure(structure, target_path)
                
                # Add type subfolder if applicable
                if file_type != "Unknown":
                    target_path = f"{target_path}/{file_type}"
                    self._ensure_path_in_structure(structure, target_path)
            
            # Record where this file should go
            file_placements[file_path] = target_path
        
        return {
            "structure": structure,
            "file_placements": file_placements
        }
    
    def _ensure_path_in_structure(self, structure: Dict, path: str):
        """
        Ensure a path exists in the folder structure
        
        Args:
            structure: Current folder structure
            path: Path to ensure exists
        """
        parts = path.split('/')
        current = structure
        
        for i, part in enumerate(parts):
            if i == 0:
                # Skip the root element (SOURCE_OF_TRUTH)
                continue
                
            if part not in current.get(parts[i-1], {}):
                if parts[i-1] not in current:
                    current[parts[i-1]] = {}
                
                current[parts[i-1]][part] = {}
            
            current = current[parts[i-1]]
