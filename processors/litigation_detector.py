"""
Litigation Detector module for Inbox Exodus
Specialized in detecting litigation-related content with legal-specific fine-tuning
"""
import os
import json
import logging
from typing import Dict, List, Any, Tuple, Optional, Union

import anthropic
from anthropic import Anthropic

from config import Config

# Setup logger
logger = logging.getLogger(__name__)

class LitigationDetector:
    """
    Advanced litigation detection using Anthropic Claude API
    Specialized in legal document analysis and litigation term detection
    """
    
    def __init__(self, config: Config = None):
        """
        Initialize the litigation detector
        
        Args:
            config: Application configuration (optional)
        """
        self.config = config or Config()
        self.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        if not self.anthropic_api_key:
            logger.warning("ANTHROPIC_API_KEY environment variable not set")
            raise ValueError("ANTHROPIC_API_KEY environment variable must be set")
            
        # Initialize the Anthropic client
        self.client = Anthropic(
            api_key=self.anthropic_api_key,
        )
        
        # The newest Anthropic model is "claude-3-5-sonnet-20241022" which was released October 22, 2024
        self.model = "claude-3-5-sonnet-20241022"
        
        # Load litigation terms from config
        self.litigation_terms = self.config.litigation_terms

    def analyze_document(self, document_text: str, document_name: str = None, 
                         document_metadata: Dict = None) -> Dict[str, Any]:
        """
        Analyze a document for litigation indicators
        
        Args:
            document_text: The document text to analyze
            document_name: The name of the document (optional)
            document_metadata: Additional metadata about the document (optional)
            
        Returns:
            Dict: Analysis results containing litigation indicators
        """
        if not document_text.strip():
            logger.warning("Empty document provided for litigation analysis")
            return {
                "is_litigation_related": False,
                "confidence": 1.0,
                "litigation_terms_found": [],
                "legal_categories": [],
                "summary": "Empty document",
                "risk_level": "none"
            }
            
        # Simple term-based detection first
        term_based_results = self._detect_litigation_terms(document_text)
        
        # If no terms found, use AI for deeper analysis to reduce API costs
        if not term_based_results["terms_found"] and len(document_text.split()) < 50:
            logger.info("No litigation terms found in short document, skipping AI analysis")
            return {
                "is_litigation_related": False,
                "confidence": 0.9,
                "litigation_terms_found": [],
                "legal_categories": [],
                "summary": "No litigation indicators found",
                "risk_level": "none"
            }
        
        # Prepare document context
        context = f"Document name: {document_name or 'Unknown'}\n\n"
        if document_metadata:
            context += f"Metadata: {json.dumps(document_metadata)}\n\n"
        context += f"Document content: {document_text[:8000]}"  # Limit text length
        
        # Define the system prompt for legal analysis
        system_prompt = """You are a specialized legal document analyzer with expertise in litigation detection. 
        Your task is to analyze documents for litigation-related content, legal risks, and regulatory issues.
        Focus on identifying:
        1. Explicit litigation terms, disputes, or legal proceedings
        2. Legal risks or potential for litigation
        3. Regulatory compliance issues
        4. Legal categories the document falls under
        
        Be thorough in your analysis but conservative in flagging litigation risk. Only indicate high risk when clear evidence exists.
        Format your response as JSON with the following fields:
        - is_litigation_related (boolean): whether the document contains litigation content
        - confidence (float between 0-1): your confidence in the assessment
        - litigation_terms_found (array of strings): specific litigation terms found
        - legal_categories (array of strings): legal categories the document falls under
        - summary (string): brief analysis of legal/litigation aspects
        - risk_level (string): "none", "low", "medium", or "high"
        """
        
        # Make the API call to Claude
        try:
            response = self.client.messages.create(
                model=self.model,
                system=system_prompt,
                max_tokens=1000,
                messages=[
                    {"role": "user", "content": f"Analyze this document for litigation content:\n\n{context}"}
                ],
                temperature=0.1,  # Low temperature for more deterministic results
            )
            
            # Extract and parse the response content
            content = response.content[0].text
            # Find the JSON part within the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = content[start_idx:end_idx]
                try:
                    result = json.loads(json_str)
                    # Add term-based results to ensure we don't miss anything
                    if term_based_results["terms_found"]:
                        result["litigation_terms_found"] = list(set(
                            result.get("litigation_terms_found", []) + term_based_results["terms_found"]
                        ))
                        # If terms were found but AI says not litigation related, override with caution
                        if not result.get("is_litigation_related", False) and term_based_results["terms_found"]:
                            result["is_litigation_related"] = True
                            result["confidence"] = 0.7  # Reduced confidence due to conflict
                            result["summary"] = "Litigation terms detected: " + ", ".join(term_based_results["terms_found"])
                            result["risk_level"] = "medium"  # Default to medium risk when terms are found
                            
                    return result
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON from Claude response: {content}")
            
            # Fallback to term-based results if JSON parsing fails
            logger.warning("Using term-based results due to JSON parsing failure")
            return self._convert_term_results_to_full_analysis(term_based_results)
            
        except Exception as e:
            logger.error(f"Error in AI litigation analysis: {str(e)}")
            # Fallback to term-based results
            logger.warning("Using term-based results due to API error")
            return self._convert_term_results_to_full_analysis(term_based_results)

    def _detect_litigation_terms(self, text: str) -> Dict[str, Any]:
        """
        Perform simple term-based litigation detection
        
        Args:
            text: The text to analyze
            
        Returns:
            Dict: Term-based detection results
        """
        text_lower = text.lower()
        terms_found = []
        
        for term in self.litigation_terms:
            if term.lower() in text_lower:
                terms_found.append(term)
                
        return {
            "has_litigation_terms": len(terms_found) > 0,
            "terms_found": terms_found
        }
        
    def _convert_term_results_to_full_analysis(self, term_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert term-based results to a full analysis format
        
        Args:
            term_results: Term-based detection results
            
        Returns:
            Dict: Full analysis results
        """
        is_litigation = term_results["has_litigation_terms"]
        terms = term_results["terms_found"]
        
        risk_level = "none"
        if len(terms) > 3:
            risk_level = "high"
        elif len(terms) > 1:
            risk_level = "medium"
        elif len(terms) > 0:
            risk_level = "low"
            
        summary = "No litigation indicators found."
        if is_litigation:
            summary = f"Litigation terms detected: {', '.join(terms)}"
            
        return {
            "is_litigation_related": is_litigation,
            "confidence": 0.8,  # Lower confidence for term-based analysis
            "litigation_terms_found": terms,
            "legal_categories": [],  # Cannot determine categories with term-based analysis
            "summary": summary,
            "risk_level": risk_level
        }
        
    def batch_analyze_documents(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple documents for litigation indicators
        
        Args:
            documents: List of document dicts, each containing 'text' and optional 'name'/'metadata'
            
        Returns:
            List[Dict]: List of analysis results for each document
        """
        results = []
        
        for doc in documents:
            text = doc.get('text', '')
            name = doc.get('name', None)
            metadata = doc.get('metadata', None)
            
            analysis = self.analyze_document(text, name, metadata)
            results.append({
                'document': doc,
                'analysis': analysis
            })
            
        return results