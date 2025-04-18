"""
Configuration settings for Inbox Exodus application
"""
import os
from dataclasses import dataclass

@dataclass
class Config:
    """Configuration settings for the application"""
    # OpenAI API settings
    openai_api_key: str = os.environ.get("OPENAI_API_KEY")
    openai_model: str = "gpt-4o"  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024

    # Microsoft 365 API settings
    ms_client_id: str = os.environ.get("MS_CLIENT_ID")
    ms_client_secret: str = os.environ.get("MS_CLIENT_SECRET")
    ms_tenant_id: str = os.environ.get("MS_TENANT_ID")
    ms_redirect_uri: str = os.environ.get("MS_REDIRECT_URI", "http://localhost:8000/callback")
    
    # Google API settings
    google_client_id: str = os.environ.get("GOOGLE_CLIENT_ID")
    google_client_secret: str = os.environ.get("GOOGLE_CLIENT_SECRET")
    google_project_id: str = os.environ.get("GOOGLE_PROJECT_ID")
    google_redirect_uri: str = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback")
    
    # Application settings
    temp_dir: str = os.environ.get("TEMP_DIR", "./temp")
    log_dir: str = os.environ.get("LOG_DIR", "./logs")
    
    # Litigation scan settings
    litigation_terms = [
        "ownership dispute", "TRO", "arbitration", "PTG refund", 
        "legal action", "litigation", "lawsuit", "court", "dispute",
        "settlement", "attorney", "counsel", "legal representation",
        "legal proceedings", "claim", "damages", "liability"
    ]
    
    # Base folder structure
    base_folder_structure = {
        "SOURCE_OF_TRUTH": {
            "Legal": {},
            "Rentals": {},
            "EstatePlanning": {},
            "OldEntities": {},
            "Personal": {},
            "Clients": {
                "Stacked": {
                    "Tidbit": {}
                }
            },
            "LITIGATION_HOLD": {}
        }
    }
    
    def __post_init__(self):
        """Validate configuration and create necessary directories"""
        # Create temp and log directories if they don't exist
        for directory in [self.temp_dir, self.log_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
        
        # Validate required API keys
        if not self.openai_api_key:
            print("Warning: OPENAI_API_KEY not set. GPT classification will not work.")
            
        if not all([self.ms_client_id, self.ms_client_secret, self.ms_tenant_id]):
            print("Warning: Microsoft 365 API credentials not set. MS365 extraction will not work.")
            
        if not all([self.google_client_id, self.google_client_secret, self.google_project_id]):
            print("Warning: Google API credentials not set. Google Workspace migration will not work.")
