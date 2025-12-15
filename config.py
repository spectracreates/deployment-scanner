import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration from environment variables."""
    
    # API Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    OPENAI_BASE_URL = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1')
    LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-3.5-turbo')
    
    # Application Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    UPLOAD_FOLDER = 'uploads'
    REPORT_FOLDER = 'reports'
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {'yaml', 'yml', 'tf', 'dockerfile'}
    
    # Severity Levels
    SEVERITY_CRITICAL = 'CRITICAL'
    SEVERITY_HIGH = 'HIGH'
    SEVERITY_MEDIUM = 'MEDIUM'
    SEVERITY_LOW = 'LOW'
    SEVERITY_INFO = 'INFO'
    
    @staticmethod
    def validate():
        """Validate required configuration."""
        if not Config.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not set in .env file")
        return True