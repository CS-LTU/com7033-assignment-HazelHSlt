# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artifact. Mostly for syntax, logic and error checking with ChatGPT and Clude Sonnet 4.5 used as the models.

# Configuration module for Flask application.

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config: # (Anthropic, 2025)
    #Base configuration class with common settings.
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    
    # SQLAlchemy Configuration.
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') or 'sqlite:///users.db'
    ADMIN_DATABASE_URI = os.environ.get('ADMIN_DATABASE_URI') or 'sqlite:///admin.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # MongoDB Configuration.
    MONGODB_URI = os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017/?tls=false'
    MONGODB_DB = os.environ.get('MONGODB_DB') or 'healthcare_db'
    
    # Session Configuration.
    SESSION_COOKIE_SECURE = True  # Ensure HTTPS only.
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access.
    SESSION_COOKIE_SAMESITE = 'Lax'  # Used for CSRF protection (Cross-Site Request Forgery).
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # Adds a 30-minute timeout.
    
    # WTF Forms for CSRF Protection.
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # Set no time limit for the CSRF tokens.
    
    # Bcrypt.
    BCRYPT_LOG_ROUNDS = 12  # "Computational cost" or "work factor" for password hashing. The higher the number, the more secure the hashing, but also the more computationally expensive, "12" with perform 2^12 (4096) rounds of hashing. 
    
    # Flask-Limiter, used for rate limiting to prevent brute-force attacks and "Denial of Service" (DoS) attacks by limiting the number of requests a user can make in a given time period.
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL') or 'memory://'
    RATELIMIT_HEADERS_ENABLED = True
    
    # Encryption.
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    # Flask-Talisman, used for Security Headers. This prevents various types of attacks such as XSS (Cross-Site Scripting), Clickjacking, and other code injection attacks by setting appropriate HTTP headers, redirecting any insecure HTTP requests to HTTPS.
    TALISMAN_FORCE_HTTPS = False  # This should be set to True, when running in production.
    TALISMAN_STRICT_TRANSPORT_SECURITY = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE = 31536000  # 1 year
    
    # Content Security Policy. 
    TALISMAN_CONTENT_SECURITY_POLICY = { # (Anthropic, 2025)
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",  # Allow inline styles for Bootstrap.
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
    }

    # HMAC key for patient_id hashing, used for duplicate checking during registration.
    # In production, store this securely in environment variable.
    PATIENT_ID_HMAC_KEY = os.environ.get('PATIENT_ID_HMAC_KEY', 'default-dev-key-change-in-production')

# Development environment configuration.
class DevelopmentConfig(Config): # (Anthropic, 2025)
    DEBUG = True
    TESTING = False
    TALISMAN_FORCE_HTTPS = False
    SESSION_COOKIE_SECURE = True 

# Production environment configuration.
class ProductionConfig(Config): # (Anthropic, 2025)
    DEBUG = False
    TESTING = False
    TALISMAN_FORCE_HTTPS = True
    SESSION_COOKIE_SECURE = True

# Testing environment configuration.
class TestingConfig(Config): # (Anthropic, 2025)
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = { # (Anthropic, 2025)
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

