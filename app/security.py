# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.

# This is the Security utilities module. Providing input sanitization, validation functions and hybrid searchable encryption using Fernet encryption for data security (non-deterministic) and "Hash-based Message Authentication Code (HMAC)" for query searches. Additionally, utilising a "Fail-secure" design by refusing to operate if encryption is unavailable.
import bleach
from cryptography.fernet import Fernet
from flask import current_app
import re
import hmac
import hashlib

# Raised when encryption or decryption operations fail.
class EncryptionError(Exception): # (Anthropic, 2025)
    pass
class DecryptionError(Exception): # (Anthropic, 2025)
    pass

# Get Fernet cipher for encryption/decryption and return none if not configured.
def get_cipher(): # (Anthropic, 2025)
    key = current_app.config.get('ENCRYPTION_KEY')
    if key:
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)
    return None

# Get HMAC key for searchable hashing and uses the same key as Fernet for simplicity.
def get_hmac_key(): # (Anthropic, 2025)
    key = current_app.config.get('ENCRYPTION_KEY')
    if not key:
        return None
    
    if isinstance(key, str):
        key = key.encode()
    return key

# Generate deterministic HMAC-based hash for searching encrypted fields, same value + field_name always produces same hash.
def generate_search_hash(value, field_name): # (Anthropic, 2025)
    if value is None:
        return None
    
    hmac_key = get_hmac_key()
    if not hmac_key:
        raise EncryptionError("HMAC key not configured. Cannot generate search hash.")
    
    try:
        # Convert value to string for consistent hashing.
        value_str = str(value)
        # Include field name to prevent hash collisions across fields.
        message = f"{field_name}:{value_str}".encode()
        
        search_hash = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
        return search_hash
    
    except Exception as e:
        current_app.logger.error(f"Search hash generation error: {e}")
        raise EncryptionError(f"Failed to generate search hash: {e}")

# Encrypt sensitive data using Fernet.
def encrypt_field(data): # (Anthropic, 2025)
    if data is None:
        return None
    
    cipher = get_cipher()
    if not cipher:
        raise EncryptionError("Encryption key not configured. Cannot encrypt sensitive data.")
    
    try:
        # Convert non-string, non-bytes data to string first.
        if not isinstance(data, (str, bytes)):
            data = str(data)
        
        # Then convert string to bytes.
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = cipher.encrypt(data)
        return encrypted.decode()
    
    except Exception as e:
        current_app.logger.error(f"Encryption error: {e}")
        raise EncryptionError(f"Failed to encrypt data: {e}")
    
# Decrypt sensitive data using Fernet and error if decryption fails.
def decrypt_field(encrypted_data): # (Anthropic, 2025)
    if encrypted_data is None:
        return None
    
    cipher = get_cipher()
    if not cipher:
        current_app.logger.error("Decryption attempted without encryption key")
        raise EncryptionError("Encryption key not configured")
    
    try:
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode()
    
    except Exception as e:
        current_app.logger.error(f"Decryption error: {e}")
        # Raise exception for tampered/invalid data (fail-secure)
        raise DecryptionError(f"Failed to decrypt data: {e}") from e

# Sanitise user input to prevent "Cross site scripting" (XSS) attacks. XSS is a common web vulnerability where attackers inject malicious scripts into web page content, ususally using HTML/JavaScript.
def sanitize_input(text, strip_tags=True): # (Anthropic, 2025)
    if text is None:
        return None
    
    if strip_tags:
        # Remove all HTML tags
        cleaned = bleach.clean(text, tags=[], strip=True)
    else:
        # Allow only safe tags
        allowed_tags = ['p', 'br', 'strong', 'em', 'u']
        cleaned = bleach.clean(text, tags=allowed_tags, strip=True)
    
    # Remove dangerous protocols and event handlers.
    dangerous_patterns = [
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'on\w+\s*=',  # Event handlers like onclick, onerror, onload.
    ]
    
    for pattern in dangerous_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    return cleaned

# Validate the password so it meets the security requirements.
def validate_password_strength(password): # (Anthropic, 2025)
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
    
    # Check for common weak passwords.
    common_passwords = [
        'password123!', 'Password123!', 'Welcome123!',
        'Admin123456!', 'Qwerty123456!'
    ]
    if password in common_passwords:
        return False, "This password is too common. Please choose a more unique password."
    return True, None

# Validate patient records data before insertion or update into the database.
def validate_patient_data(data): # (Anthropic, 2025)
    errors = {}
    # Validate age.
    if 'age' in data:
        try:
            age = float(data['age'])
            if age < 0 or age > 120:
                errors['age'] = "Age must be between 0 and 120."
                
        except (ValueError, TypeError):
            errors['age'] = "Age must be a valid number."
    
    # Validate gender.
    if 'gender' in data:
        valid_genders = ['Male', 'Female', 'Other']
        if data['gender'] not in valid_genders:
            errors['gender'] = f"Gender must be one of: {', '.join(valid_genders)}."
    
    # Validate hypertension. 
    if 'hypertension' in data:
        if data['hypertension'] not in [0, 1, '0', '1']:
            errors['hypertension'] = "Hypertension must be 0 or 1."
    
    # Validate heart_disease. 
    if 'heart_disease' in data:
        if data['heart_disease'] not in [0, 1, '0', '1']:
            errors['heart_disease'] = "Heart disease must be 0 or 1."
    
    # Validate average glucose level.
    if 'avg_glucose_level' in data:
        try:
            glucose = float(data['avg_glucose_level'])
            if glucose < 0 or glucose > 500:
                errors['avg_glucose_level'] = "Glucose level must be between 0 and 500."
                
        except (ValueError, TypeError):
            errors['avg_glucose_level'] = "Glucose level must be a valid number."
    
    # Validate Body mass index (BMI).
    if 'bmi' in data:
        if data['bmi'] and data['bmi'] != 'N/A':
            try:
                bmi = float(data['bmi'])
                if bmi < 10 or bmi > 100:
                    errors['bmi'] = "BMI must be between 10 and 100."
                    
            except (ValueError, TypeError):
                errors['bmi'] = "BMI must be a valid number or 'N/A'."
    
    # Validate stroke.
    if 'stroke' in data:
        if data['stroke'] not in [0, 1, '0', '1']:
            errors['stroke'] = "Stroke must be 0 or 1."
    return len(errors) == 0, errors

# Fields that should be encrypted for "General Data Protection Regulation" (GDPR), and "ISO 27001" (International Organization for Standardization) compliance, since they are "Protected Health Information" (PHI) and "Personally Identifiable Information" (PII) fields.
ENCRYPTED_FIELDS = [
    'id',
    'avg_glucose_level',
    'bmi',
    'smoking_status',
    'stroke',
    'hypertension',
    'heart_disease'
]

# Fields that should have searchable hashes (subset or all of ENCRYPTED_FIELDS).
SEARCHABLE_ENCRYPTED_FIELDS = [
    'id',  
    'smoking_status',
    'stroke',
    'hypertension',
    'heart_disease'
]

# Hybrid encryption function for patient records.
def encrypt_patient_record(record): # (Anthropic, 2025)
    encrypted_record = record.copy()
    
    for field in ENCRYPTED_FIELDS:
        if field in encrypted_record and encrypted_record[field] is not None:
            # Convert to string before encryption.
            value_str = str(encrypted_record[field])
            
            # Encrypt the actual value (random, secure).
            encrypted_record[field] = encrypt_field(value_str)
            
            # Generate searchable hash for queryable fields.
            if field in SEARCHABLE_ENCRYPTED_FIELDS:
                search_field_name = f"{field}_search"
                encrypted_record[search_field_name] = generate_search_hash(value_str, field)
    return encrypted_record

# Decrypt sensitive fields in a patient record and removes search hash fields from display.
def decrypt_patient_record(record): # (Anthropic, 2025)
    decrypted_record = record.copy()
    
    for field in ENCRYPTED_FIELDS:
        if field in decrypted_record and decrypted_record[field] is not None:
            decrypted_value = decrypt_field(decrypted_record[field])
            
            # Convert back to appropriate type.
            if field in ['stroke', 'hypertension', 'heart_disease']:
                try:
                    # Handle decryption errors.
                    if decrypted_value is not None and isinstance(decrypted_value, str) and decrypted_value.startswith('['):
                        decrypted_record[field] = decrypted_value  # Show error.
                    else:
                        decrypted_record[field] = int(decrypted_value) if decrypted_value is not None else 0
                        
                except (ValueError, TypeError, AttributeError):
                    current_app.logger.error(f"Error converting {field} to int: {decrypted_value}")
                    decrypted_record[field] = 0
                    
            elif field == 'avg_glucose_level':
                try:
                    if decrypted_value is not None and isinstance(decrypted_value, str) and decrypted_value.startswith('['):
                        decrypted_record[field] = decrypted_value  # Show error.
                    else:
                        decrypted_record[field] = float(decrypted_value) if decrypted_value is not None else 0.0
                        
                except (ValueError, TypeError):
                    current_app.logger.error(f"Error converting {field} to float: {decrypted_value}")
                    decrypted_record[field] = 0.0
            else:
                # Keep as a string for bmi and smoking_status.
                decrypted_record[field] = decrypted_value
        
        # Remove search hash fields from display (internal use only).
        search_field_name = f"{field}_search"
        if search_field_name in decrypted_record:
            del decrypted_record[search_field_name]
    return decrypted_record

# Decrypt multiple patient records efficiently and returns a list of the decrypted patient records.
def decrypt_patient_records_batch(records): # (Anthropic, 2025)
    return [decrypt_patient_record(record) for record in records]

# Creates audit log entries.
def log_audit(user_id, action, table_name, record_id=None, ip_address=None, user_agent=None, details=None): # (Anthropic, 2025)
    from app.models import AuditLog
    from app import db
    import json
    
    try:
        # Convert details to JSON string if dict.
        if isinstance(details, dict):
            details = json.dumps(details)
        
        log = AuditLog()
        log.user_id = user_id
        log.action = action
        log.table_name = table_name
        log.record_id = str(record_id) if record_id else None
        log.ip_address = ip_address
        log.user_agent = user_agent
        log.details = details
        db.session.add(log)
        db.session.commit()
        
    except Exception as e:
        current_app.logger.error(f"Audit logging error: {e}")
        db.session.rollback()

