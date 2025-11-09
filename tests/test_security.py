# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.

# Unit tests for security functions, encryption, hashing, sanitization, validation, and fail-secure design.

import os
import pytest
from cryptography.fernet import Fernet
import hmac
import hashlib
from tests.test_utils import assert_encrypted_data, assert_search_hashes_exist

# Test that encryption key is configured.
def test_encryption_key_available(): # (Anthropic, 2025)
    assert 'ENCRYPTION_KEY' in os.environ
    key = os.environ['ENCRYPTION_KEY']
    assert key is not None
    # Verify it's a valid Fernet key by trying to create a cipher.
    try:
        from cryptography.fernet import Fernet
        Fernet(key.encode())
    except Exception as e:
        pytest.fail(f"ENCRYPTION_KEY is not a valid Fernet key: {e}")

# Test Fernet encryption and decryption cycle.
def test_fernet_encryption_decryption(): # (Anthropic, 2025)
    key = os.environ['ENCRYPTION_KEY'].encode()
    cipher = Fernet(key)
    
    test_data = b"sensitive_health_data"
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)
    
    assert decrypted == test_data
    assert encrypted != test_data

# Test that HMAC hashes are deterministic (same input = same output).
def test_hmac_hash_deterministic():     # (Anthropic, 2025)
    key = os.environ['ENCRYPTION_KEY'].encode()
    
    hash1 = hmac.new(key, b"stroke:1", hashlib.sha256).hexdigest()
    hash2 = hmac.new(key, b"stroke:1", hashlib.sha256).hexdigest()
    assert hash1 == hash2
    
    hash3 = hmac.new(key, b"stroke:0", hashlib.sha256).hexdigest()
    assert hash1 != hash3

# Test that field name is included in hash to prevent collisions.
def test_hmac_hash_field_specific(): # (Anthropic, 2025)
    key = os.environ['ENCRYPTION_KEY'].encode()
    
    hash_stroke = hmac.new(key, b"stroke:1", hashlib.sha256).hexdigest()
    hash_hypertension = hmac.new(key, b"hypertension:1", hashlib.sha256).hexdigest()
    assert hash_stroke != hash_hypertension

 # (Anthropic, 2025)
@pytest.mark.parametrize("password", [
    "SecurePass123!@#",
    "MyP@ssw0rd2024!",
    "Str0ng!Passw0rd",
    "C0mpl3x&Secure!"
])

# Test that strong passwords pass validation.
def test_password_strength_validation_strong(password): # (Anthropic, 2025)
    from app.security import validate_password_strength
    
    valid, msg = validate_password_strength(password)
    assert valid == True, f"Password '{password}' should be valid"

 # (Anthropic, 2025)
@pytest.mark.parametrize("password,reason", [
    ("short", "Too short"),
    ("nouppercase123!", "No uppercase"),
    ("NOLOWERCASE123!", "No lowercase"),
    ("NoNumbers!", "No numbers"),
    ("NoSpecialChar123", "No special characters"),
    ("password123!", "Common password"),
])

# Test that weak passwords fail validation.
def test_password_strength_validation_weak(password, reason): # (Anthropic, 2025)
    from app.security import validate_password_strength
    
    valid, msg = validate_password_strength(password)
    assert valid == False, f"Password '{password}' should be invalid ({reason})"
    assert msg is not None

 # (Anthropic, 2025)
@pytest.mark.parametrize("dangerous", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "javascript:alert(1)",
    "<svg onload=alert('XSS')>",
])

# Test that XSS attacks are prevented.
def test_xss_sanitization(dangerous): # (Anthropic, 2025)
    from app.security import sanitize_input
    
    clean = sanitize_input(dangerous)
    assert clean is not None
    assert "<script>" not in clean.lower()
    assert "javascript:" not in clean.lower()
    assert "onerror" not in clean.lower()
    assert "onload" not in clean.lower()

 # (Anthropic, 2025)
@pytest.mark.parametrize("safe", [
    "Normal text",
    "Text with numbers 123",
    "Email: test@example.com",
    "Age: 45",
])

# Test that safe text is preserved during sanitization.
def test_sanitization_preserves_safe_text(safe): # (Anthropic, 2025)
    from app.security import sanitize_input
    
    clean = sanitize_input(safe)
    assert clean is not None
    assert len(clean) > 0
    assert clean == safe, "Safe text should be preserved unchanged"

# Test validation of valid patient data.
def test_patient_data_validation_valid(sample_patient_data): # (Anthropic, 2025)
    from app.security import validate_patient_data
    
    is_valid, errors = validate_patient_data(sample_patient_data)
    assert is_valid == True
    assert len(errors) == 0

 # (Anthropic, 2025)
@pytest.mark.parametrize("invalid_field,invalid_value", [
    ('age', 150),
    ('gender', 'Invalid'),
])

# Test validation catches invalid data.
def test_patient_data_validation_invalid(sample_patient_data, invalid_field, invalid_value): # (Anthropic, 2025)
    from app.security import validate_patient_data
    
    invalid_data = {**sample_patient_data, invalid_field: invalid_value}
    is_valid, errors = validate_patient_data(invalid_data)
    assert is_valid == False
    assert invalid_field in errors

# Test patient record encryption with search hashes.
def test_encrypt_patient_record(app_context, sample_patient_data): # (Anthropic, 2025)
    from app.security import encrypt_patient_record, ENCRYPTED_FIELDS, SEARCHABLE_ENCRYPTED_FIELDS
    
    encrypted = encrypt_patient_record(sample_patient_data)
    
    assert_encrypted_data(encrypted, sample_patient_data, ENCRYPTED_FIELDS)
    assert_search_hashes_exist(encrypted, SEARCHABLE_ENCRYPTED_FIELDS)

# Test patient record decryption.
def test_decrypt_patient_record(app_context, sample_patient_data): # (Anthropic, 2025)
    from app.security import encrypt_patient_record, decrypt_patient_record
    
    encrypted = encrypt_patient_record(sample_patient_data)
    decrypted = decrypt_patient_record(encrypted)
    
    assert decrypted['stroke'] == sample_patient_data['stroke']
    assert decrypted['hypertension'] == sample_patient_data['hypertension']
    assert decrypted['heart_disease'] == sample_patient_data['heart_disease']
    assert decrypted['smoking_status'] == sample_patient_data['smoking_status']
    assert abs(decrypted['avg_glucose_level'] - sample_patient_data['avg_glucose_level']) < 0.01
    
    assert 'stroke_search' not in decrypted
    assert 'hypertension_search' not in decrypted

# Test that encryption fails securely without key.
def test_fail_secure_encrypt_without_key(app): # (Anthropic, 2025)
    from app.security import encrypt_field, EncryptionError
    
    original_key = os.environ.get('ENCRYPTION_KEY')
    original_config_key = app.config.get('ENCRYPTION_KEY')
    
    try:
        if 'ENCRYPTION_KEY' in os.environ:
            del os.environ['ENCRYPTION_KEY']
        app.config['ENCRYPTION_KEY'] = None
        
        with app.app_context():
            # Should raise EncryptionError when key is missing.
            with pytest.raises(EncryptionError):
                encrypt_field("test_data")
    finally:
        if original_key:
            os.environ['ENCRYPTION_KEY'] = original_key
        if original_config_key:
            app.config['ENCRYPTION_KEY'] = original_config_key

# Test search hash generation function.
def test_generate_search_hash_function(app_context): # (Anthropic, 2025)
    from app.security import generate_search_hash
    
    hash1 = generate_search_hash('1', 'stroke')
    assert isinstance(hash1, str)
    assert len(hash1) == 64
    
    hash2 = generate_search_hash('1', 'stroke')
    assert hash1 == hash2
    
    hash3 = generate_search_hash('0', 'stroke')
    assert hash1 != hash3
    
    hash4 = generate_search_hash('1', 'hypertension')
    assert hash1 != hash4

#Test encryption and decryption with edge case values (None, empty string, zero).
@pytest.mark.parametrize("value", [None, "", 0])
def test_encryption_with_edge_cases(app_context, value): # (Anthropic, 2025)
    from app.security import encrypt_field, decrypt_field
    
    if value is None:
        encrypted = encrypt_field(value)
        assert encrypted is None
        decrypted = decrypt_field(value)
        assert decrypted is None
    else:
        encrypted = encrypt_field(value)
        assert encrypted is not None, f"Value {value} should be encrypted"
        decrypted = decrypt_field(encrypted)
        assert str(decrypted) == str(value), f"Value {value} should decrypt correctly"

# Test batch decryption of multiple records.
def test_batch_decryption(app_context): # (Anthropic, 2025)
    from app.security import encrypt_patient_record, decrypt_patient_records_batch
    
    records = [
        {'stroke': 1, 'hypertension': 0, 'heart_disease': 1},
        {'stroke': 0, 'hypertension': 1, 'heart_disease': 0},
        {'stroke': 1, 'hypertension': 1, 'heart_disease': 1},
    ]
    
    encrypted_records = [encrypt_patient_record(r) for r in records]
    decrypted_records = decrypt_patient_records_batch(encrypted_records)
    
    assert len(decrypted_records) == len(records)
    
    for original, decrypted in zip(records, decrypted_records):
        assert decrypted['stroke'] == original['stroke']
        assert decrypted['hypertension'] == original['hypertension']
        assert decrypted['heart_disease'] == original['heart_disease']

