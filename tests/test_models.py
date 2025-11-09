# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.

# Unit tests for the database models, user and AuditLog models.
import pytest
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from tests.test_utils import create_user, create_audit_log

# Test that User model is defined.
def test_user_model_exists(): # (Anthropic, 2025)
    from app.models import User
    assert User is not None

# Test that AuditLog model is defined.
def test_audit_log_model_exists(): # (Anthropic, 2025)
    from app.models import AuditLog
    assert AuditLog is not None

# (Anthropic, 2025)
@pytest.mark.parametrize("field", [
    'id', 'username', 'email', 'password_hash',
    'created_at', 'last_login', 'is_active', 'role',
    'failed_login_attempts', 'account_locked_until'
])
# Test that User model has all required fields.
def test_user_model_fields(init_database, field): # (Anthropic, 2025)
    from app.models import User
    user = User()
    assert hasattr(user, field), f"Missing field: {field}"

# (Anthropic, 2025)
@pytest.mark.parametrize("field", [
    'id', 'user_id', 'action', 'table_name', 'record_id',
    'ip_address', 'user_agent', 'timestamp', 'details'
])

# Test that AuditLog model has all required fields.
def test_audit_log_model_fields(init_database, field): # (Anthropic, 2025)
    from app.models import AuditLog
    log = AuditLog()
    assert hasattr(log, field), f"Missing field: {field}"

# Test creating a user.
def test_create_user(init_database, bcrypt_instance): # (Anthropic, 2025)
    from app import db
    user = create_user(
        'testuser123',
        'test123@example.com',
        bcrypt_instance.generate_password_hash('TestPass123!').decode('utf-8')
    )
    
    assert user.id is not None
    assert user.username == 'testuser123'
    assert user.email == 'test123@example.com'
    assert user.is_active == True
    assert user.role == 'user'
    assert user.failed_login_attempts == 0

# Test user string representation.
def test_user_repr(test_user): # (Anthropic, 2025)
    assert 'testuser' in repr(test_user)

# Test that new user account is not locked
def test_user_account_not_locked_initially(test_user): # (Anthropic, 2025)
    assert test_user.is_account_locked() == False

# Test incrementing failed login attempts.
def test_user_increment_failed_login(test_user): # (Anthropic, 2025)
    initial_attempts = test_user.failed_login_attempts
    test_user.increment_failed_login()
    assert test_user.failed_login_attempts == initial_attempts + 1

# Test that account locks after 5 failed attempts.
def test_user_account_locks_after_5_failures(init_database, bcrypt_instance): # (Anthropic, 2025)
    from app import db
    user = create_user(
        'locktest',
        'locktest@example.com',
        bcrypt_instance.generate_password_hash('TestPass123!').decode('utf-8')
    )
    
    for i in range(5):
        user.increment_failed_login()
    
    assert user.is_account_locked() == True
    assert user.account_locked_until is not None

# Test resetting failed login attempts.
def test_user_reset_failed_login(test_user): # (Anthropic, 2025)
    test_user.failed_login_attempts = 3
    test_user.reset_failed_login()
    
    assert test_user.failed_login_attempts == 0
    assert test_user.account_locked_until is None

# Test that user has audit_logs relationship.
def test_user_relationships(test_user): # (Anthropic, 2025)
    assert hasattr(test_user, 'audit_logs')

# Test creating an audit log entry.
def test_create_audit_log(init_database, test_user): # (Anthropic, 2025)
    from app import db
    log = create_audit_log(test_user.id, 'CREATE', 'patient_records')
    assert log.id is not None
    assert log.user_id == test_user.id
    assert log.action == 'CREATE'
    assert log.table_name == 'patient_records'
    assert log.timestamp is not None

# Test audit log string representation.
def test_audit_log_repr(init_database, test_user): # (Anthropic, 2025)
    log = create_audit_log(test_user.id, 'READ', 'users')
    repr_str = repr(log)
    assert 'READ' in repr_str
    assert str(test_user.id) in repr_str

# Test that password is hashed, not stored as plaintext.
def test_user_password_not_stored_as_plaintext(test_user): # (Anthropic, 2025)
    assert test_user.password_hash != 'SecurePass123!@#'
    assert test_user.password_hash.startswith('$2b$')

# Test that usernames and emails must be unique.
@pytest.mark.parametrize("unique_field", ['username', 'email'])
def test_user_unique_constraints(init_database, bcrypt_instance, unique_field): # (Anthropic, 2025)
    from app import db
    user1 = create_user(
        'uniqueuser',
        'unique@example.com',
        bcrypt_instance.generate_password_hash('Pass123!').decode('utf-8')
    )
    
    from app.models import User
    user2 = User()
    user2.username = 'uniqueuser' if unique_field == 'username' else 'user2'
    user2.email = 'unique@example.com' if unique_field == 'email' else 'user2@example.com'
    user2.password_hash = bcrypt_instance.generate_password_hash('Pass123!').decode('utf-8')
    db.session.add(user2)
    
    with pytest.raises(IntegrityError):
        db.session.commit()
    
    db.session.rollback()

# Test that user has correct default values.
def test_user_default_values(init_database, bcrypt_instance): # (Anthropic, 2025)
    user = create_user(
        'defaultuser',
        'default@example.com',
        bcrypt_instance.generate_password_hash('Pass123!').decode('utf-8')
    )
    
    assert user.is_active == True
    assert user.role == 'user'
    assert user.failed_login_attempts == 0
    assert user.account_locked_until is None
    assert user.created_at is not None

# Test that audit log has automatic timestamps.
def test_audit_log_default_timestamp(init_database, test_user): # (Anthropic, 2025)
    log = create_audit_log(test_user.id, 'TEST', 'test_table')
    assert log.timestamp is not None
    assert (datetime.utcnow() - log.timestamp).seconds < 60

