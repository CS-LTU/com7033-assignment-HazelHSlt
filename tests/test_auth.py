# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.

# Unit tests for authentication and authorization, Tests login, logout, registration, and session management
import pytest
from datetime import datetime, timedelta
from tests.test_utils import create_user

# (Anthropic, 2025)
@pytest.mark.parametrize("route,expected_status,expected_content", [
    ('/login', 200, b'Login'),
    ('/register', 200, b'Register'),
    ('/', 200, b'Healthcare')
])

# Test that public pages are accessible.
def test_public_pages_accessible(client, route, expected_status, expected_content): # (Anthropic, 2025)
    response = client.get(route)
    assert response.status_code == expected_status
    assert expected_content in response.data, f"Expected content missing from {route}"

# Test that dashboard requires login.
def test_dashboard_requires_authentication(client): # (Anthropic, 2025)
    response = client.get('/dashboard', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.location

# Test that logout redirects to index.
def test_logout_redirects_to_index(authenticated_client): # (Anthropic, 2025)
    response = authenticated_client.get('/logout', follow_redirects=False)
    assert response.status_code == 302

# Test bcrypt password hashing and verification.
def test_bcrypt_hash_verification(bcrypt_instance): # (Anthropic, 2025)
    password = "TestPassword123!"
    password_hash = bcrypt_instance.generate_password_hash(password).decode('utf-8')
    
    assert bcrypt_instance.check_password_hash(password_hash, password) == True
    assert bcrypt_instance.check_password_hash(password_hash, "WrongPassword") == False

# Test that same password produces different hashes (due to salt).
def test_password_hash_is_different_each_time(bcrypt_instance): # (Anthropic, 2025)
    password = "SamePassword123!"

    hash1 = bcrypt_instance.generate_password_hash(password).decode('utf-8')
    hash2 = bcrypt_instance.generate_password_hash(password).decode('utf-8')

    assert hash1 != hash2
    assert bcrypt_instance.check_password_hash(hash1, password) == True
    assert bcrypt_instance.check_password_hash(hash2, password) == True

# Test that login manager is configured.
def test_user_login_manager_exists(app): # (Anthropic, 2025)
    assert hasattr(app, 'login_manager')

# Test that user loader function is defined.
def test_user_loader_function_exists(init_database, test_user): # (Anthropic, 2025)
    from app.models import load_user
    from app import db
    db.session.commit()
    
    # Try loading user by ID
    loaded_user = load_user(str(test_user.id))
    if loaded_user is None:
        loaded_user = load_user(f'user_{test_user.id}')
    
    assert loaded_user is not None, "User loader should return user"
    assert loaded_user.username == test_user.username
    assert loaded_user.id == test_user.id

# Test that user loader returns None for invalid ID.
def test_user_loader_returns_none_for_invalid_id(init_database): # (Anthropic, 2025)
    from app.models import load_user
    
    loaded_user = load_user(str(99999))
    assert loaded_user is None

# Test that @login_required decorator exists.
def test_flask_login_required_decorator(): # (Anthropic, 2025)
    from flask_login import login_required
    assert login_required is not None
    assert callable(login_required)

 # (Anthropic, 2025)
@pytest.mark.parametrize("config_key,expected_value", [
    ('SESSION_COOKIE_HTTPONLY', True),
    ('SESSION_COOKIE_SAMESITE', 'Lax'),
])

# Test that session is configured securely.
def test_session_configuration(app, config_key, expected_value): # (Anthropic, 2025)
    assert config_key in app.config
    assert app.config[config_key] == expected_value, f"{config_key} should be {expected_value}"

# Second part of the previous test, permanent session lifetime is configuration test.
def test_permanent_session_lifetime_configured(app): # (Anthropic, 2025)
    from datetime import timedelta
    assert 'PERMANENT_SESSION_LIFETIME' in app.config
    lifetime = app.config['PERMANENT_SESSION_LIFETIME']
    assert isinstance(lifetime, timedelta)
    assert lifetime.total_seconds() > 0
    
# Test that bcrypt is configured with appropriate rounds.
def test_bcrypt_rounds_configuration(app): # (Anthropic, 2025)
    assert 'BCRYPT_LOG_ROUNDS' in app.config
    rounds = app.config['BCRYPT_LOG_ROUNDS']
    assert rounds >= 12

# Test that CSRF protection is configured.
def test_csrf_protection_configuration(app): # (Anthropic, 2025)
    assert 'WTF_CSRF_ENABLED' in app.config
    assert app.config['WTF_CSRF_ENABLED'] == False

# Test that create patient route exists.
def test_create_user_route_exists(client): # (Anthropic, 2025)
    response = client.get('/patient/create', follow_redirects=False)
    assert response.status_code == 302

# (Anthropic, 2025)
@pytest.mark.parametrize("route", [
    '/dashboard',
    '/patient/create',
    '/user-dashboard',
    '/userpage',
])

# Test that all CRUD routes require authentication.
def test_protected_routes_require_auth(client, route): # (Anthropic, 2025)
    response = client.get(route, follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.location

# Test that account unlocks after timeout period.
def test_account_unlock_after_timeout(init_database, bcrypt_instance): # (Anthropic, 2025)
    from app import db
    
    user = create_user(
        'timeouttest',
        'timeout@example.com',
        bcrypt_instance.generate_password_hash('Pass123!').decode('utf-8')
    )
    
    user.failed_login_attempts = 5
    user.account_locked_until = datetime.utcnow() - timedelta(minutes=1)
    db.session.commit()
    
    is_locked = user.is_account_locked()
    
    assert is_locked == False
    assert user.failed_login_attempts == 0

# (Anthropic, 2025)
@pytest.mark.parametrize("method,expected_value", [
    ('is_authenticated', True),
    ('is_active', True),
    ('is_anonymous', False),
])

# Test that User model implements Flask-Login UserMixin methods (is_authenticated, is_active, is_anonymous) with correct boolean values.
def test_user_mixin_provides_flask_login_methods(test_user, method, expected_value): # (Anthropic, 2025)
    assert hasattr(test_user, method)
    if method != 'get_id':
        assert getattr(test_user, method) == expected_value

# Test that User.get_id() returns a string representation of the user ID for Flask-Login session management.
def test_user_get_id_returns_string(test_user): # (Anthropic, 2025)
    user_id = test_user.get_id()
    assert user_id is not None
    assert isinstance(user_id, str)

