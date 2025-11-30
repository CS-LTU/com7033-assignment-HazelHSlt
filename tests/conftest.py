# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.

# Pytest configuration and fixtures for records analysis app.
import pytest
import os
import sys
from cryptography.fernet import Fernet

# Add parent directory to path.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set test environment variables before importing app, (Anthropic, 2025).
os.environ['FLASK_ENV'] = 'testing'
os.environ['TESTING'] = 'True'

# Generate test encryption key if not provided,  (Anthropic, 2025).
if 'ENCRYPTION_KEY' not in os.environ:
    test_key = Fernet.generate_key().decode()
    os.environ['ENCRYPTION_KEY'] = test_key

if 'SECRET_KEY' not in os.environ:
    os.environ['SECRET_KEY'] = 'test_secret_key_for_testing_only'

# Set test MongoDB URI to use the test database, (Anthropic, 2025).
if 'MONGODB_URI' not in os.environ:
    os.environ['MONGODB_URI'] = 'mongodb+srv://leedstrinityhazelltu_db_user:OtEtnVn5lGBzDbYb@secureappdb.wgoupdf.mongodb.net/?appName=SecureAppDB'

from app import create_app, db
from app.models import User

# Create application for testing session which is shared across all tests.
@pytest.fixture(scope='session')
def app(): # (Anthropic, 2025)
    app = create_app('testing')
    
    # Additional test configuration with separate in-memory DBs for each bind.
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_BINDS': {
            'admin': 'sqlite:///:memory:'  # Separate in-memory DB for admin.
        },
        'MONGODB_URI': os.environ.get('MONGODB_URI', 'mongodb+srv://leedstrinityhazelltu_db_user:OtEtnVn5lGBzDbYb@secureappdb.wgoupdf.mongodb.net/?appName=SecureAppDB'),
    })
    return app

# Session-wide test database.
@pytest.fixture(scope='session')
def _db(app): # (Anthropic, 2025)
    with app.app_context():
        # Import models to ensure they're registered
        from app.admin_models import AdminUser, AdminAuditLog
        from app.models import User, AuditLog
        
        # Create all tables for both binds
        db.create_all()
        yield db
        db.drop_all()

# Check if MongoDB is available, used for conditional skipping.
@pytest.fixture(scope='session')
def mongodb_available(app): # (Anthropic, 2025)
    with app.app_context():
        try:
            from app import mongo_db
            if mongo_db is None:
                return False
            # Test connection
            mongo_db.client.server_info()
            return True
        except Exception:
            return False

# Session-wide MongoDB connection, only if available.
@pytest.fixture(scope='session')
def _mongodb(app, mongodb_available): # (Anthropic, 2025)
    if not mongodb_available:
        pytest.skip("MongoDB not available - Please check cloud atlas connection settings.")
    
    with app.app_context():
        from app import mongo_db
        yield mongo_db
        # Clean up test database at end of session.
        try:
            mongo_db.client.drop_database('SecureAppDB')
        except Exception:
            pass

# Function-scoped database cleans up after each test, use this in tests that need SQLAlchemy DB.
@pytest.fixture(scope='function')
def init_database(app, _db): # (Anthropic, 2025)
    with app.app_context():
        yield _db
        # Rollback and clean all tables
        _db.session.rollback()
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()

# Function-scoped MongoDB - cleans up after each test. Use this in tests that need MongoDB.
@pytest.fixture(scope='function')
def init_mongodb(app, _mongodb): # (Anthropic, 2025)
    with app.app_context():
        yield _mongodb
        # Clean up all collections
        try:
            for collection_name in _mongodb.list_collection_names():
                _mongodb[collection_name].delete_many({})
        except Exception:
            # If cleanup fails, it's not critical
            pass

# Create test client.
@pytest.fixture(scope='function')
def client(app): # (Anthropic, 2025)
    return app.test_client()

# Create application context.
@pytest.fixture(scope='function')
def app_context(app): # (Anthropic, 2025)
    with app.app_context():
        yield app

# Get bcrypt instance.
@pytest.fixture(scope='function')
def bcrypt_instance(app): # (Anthropic, 2025)
    from flask_bcrypt import Bcrypt
    return Bcrypt(app)

# Create a test user, reusable across tests.
@pytest.fixture(scope='function')
def test_user(init_database, bcrypt_instance): # (Anthropic, 2025)
    user = User()
    user.username = 'testuser'
    user.email = 'test@example.com'
    user.password_hash = bcrypt_instance.generate_password_hash('SecurePass123!@#').decode('utf-8')
    user.role = 'user'
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)
    return user

# Create an admin user for testing.
@pytest.fixture(scope='function')
def admin_user(init_database, bcrypt_instance): # (Anthropic, 2025)
    from app.admin_models import AdminUser
    admin = AdminUser()
    admin.username = 'testadmin'
    admin.password_hash = bcrypt_instance.generate_password_hash('TestAdmin123!').decode('utf-8')
    admin.role = 'admin'
    admin.is_active = True
    db.session.add(admin)
    db.session.commit()
    db.session.refresh(admin)
    return admin

# Create a user for testing.
@pytest.fixture(scope='function')
def standard_user(init_database, bcrypt_instance): # (Anthropic, 2025)
    user = User()
    user.username = 'testuser@example.com'
    user.email = 'testuser@example.com'
    user.password_hash = bcrypt_instance.generate_password_hash('TestUser123!').decode('utf-8')
    user.set_patient_id(12345)
    user.role = 'user'
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)
    return user

# Create an authenticated test client.
@pytest.fixture(scope='function')
def authenticated_client(client, test_user): # (Anthropic, 2025)
    with client:
        with client.session_transaction() as session:
            session['_user_id'] = str(test_user.id)
            session['_fresh'] = True
        yield client

# Provide sample patient data for testing.
@pytest.fixture(scope='function')
def sample_patient_data(): # (Anthropic, 2025)
    return {
        'id': 1,
        'gender': 'Male',
        'age': 45.0,
        'hypertension': 0,
        'heart_disease': 1,
        'ever_married': 'Yes',
        'work_type': 'Private',
        'residence_type': 'Urban',
        'avg_glucose_level': 120.5,
        'bmi': '28.5',
        'smoking_status': 'never smoked',
        'stroke': 0
    }

# Create a mock patient record in MongoDB for testing. Requires MongoDB to be running.
@pytest.fixture(scope='function')
def mock_patient_record(app, init_mongodb, sample_patient_data): # (Anthropic, 2025)
    from app.security import encrypt_patient_record
    
    with app.app_context():
        collection = init_mongodb.patient_records
        patient_data = {**sample_patient_data, 'id': 12345}
        encrypted_data = encrypt_patient_record(patient_data)
        result = collection.insert_one(encrypted_data)
        
        yield result.inserted_id

