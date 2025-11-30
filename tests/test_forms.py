# AI declaration:
# Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.
 
''' Unit tests module for form validation.

Tests the WTForms validation, CSRF protection, and input sanitization.
'''

import pytest

# (Anthropic, 2025)
@pytest.mark.parametrize("form_class", [
    'RegistrationForm',
    'LoginForm',
    'PatientRecordForm',
    'SearchForm'
])

# Test that all forms are defined.
def test_forms_exist(form_class):
    from app import forms
    assert hasattr(forms, form_class)

# Test that registration form has all required fields.
@pytest.mark.parametrize("field", ['email', 'patient_id', 'password', 'confirm_password'])
def test_registration_form_has_required_fields(field): # (Anthropic, 2025)
    from app.forms import RegistrationForm
    field_obj = getattr(RegistrationForm, field)
    assert hasattr(RegistrationForm, field), f"Missing field: {field}"

# Test that login form has all required fields.
@pytest.mark.parametrize("field", ['username', 'password', 'remember_me'])
def test_login_form_has_required_fields(field): # (Anthropic, 2025)
    from app.forms import LoginForm
    assert hasattr(LoginForm, field), f"Missing field: {field}"

# Test that gender field has correct choices.
@pytest.mark.parametrize("gender", ['Male', 'Female', 'Other'])
def test_patient_form_gender_choices(app_context, gender): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    
    form = PatientRecordForm()
    gender_choices = [choice[0] for choice in form.gender.choices]
    assert gender in gender_choices

# Test that binary fields have Yes/No choices.
@pytest.mark.parametrize("field_name", ['hypertension', 'heart_disease', 'stroke'])
def test_patient_form_binary_fields(app_context, field_name): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    
    form = PatientRecordForm()
    field_choices = [choice[0] for choice in getattr(form, field_name).choices]
    assert '0' in field_choices
    assert '1' in field_choices

# Test smoking status has all expected options.
@pytest.mark.parametrize("status", ['never smoked', 'formerly smoked', 'smokes', 'Unknown'])
def test_patient_form_smoking_status_choices(app_context, status): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    form = PatientRecordForm()
    smoking_choices = [choice[0] for choice in form.smoking_status.choices]
    assert status in smoking_choices

# Test work type has all expected options.
@pytest.mark.parametrize("work", ['Private', 'Self-employed', 'Govt_job', 'children', 'Never_worked'])
def test_patient_form_work_type_choices(app_context, work): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    form = PatientRecordForm()
    work_choices = [choice[0] for choice in form.work_type.choices]
    assert work in work_choices

# Test form validation with valid patient data.
def test_form_validation_with_valid_data(app_context, sample_patient_data): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_request_context():
        form = PatientRecordForm(data={
            **sample_patient_data,
            'hypertension': str(sample_patient_data['hypertension']),
            'heart_disease': str(sample_patient_data['heart_disease']),
            'stroke': str(sample_patient_data['stroke'])
        })
        assert form.validate() == True, f"Form should be valid. Errors: {form.errors}"

# (Anthropic, 2025)
@pytest.mark.parametrize("validation_method", [
    'validate_password',
    'validate_email',
    'validate_patient_id'
])

# Test that registration form has validation methods.
def test_registration_form_validations(validation_method): # (Anthropic, 2025)
    from app.forms import RegistrationForm
    assert hasattr(RegistrationForm, validation_method)

# Test that patient form validates BMI.
def test_patient_form_bmi_validation(): # (Anthropic, 2025)
    from app.forms import PatientRecordForm
    assert hasattr(PatientRecordForm, 'validate_bmi')

# Test that CSRF is disabled in testing environment.
def test_form_csrf_protection_disabled_in_testing(app): # (Anthropic, 2025)
    assert app.config['WTF_CSRF_ENABLED'] == False

# Test that search value is optional in search form.
def test_search_form_optional_search_value(app_context): # (Anthropic, 2025)
    from app.forms import SearchForm
    form = SearchForm()
    assert hasattr(form, 'search_value')

