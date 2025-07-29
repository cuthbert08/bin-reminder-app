# app.py

import os
import json
from flask import Flask, jsonify, request
from upstash_redis import Redis
from datetime import datetime, date, timedelta
import uuid
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

# --- INITIALIZATION ---

app = Flask(__name__)
CORS(app)

# Initialize Redis Client with the correct Vercel KV environment variables
redis = Redis(
    url=os.environ.get('KV_REST_API_URL'),
    token=os.environ.get('KV_REST_API_TOKEN')
)

# Secret key for signing JWT tokens. Should be a strong, random string.
# For security, this should be set as an environment variable in Vercel.
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key-for-testing')

# --- IMPORT SENDING FUNCTIONS ---
# (send_whatsapp.py, send_sms.py, send_email.py remain the same, but send_email_message will now be passed HTML)
from send_whatsapp import send_whatsapp_message
from send_sms import send_sms_message
from send_email import send_email_message


# --- SECURITY & AUTHENTICATION ---

def token_required(f):
    """Decorator to protect routes and check for valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            admins_json = redis.get('admins')
            admins = json.loads(admins_json) if admins_json else []
            current_user = next((admin for admin in admins if admin['id'] == data['id']), None)
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(role):
    """Decorator to check if a user has the required role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user['role'] not in role:
                return jsonify({'message': 'Permission denied!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Handles admin login."""
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401

    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []
    user = next((admin for admin in admins if admin['email'] == auth['email']), None)

    if not user or not check_password_hash(user['password_hash'], auth['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'id': user['id'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, JWT_SECRET_KEY, "HS256")

    return jsonify({'token': token, 'user': {'email': user['email'], 'role': user['role']}})


# --- HELPER FUNCTIONS ---

def add_log_entry(message):
    """Adds a new entry to the logs in the database."""
    # ... (code remains the same)
    pass # Placeholder for brevity

# --- ONE-TIME SETUP ---

@app.route('/api/initialize-data')
def initialize_data():
    """
    One-time setup to initialize the database with all necessary data structures
    and create the first superuser.
    """
    try:
        # --- Initialize Admins ---
        superuser_password_hash = generate_password_hash("Mudharaa@1", method='pbkdf2:sha256')
        admins = [{
            "id": str(uuid.uuid4()),
            "email": "cutberndikudze@gmail.com",
            "password_hash": superuser_password_hash,
            "role": "superuser"
        }]
        redis.set('admins', json.dumps(admins))

        # --- Initialize Residents ---
        residents_to_add = [{
            "id": str(uuid.uuid4()),
            "flat_number": "Flat 1",
            "name": "Cuthbert Ndikudze",
            "contact": { "whatsapp": "+27621841122", "sms": "+27621841122", "email": "cutbertndikudze@gmail.com" },
            "notes": "Initial resident."
        }]
        redis.set('flats', json.dumps(residents_to_add))

        # --- Initialize System Settings ---
        settings = {
            "owner_name": "Property Owner",
            "owner_contact_number": os.environ.get('OWNER_CONTACT_NUMBER', ''), # Store owner's number in env vars
            "owner_contact_email": os.environ.get('OWNER_CONTACT_EMAIL', ''), # Store owner's email in env vars
            "owner_contact_whatsapp": os.environ.get('OWNER_CONTACT_WHATSAPP', ''),
            "report_issue_link": "https://your-frontend-url/report", # Default link
            "reminder_template": "Hi {first_name}! {flat_number}\nJust a friendly reminder that it's your turn to take out the dustbin today. Thank you!",
            "announcement_template": "Hi {first_name},\n{message}"
        }
        redis.set('settings', json.dumps(settings))

        # --- Initialize Other Data Structures ---
        redis.set('current_turn_index', 0)
        redis.set('last_reminder_date', "2000-01-01")
        redis.set('reminders_paused', False)
        redis.set('logs', json.dumps([]))
        redis.set('issues', json.dumps([]))
        redis.set('polls', json.dumps([]))
        redis.set('documents', json.dumps([]))
        
        add_log_entry("System initialized successfully.")
        return "Database has been initialized successfully."
    except Exception as e:
        return f"An error occurred during setup: {e}", 500


# --- PROTECTED ADMIN ROUTES ---

# (All previous routes like /api/residents, /api/dashboard, etc., would now have the @token_required decorator)
# Example:
@app.route('/api/dashboard')
@token_required
def get_dashboard_info(current_user):
    # ... (logic remains the same)
    pass # Placeholder for brevity


# --- NEW FEATURE: ISSUE TRACKER ---

@app.route('/api/issues', methods=['POST'])
def report_issue():
    """Public endpoint for residents to report issues."""
    data = request.get_json()
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    
    new_issue = {
        "id": str(uuid.uuid4()),
        "reported_by": data.get("name"),
        "flat_number": data.get("flat_number"),
        "description": data.get("description"),
        "image_url": data.get("image_url"), # Frontend will provide this after uploading to blob storage
        "status": "Reported",
        "timestamp": datetime.utcnow().isoformat()
    }
    issues.insert(0, new_issue)
    redis.set('issues', json.dumps(issues))
    
    # --- Notify the Owner ---
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}
    owner_whatsapp = settings.get('owner_contact_whatsapp')
    owner_sms = settings.get('owner_contact_number')
    owner_email = settings.get('owner_contact_email')
    
    notification_message = f"New Issue Reported by {new_issue['reported_by']} ({new_issue['flat_number']}):\n{new_issue['description']}"
    if new_issue['image_url']:
        notification_message += f"\nImage: {new_issue['image_url']}"
        
    if owner_whatsapp: send_whatsapp_message(owner_whatsapp, notification_message)
    if owner_sms: send_sms_message(owner_sms, notification_message)
    if owner_email: send_email_message(owner_email, "New Maintenance Issue Reported", notification_message)
    
    return jsonify({"message": "Issue reported successfully."}), 201

@app.route('/api/issues', methods=['GET'])
@token_required
def get_issues(current_user):
    """Admin endpoint to get all issues."""
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    return jsonify(issues)

# ... (Other new feature endpoints for Polls, Documents, and Settings would be added here) ...

# --- HTML EMAIL EXAMPLE ---
# (This would be integrated into the main trigger_reminder function)

def create_html_email_body(first_name, flat_number, settings):
    """Generates a professional HTML email."""
    template = settings.get('reminder_template', '')
    # Basic templating - a real app might use a library like Jinja2
    message_body = template.replace("{first_name}", first_name).replace("{flat_number}", flat_number)
    
    report_link = settings.get('report_issue_link', '#')
    owner_name = settings.get('owner_name', 'Admin')
    owner_number = settings.get('owner_contact_number', '')

    html = f"""
    <html>
        <body style="font-family: sans-serif; margin: 20px;">
            <h2>Bin Duty Reminder</h2>
            <p>{message_body}</p>
            <p>If you have any issues or enquiries, please contact {owner_name} at {owner_number}.</p>
            <a href="{report_link}" style="display: inline-block; padding: 10px 15px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">
                Report a Maintenance Issue
            </a>
            <hr style="margin-top: 20px;">
            <p style="font-size: 12px; color: #888;">This is an automated message from your community management system.</p>
        </body>
    </html>
    """
    return html

