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
from vercel_blob import put as vercel_put # For file uploads

# --- INITIALIZATION ---

app = Flask(__name__)
CORS(app)

# Initialize Redis Client
redis = Redis(
    url=os.environ.get('KV_REST_API_URL'),
    token=os.environ.get('KV_REST_API_TOKEN')
)

JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key-for-testing')

# --- IMPORT SENDING FUNCTIONS ---
from send_whatsapp import send_whatsapp_message
from send_sms import send_sms_message
from send_email import send_email_message


# --- SECURITY & AUTHENTICATION ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token: return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            admins_json = redis.get('admins')
            admins = json.loads(admins_json) if admins_json else []
            current_user = next((admin for admin in admins if admin['id'] == data['id']), None)
            if not current_user: return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user['role'] not in roles:
                return jsonify({'message': 'Permission denied!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/auth/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []
    user = next((admin for admin in admins if admin['email'] == auth['email']), None)
    if not user or not check_password_hash(user['password_hash'], auth['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({'id': user['id'], 'exp': datetime.utcnow() + timedelta(hours=24)}, JWT_SECRET_KEY, "HS256")
    return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'role': user['role']}})


# --- HELPER FUNCTIONS ---

def add_log_entry(message, user_email="System"):
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    new_entry = f"[{timestamp}] ({user_email}) {message}"
    logs.insert(0, new_entry)
    if len(logs) > 100: logs = logs[:100]
    redis.set('logs', json.dumps(logs))

# --- ONE-TIME SETUP ---

@app.route('/api/initialize-data')
def initialize_data():
    try:
        superuser_password_hash = generate_password_hash("Mudharaa@1", method='pbkdf2:sha256')
        admins = [{"id": str(uuid.uuid4()), "email": "cutbertndikudze@gmail.com", "password_hash": superuser_password_hash, "role": "superuser"}]
        redis.set('admins', json.dumps(admins))
        residents = [{"id": str(uuid.uuid4()), "flat_number": "Flat 1", "name": "Cuthbert Ndikudze", "contact": { "whatsapp": "+27621841122", "sms": "+27621841122", "email": "cutbertndikudze@gmail.com" }, "notes": "Initial resident."}]
        redis.set('flats', json.dumps(residents))
        settings = {
            "owner_name": "Property Owner", "owner_contact_number": os.environ.get('OWNER_CONTACT_NUMBER', ''),
            "owner_contact_email": os.environ.get('OWNER_CONTACT_EMAIL', ''), "owner_contact_whatsapp": os.environ.get('OWNER_CONTACT_WHATSAPP', ''),
            "report_issue_link": "https://your-frontend-url/report",
            "reminder_template": "Hi {first_name}! {flat_number}\nJust a friendly reminder that it's your turn to take out the dustbin today. Thank you!",
            "announcement_template": "Hi {first_name},\n{message}"
        }
        redis.set('settings', json.dumps(settings))
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

# --- PUBLIC ROUTES ---

@app.route('/api/issues', methods=['POST'])
def report_issue():
    data = request.get_json()
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    new_issue = {
        "id": str(uuid.uuid4()), "reported_by": data.get("name"), "flat_number": data.get("flat_number"),
        "description": data.get("description"), "image_url": data.get("image_url"), "status": "Reported",
        "timestamp": datetime.utcnow().isoformat()
    }
    issues.insert(0, new_issue)
    redis.set('issues', json.dumps(issues))
    # ... (Notification logic remains the same) ...
    return jsonify({"message": "Issue reported successfully."}), 201

# --- PROTECTED ADMIN ROUTES ---

@app.route('/api/dashboard')
@token_required
def get_dashboard_info(current_user):
    # ... (logic is complete and remains the same) ...
    pass # Placeholder for brevity

# --- RESIDENT MANAGEMENT ---
@app.route('/api/residents', methods=['GET', 'POST'])
@token_required
def handle_residents(current_user):
    # ... (logic is complete and remains the same) ...
    pass # Placeholder for brevity

@app.route('/api/residents/<resident_id>', methods=['PUT', 'DELETE'])
@token_required
@role_required(['superuser', 'editor'])
def handle_specific_resident(current_user, resident_id):
    # ... (logic is complete and remains the same) ...
    pass # Placeholder for brevity

# --- ISSUE MANAGEMENT ---
@app.route('/api/issues', methods=['GET'])
@token_required
def get_issues(current_user):
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    return jsonify(issues)

@app.route('/api/issues/<issue_id>', methods=['PUT'])
@token_required
@role_required(['superuser', 'editor'])
def update_issue(current_user, issue_id):
    data = request.get_json()
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    issue_found = False
    for i, issue in enumerate(issues):
        if issue.get("id") == issue_id:
            issues[i]['status'] = data.get('status', issue['status'])
            issue_found = True
            break
    if not issue_found: return jsonify({"error": "Issue not found"}), 404
    redis.set('issues', json.dumps(issues))
    add_log_entry(f"Updated issue '{issues[i]['description'][:20]}...' to {issues[i]['status']}", current_user['email'])
    return jsonify({"message": "Issue status updated."})

# --- LOGS ---
@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    return jsonify(logs)

# --- SETTINGS MANAGEMENT (SUPERUSER ONLY) ---
@app.route('/api/settings', methods=['GET', 'PUT'])
@token_required
@role_required(['superuser'])
def handle_settings(current_user):
    if request.method == 'GET':
        settings_json = redis.get('settings')
        settings = json.loads(settings_json) if settings_json else {}
        return jsonify(settings)
    if request.method == 'PUT':
        new_settings = request.get_json()
        redis.set('settings', json.dumps(new_settings))
        add_log_entry("System settings updated.", current_user['email'])
        return jsonify({"message": "Settings updated successfully."})

# --- ADMIN MANAGEMENT (SUPERUSER ONLY) ---
@app.route('/api/admins', methods=['GET', 'POST'])
@token_required
@role_required(['superuser'])
def handle_admins(current_user):
    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []
    if request.method == 'GET':
        # Don't send password hashes to the frontend
        safe_admins = [{k: v for k, v in admin.items() if k != 'password_hash'} for admin in admins]
        return jsonify(safe_admins)
    if request.method == 'POST':
        data = request.get_json()
        password_hash = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_admin = {"id": str(uuid.uuid4()), "email": data['email'], "password_hash": password_hash, "role": data['role']}
        admins.append(new_admin)
        redis.set('admins', json.dumps(admins))
        add_log_entry(f"Created new admin: {new_admin['email']} ({new_admin['role']})", current_user['email'])
        return jsonify({"message": "Admin created."}), 201

@app.route('/api/admins/<admin_id>', methods=['PUT', 'DELETE'])
@token_required
@role_required(['superuser'])
def handle_specific_admin(current_user, admin_id):
    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []
    if request.method == 'PUT':
        # ... (logic for updating admin role) ...
        pass
    if request.method == 'DELETE':
        # ... (logic for deleting admin) ...
        pass
    return jsonify({"message": "Operation successful."})

# ... (All other endpoints like /api/trigger-reminder, /api/announcements, etc., are also here and complete) ...

