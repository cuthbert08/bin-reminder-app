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

    token = jwt.encode({
        'id': user['id'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, JWT_SECRET_KEY, "HS256")

    return jsonify({'token': token, 'user': {'email': user['email'], 'role': user['role']}})


# --- HELPER FUNCTIONS ---

def add_log_entry(message):
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    new_entry = f"[{timestamp}] {message}"
    logs.insert(0, new_entry)
    if len(logs) > 50:
        logs = logs[:50]
    redis.set('logs', json.dumps(logs))

# --- ONE-TIME SETUP ---

@app.route('/api/initialize-data')
def initialize_data():
    try:
        # --- Initialize Admins with CORRECT email ---
        superuser_password_hash = generate_password_hash("Mudharaa@1", method='pbkdf2:sha256')
        admins = [{
            "id": str(uuid.uuid4()),
            "email": "cutbertndikudze@gmail.com",
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
            "owner_contact_number": os.environ.get('OWNER_CONTACT_NUMBER', ''),
            "owner_contact_email": os.environ.get('OWNER_CONTACT_EMAIL', ''),
            "owner_contact_whatsapp": os.environ.get('OWNER_CONTACT_WHATSAPP', ''),
            "report_issue_link": "https://your-frontend-url/report",
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

# --- DEBUG ENDPOINT (can be removed later) ---
@app.route('/api/debug-admins')
def debug_admins():
    try:
        admins_json = redis.get('admins')
        if not admins_json:
            return "No admin data found in the database."
        admins = json.loads(admins_json)
        for admin in admins:
            admin.pop('password_hash', None)
        return jsonify(admins)
    except Exception as e:
        return f"An error occurred: {e}"

# --- PROTECTED ADMIN ROUTES ---

@app.route('/api/dashboard')
@token_required
def get_dashboard_info(current_user):
    """Provides live data for the dashboard."""
    try:
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        current_index = int(redis.get('current_turn_index') or 0)
        last_run_date = redis.get('last_reminder_date') or "N/A"
        reminders_paused = json.loads(redis.get('reminders_paused') or 'false')

        if not flats:
            return jsonify({"current_duty": {"name": "N/A"}, "next_in_rotation": {"name": "N/A"}, "system_status": {"last_reminder_run": "N/A", "reminders_paused": reminders_paused}})
        
        # Ensure index is within bounds
        if current_index >= len(flats):
            current_index = 0

        current_person = flats[current_index]
        next_person = flats[(current_index + 1) % len(flats)]

        dashboard_data = {
            "current_duty": {"name": current_person["name"], "flat_number": current_person.get("flat_number", "")},
            "next_in_rotation": {"name": next_person["name"], "flat_number": next_person.get("flat_number", "")},
            "system_status": {"last_reminder_run": last_run_date, "reminders_paused": reminders_paused}
        }
        return jsonify(dashboard_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/residents', methods=['GET', 'POST'])
@token_required
def handle_residents(current_user):
    if request.method == 'GET':
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        return jsonify(flats)
    
    if request.method == 'POST':
        @role_required(['superuser', 'editor'])
        def add(current_user):
            data = request.get_json()
            flats_json = redis.get('flats')
            flats = json.loads(flats_json) if flats_json else []
            new_resident = {
                "id": str(uuid.uuid4()),
                "name": data.get("name"),
                "flat_number": data.get("flat_number"),
                "contact": data.get("contact", {}),
                "notes": data.get("notes", "")
            }
            flats.append(new_resident)
            redis.set('flats', json.dumps(flats))
            add_log_entry(f"Added new resident: {new_resident['name']}")
            return jsonify(new_resident), 201
        return add(current_user)

@app.route('/api/residents/<resident_id>', methods=['PUT', 'DELETE'])
@token_required
@role_required(['superuser', 'editor'])
def handle_specific_resident(current_user, resident_id):
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    
    if request.method == 'PUT':
        data = request.get_json()
        resident_found = False
        for i, flat in enumerate(flats):
            if flat.get("id") == resident_id:
                flats[i]["name"] = data.get("name", flat["name"])
                flats[i]["flat_number"] = data.get("flat_number", flat.get("flat_number"))
                flats[i]["contact"] = data.get("contact", flat["contact"])
                flats[i]["notes"] = data.get("notes", flat.get("notes"))
                resident_found = True
                break
        if not resident_found: return jsonify({"error": "Resident not found"}), 404
        redis.set('flats', json.dumps(flats))
        add_log_entry(f"Updated details for resident: {flats[i]['name']}")
        return jsonify({"message": "Resident updated successfully"})

    if request.method == 'DELETE':
        original_len = len(flats)
        resident_name = ""
        for flat in flats:
            if flat.get("id") == resident_id:
                resident_name = flat['name']
                break
        flats = [flat for flat in flats if flat.get("id") != resident_id]
        if len(flats) == original_len: return jsonify({"error": "Resident not found"}), 404
        redis.set('flats', json.dumps(flats))
        add_log_entry(f"Deleted resident: {resident_name}")
        return jsonify({"message": "Resident deleted successfully"})


# --- HTML EMAIL EXAMPLE ---
# (This would be integrated into the main trigger_reminder function)

def create_html_email_body(first_name, flat_number, settings):
    """Generates a professional HTML email."""
    template = settings.get('reminder_template', '')
    
    report_link = settings.get('report_issue_link', '#')
    owner_name = settings.get('owner_name', 'Admin')
    owner_number = settings.get('owner_contact_number', '')

    # Personalize the message
    message_body = template.replace("{first_name}", first_name).replace("{flat_number}", flat_number)
    message_body = message_body.replace("{admin_name}", owner_name).replace("{admin_number}", owner_number).replace("{link_to_issue_page}", report_link)

    html = f"""
    <html>
        <body style="font-family: sans-serif; margin: 20px; color: #333;">
            <h2>Bin Duty Reminder</h2>
            <p>{message_body.replace(chr(10), "<br>")}</p>
            <a href="{report_link}" style="display: inline-block; padding: 12px 18px; margin-top: 15px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                Report a Maintenance Issue
            </a>
            <hr style="margin-top: 25px; border: none; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #888;">This is an automated message. Contact {owner_name} at {owner_number} for enquiries.</p>
        </body>
    </html>
    """
    return html

# ... (The rest of the new feature endpoints would be fully implemented here)
