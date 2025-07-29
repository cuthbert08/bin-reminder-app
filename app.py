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
# These files would need to be in the same directory.
# from send_whatsapp import send_whatsapp_message
# from send_sms import send_sms_message
# from send_email import send_email_message
# Mock functions if the files don't exist:
def send_whatsapp_message(to, body):
    print(f"WHATSAPP to {to}: {body}")
def send_sms_message(to, body):
    print(f"SMS to {to}: {body}")
def send_email_message(to, subject, body):
    print(f"EMAIL to {to}: Subject: {subject}\nBody: {body}")


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

# --- HTML EMAIL ---
def create_html_email_body(first_name, flat_number, settings):
    template = settings.get('reminder_template', '')
    report_link = settings.get('report_issue_link', '#')
    owner_name = settings.get('owner_name', 'Admin')
    owner_number = settings.get('owner_contact_number', '')
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

# --- PUBLIC ROUTES ---

@app.route('/api/issues', methods=['POST'])
def report_issue():
    data = request.get_json()
    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    
    new_issue = {
        "id": str(uuid.uuid4()),
        "reported_by": data.get("name"),
        "flat_number": data.get("flat_number"),
        "description": data.get("description"),
        "image_url": data.get("image_url"),
        "status": "Reported",
        "timestamp": datetime.utcnow().isoformat()
    }
    issues.insert(0, new_issue)
    redis.set('issues', json.dumps(issues))
    
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}
    owner_whatsapp = settings.get('owner_contact_whatsapp')
    owner_email = settings.get('owner_contact_email')
    
    notification_message = f"New Issue Reported by {new_issue['reported_by']} ({new_issue['flat_number']}):\n{new_issue['description']}"
    if new_issue['image_url']:
        notification_message += f"\nImage: {new_issue['image_url']}"
        
    if owner_whatsapp: send_whatsapp_message(owner_whatsapp, notification_message)
    if owner_email: send_email_message(owner_email, "New Maintenance Issue Reported", notification_message)
    
    add_log_entry(f"New issue reported by {new_issue['reported_by']}.")
    return jsonify({"message": "Issue reported successfully."}), 201

# --- PROTECTED ROUTES ---

@app.route('/api/dashboard')
@token_required
def get_dashboard_info(current_user):
    try:
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        current_index = int(redis.get('current_turn_index') or 0)
        last_run_date = redis.get('last_reminder_date') or "N/A"
        reminders_paused = json.loads(redis.get('reminders_paused') or 'false')

        if not flats:
            return jsonify({"current_duty": {"name": "N/A"}, "next_in_rotation": {"name": "N/A"}, "system_status": {"last_reminder_run": "N/A", "reminders_paused": reminders_paused}})
        
        if current_index >= len(flats):
            current_index = 0

        current_person = flats[current_index]
        next_person = flats[(current_index + 1) % len(flats)]

        dashboard_data = {
            "current_duty": {"name": current_person["name"]},
            "next_in_rotation": {"name": next_person["name"]},
            "system_status": {"last_reminder_run": last_run_date, "reminders_paused": reminders_paused}
        }
        return jsonify(dashboard_data)
    except Exception as e:
        add_log_entry(f"ERROR fetching dashboard: {str(e)}", current_user['email'])
        return jsonify({"error": str(e)}), 500

# RESIDENTS
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
            add_log_entry(f"Admin '{current_user['email']}' added new resident: {new_resident['name']}", current_user['email'])
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
        updated_name = ""
        for i, flat in enumerate(flats):
            if flat.get("id") == resident_id:
                flats[i]["name"] = data.get("name", flat["name"])
                flats[i]["flat_number"] = data.get("flat_number", flat.get("flat_number"))
                flats[i]["contact"] = data.get("contact", flat["contact"])
                flats[i]["notes"] = data.get("notes", flat.get("notes"))
                resident_found = True
                updated_name = flats[i]['name']
                break
        if not resident_found: return jsonify({"error": "Resident not found"}), 404
        redis.set('flats', json.dumps(flats))
        add_log_entry(f"Admin '{current_user['email']}' updated details for resident: {updated_name}", current_user['email'])
        return jsonify({"message": "Resident updated successfully"})

    if request.method == 'DELETE':
        original_len = len(flats)
        resident_name = next((flat['name'] for flat in flats if flat.get("id") == resident_id), "Unknown")
        flats = [flat for flat in flats if flat.get("id") != resident_id]
        if len(flats) == original_len: return jsonify({"error": "Resident not found"}), 404
        redis.set('flats', json.dumps(flats))
        add_log_entry(f"Admin '{current_user['email']}' deleted resident: {resident_name}", current_user['email'])
        return jsonify({"message": "Resident deleted successfully"})

# ISSUES
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
    new_status = data.get('status')
    if not new_status:
        return jsonify({"error": "Status is required"}), 400

    issues_json = redis.get('issues')
    issues = json.loads(issues_json) if issues_json else []
    
    issue_found = False
    for i, issue in enumerate(issues):
        if issue.get("id") == issue_id:
            issues[i]['status'] = new_status
            issue_found = True
            break
            
    if not issue_found:
        return jsonify({"error": "Issue not found"}), 404
        
    redis.set('issues', json.dumps(issues))
    add_log_entry(f"Admin '{current_user['email']}' updated issue {issue_id} to '{new_status}'", current_user['email'])
    return jsonify({"message": "Issue status updated successfully"})

# LOGS
@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    return jsonify(logs)

# ADMINS
@app.route('/api/admins', methods=['GET', 'POST'])
@token_required
@role_required(['superuser'])
def handle_admins(current_user):
    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []

    if request.method == 'GET':
        safe_admins = [{k: v for k, v in admin.items() if k != 'password_hash'} for admin in admins]
        return jsonify(safe_admins)
    
    if request.method == 'POST':
        data = request.get_json()
        if not data.get('email') or not data.get('password') or not data.get('role'):
            return jsonify({'message': 'Email, password, and role are required'}), 400
        
        if any(admin['email'] == data['email'] for admin in admins):
            return jsonify({'message': 'Admin with this email already exists'}), 409

        new_admin = {
            "id": str(uuid.uuid4()),
            "email": data['email'],
            "password_hash": generate_password_hash(data['password'], method='pbkdf2:sha256'),
            "role": data['role']
        }
        admins.append(new_admin)
        redis.set('admins', json.dumps(admins))
        add_log_entry(f"Superuser '{current_user['email']}' created new admin: {new_admin['email']}", current_user['email'])
        
        safe_new_admin = {k: v for k, v in new_admin.items() if k != 'password_hash'}
        return jsonify(safe_new_admin), 201

@app.route('/api/admins/<admin_id>', methods=['PUT', 'DELETE'])
@token_required
@role_required(['superuser'])
def handle_specific_admin(current_user, admin_id):
    admins_json = redis.get('admins')
    admins = json.loads(admins_json) if admins_json else []

    if request.method == 'PUT':
        data = request.get_json()
        admin_found = False
        for i, admin in enumerate(admins):
            if admin.get("id") == admin_id:
                if 'role' in data:
                    admins[i]['role'] = data['role']
                if 'password' in data and data['password']:
                    admins[i]['password_hash'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
                admin_found = True
                break
        if not admin_found: return jsonify({"error": "Admin not found"}), 404
        redis.set('admins', json.dumps(admins))
        add_log_entry(f"Superuser '{current_user['email']}' updated details for admin ID: {admin_id}", current_user['email'])
        return jsonify({"message": "Admin updated successfully"})

    if request.method == 'DELETE':
        if current_user['id'] == admin_id:
            return jsonify({'message': 'Cannot delete yourself'}), 403
            
        original_len = len(admins)
        admin_email = next((admin['email'] for admin in admins if admin.get("id") == admin_id), "Unknown")
        admins = [admin for admin in admins if admin.get("id") != admin_id]
        if len(admins) == original_len: return jsonify({"error": "Admin not found"}), 404
        redis.set('admins', json.dumps(admins))
        add_log_entry(f"Superuser '{current_user['email']}' deleted admin: {admin_email}", current_user['email'])
        return jsonify({"message": "Admin deleted successfully"})

# SETTINGS
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
        add_log_entry(f"Superuser '{current_user['email']}' updated system settings.", current_user['email'])
        return jsonify(new_settings)

# CORE ACTIONS
@app.route('/api/trigger-reminder', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def trigger_reminder(current_user):
    data = request.get_json()
    custom_message = data.get('message') if data else None

    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    if not flats:
        return jsonify({"message": "No residents to remind."}), 400
    
    current_index = int(redis.get('current_turn_index') or 0)
    person_on_duty = flats[current_index % len(flats)]
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}

    contact_info = person_on_duty.get('contact', {})
    if custom_message:
        message_to_send = custom_message
        html_body = message_to_send
    else:
        message_to_send = settings.get("reminder_template", "Reminder: It's your turn for bin duty.").format(
            first_name=person_on_duty.get("name", "").split(" ")[0],
            flat_number=person_on_duty.get("flat_number", "")
        )
        html_body = create_html_email_body(person_on_duty.get("name", ""), person_on_duty.get("flat_number", ""), settings)

    if contact_info.get('whatsapp'): send_whatsapp_message(contact_info['whatsapp'], message_to_send)
    if contact_info.get('sms'): send_sms_message(contact_info['sms'], message_to_send)
    if contact_info.get('email'): send_email_message(contact_info['email'], "Bin Duty Reminder", html_body)
    
    redis.set('last_reminder_date', date.today().isoformat())
    add_log_entry(f"Admin '{current_user['email']}' manually triggered reminder for {person_on_duty['name']}.", current_user['email'])
    return jsonify({"message": f"Reminder sent to {person_on_duty['name']}."})

@app.route('/api/announcements', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def send_announcement(current_user):
    data = request.get_json()
    subject = data.get('subject')
    message = data.get('message')
    if not subject or not message:
        return jsonify({"message": "Subject and message are required."}), 400

    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    for resident in flats:
        contact_info = resident.get('contact', {})
        if contact_info.get('whatsapp'): send_whatsapp_message(contact_info['whatsapp'], f"*{subject}*\n{message}")
        if contact_info.get('sms'): send_sms_message(contact_info['sms'], f"Announcement: {subject}\n{message}")
        if contact_info.get('email'): send_email_message(contact_info['email'], subject, message)
        
    add_log_entry(f"Admin '{current_user['email']}' sent an announcement with subject: {subject}", current_user['email'])
    return jsonify({"message": "Announcement sent to all residents."})

@app.route('/api/set-current-turn/<resident_id>', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def set_current_turn(current_user, resident_id):
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    
    try:
        new_index = next(i for i, flat in enumerate(flats) if flat.get("id") == resident_id)
        redis.set('current_turn_index', new_index)
        add_log_entry(f"Admin '{current_user['email']}' set current turn to {flats[new_index]['name']}.", current_user['email'])
        return jsonify({"message": f"Current turn set to {flats[new_index]['name']}."})
    except StopIteration:
        return jsonify({"error": "Resident not found"}), 404

@app.route('/api/skip-turn', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def skip_turn(current_user):
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    if not flats:
        return jsonify({"message": "No residents in the list to skip."}), 400
        
    current_index = int(redis.get('current_turn_index') or 0)
    skipped_person_name = flats[current_index % len(flats)]['name']
    new_index = (current_index + 1) % len(flats)
    redis.set('current_turn_index', new_index)
    
    add_log_entry(f"Admin '{current_user['email']}' skipped {skipped_person_name}'s turn.", current_user['email'])
    return jsonify({"message": "Turn skipped successfully."})

@app.route('/api/toggle-pause', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def toggle_pause(current_user):
    is_paused = json.loads(redis.get('reminders_paused') or 'false')
    new_status = not is_paused
    redis.set('reminders_paused', json.dumps(new_status))
    status_text = "paused" if new_status else "resumed"
    add_log_entry(f"Admin '{current_user['email']}' {status_text} reminders.", current_user['email'])
    return jsonify({"message": f"Reminders are now {status_text}.", "reminders_paused": new_status})

if __name__ == '__main__':
    # You might want to remove the initialization routes or protect them
    # before deploying to a production environment.
    app.run(debug=True)

    