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
# These should be your actual implementations that use services like Twilio/SendGrid
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

def add_log_entry(user_email, action_description):
    """Adds a log entry as a formatted string to the database."""
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    new_entry = f"[{timestamp}] ({user_email}) {action_description}"
    
    logs.insert(0, new_entry)
    if len(logs) > 100:  # Keep the last 100 log entries
        logs = logs[:100]
        
    redis.set('logs', json.dumps(logs))

def generate_text_message(template, resident, settings, subject=None):
    """Personalizes a text message and adds the standard footer."""
    first_name = resident.get("name", "").split(" ")[0]
    flat_number = resident.get("flat_number", "")
    owner_name = settings.get('owner_name', 'Admin')
    owner_number = settings.get('owner_contact_number', '')

    # Personalize the main message
    personalized_body = template.replace("{first_name}", first_name).replace("{flat_number}", flat_number)
    
    # Add a more SMS-friendly footer
    footer = f"\n\nContact {owner_name} at {owner_number} for issues."
    
    # Prepend subject for announcements
    if subject:
        return f"Announcement: {subject}\n{personalized_body}{footer}"
    else:
        return f"{personalized_body}{footer}"

def generate_html_message(template, resident, settings, subject="Bin Duty Reminder"):
    """Generates a professional and beautiful HTML email."""
    first_name = resident.get("name", "").split(" ")[0]
    flat_number = resident.get("flat_number", "")
    owner_name = settings.get('owner_name', 'Admin')
    owner_number = settings.get('owner_contact_number', '')
    report_link = settings.get('report_issue_link', '#')

    # Personalize the main message, ensuring newlines are converted to <br> tags
    personalized_body = template.replace("{first_name}", first_name).replace("{flat_number}", flat_number).replace('\n', '<br>')
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{subject}</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
            body {{
                font-family: 'Poppins', sans-serif;
                background-color: #f4f4f4;
                color: #333;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0,0,0,0.05);
                border: 1px solid #e8e8e8;
            }}
            .header {{
                background-color: #4A90E2; /* A nice blue */
                color: #ffffff;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 30px;
                line-height: 1.7;
                color: #555;
            }}
            .content p {{
                margin: 0 0 15px 0;
            }}
            .button-container {{
                text-align: center;
                margin-top: 25px;
            }}
            .button {{
                display: inline-block;
                padding: 12px 25px;
                background-color: #50C878; /* A friendly green */
                color: #ffffff;
                text-decoration: none;
                border-radius: 50px;
                font-weight: 600;
                font-size: 16px;
            }}
            .footer {{
                padding: 20px;
                font-size: 12px;
                color: #888;
                text-align: center;
                background-color: #f9f9f9;
                border-top: 1px solid #e8e8e8;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{subject}</h1>
            </div>
            <div class="content">
                <p>Hi {first_name},</p>
                <p>{personalized_body}</p>
                <div class="button-container">
                    <a href="{report_link}" class="button">Report an Issue</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message. For urgent enquiries, please contact {owner_name} at {owner_number}.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def generate_owner_issue_email(issue, settings):
    """Generates a professional HTML email for the owner about a new issue."""
    
    # Safely get the frontend URL, defaulting to a placeholder if not set
    base_url = settings.get('report_issue_link', 'http://localhost:9002').rsplit('/report', 1)[0]
    issues_link = f"{base_url}/issues"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Maintenance Issue Reported</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
            body {{
                font-family: 'Poppins', sans-serif;
                background-color: #f9fafb;
                color: #374151;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 560px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
                border: 1px solid #e5e7eb;
            }}
            .header {{
                background-color: #FF5A5F;
                color: #ffffff;
                padding: 24px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .content {{
                padding: 32px;
                color: #4b5563;
            }}
            .content h2 {{
                font-size: 20px;
                color: #111827;
                margin-top: 0;
                margin-bottom: 20px;
            }}
            .content p {{
                margin: 0 0 10px;
                line-height: 1.6;
            }}
            .details-box {{
                background-color: #f3f4f6;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                padding: 20px;
                margin-top: 20px;
            }}
            .details-box strong {{
                color: #111827;
            }}
            .button-container {{
                text-align: center;
                margin-top: 30px;
                margin-bottom: 10px;
            }}
            .button {{
                display: inline-block;
                padding: 14px 28px;
                background-color: #3B82F6;
                color: #ffffff;
                text-decoration: none;
                border-radius: 50px;
                font-weight: 600;
                font-size: 16px;
                transition: background-color 0.3s;
            }}
            .button:hover {{
                background-color: #2563EB;
            }}
            .footer {{
                padding: 24px;
                font-size: 13px;
                color: #9ca3af;
                text-align: center;
                background-color: #f9fafb;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>New Issue Reported</h1>
            </div>
            <div class="content">
                <h2>A new maintenance issue has been submitted.</h2>
                <p>Here are the details:</p>
                <div class="details-box">
                    <p><strong>Reported By:</strong> {issue['reported_by']}</p>
                    <p><strong>Flat Number:</strong> {issue['flat_number']}</p>
                    <p><strong>Description:</strong></p>
                    <p>{issue['description']}</p>
                </div>
                <div class="button-container">
                    <a href="{issues_link}" class="button">View All Issues</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from your Bin Reminder App.</p>
            </div>
        </div>
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
        "status": "Reported",
        "timestamp": datetime.utcnow().isoformat()
    }
    issues.insert(0, new_issue)
    redis.set('issues', json.dumps(issues))
    
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}
    owner_whatsapp = settings.get('owner_contact_whatsapp')
    owner_sms = settings.get('owner_contact_number')
    owner_email = settings.get('owner_contact_email')

    # Construct the link to the issues page
    base_url = settings.get('report_issue_link', 'http://localhost:9002').rsplit('/report', 1)[0]
    issues_link = f"{base_url}/issues"
    
    # Prepare messages for different channels
    text_notification = f"New Issue Reported by {new_issue['reported_by']}, Flat {new_issue['flat_number']}: {new_issue['description'][:80]}... See it here: {issues_link}"
    html_notification = generate_owner_issue_email(new_issue, settings)

    if owner_whatsapp: 
        send_whatsapp_message(owner_whatsapp, text_notification)
    if owner_sms:
        send_sms_message(owner_sms, text_notification)
    if owner_email: 
        send_email_message(owner_email, "New Maintenance Issue Reported", html_notification)
    
    add_log_entry("Public", f"Issue Reported by {new_issue['reported_by']}: {new_issue['description'][:50]}...")
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
        add_log_entry(current_user['email'], f"Error fetching dashboard: {str(e)}")
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
            add_log_entry(current_user['email'], f"Resident Added: {new_resident['name']}")
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
        add_log_entry(current_user['email'], f"Resident Updated: {updated_name}")
        return jsonify({"message": "Resident updated successfully"})

    if request.method == 'DELETE':
        original_len = len(flats)
        resident_name = next((flat['name'] for flat in flats if flat.get("id") == resident_id), "Unknown")
        flats = [flat for flat in flats if flat.get("id") != resident_id]
        if len(flats) == original_len: return jsonify({"error": "Resident not found"}), 404
        redis.set('flats', json.dumps(flats))
        add_log_entry(current_user['email'], f"Resident Deleted: {resident_name}")
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
    add_log_entry(current_user['email'], f"Issue status for {issue_id} updated to '{new_status}'")
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
        add_log_entry(current_user['email'], f"Admin Created: {new_admin['email']} with role {new_admin['role']}")
        
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
        updated_email = ""
        for i, admin in enumerate(admins):
            if admin.get("id") == admin_id:
                if 'role' in data:
                    admins[i]['role'] = data['role']
                    updated_email = admins[i]['email']
                if 'password' in data and data['password']:
                    admins[i]['password_hash'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
                admin_found = True
                break
        if not admin_found: return jsonify({"error": "Admin not found"}), 404
        redis.set('admins', json.dumps(admins))
        add_log_entry(current_user['email'], f"Admin Updated: {updated_email}")
        return jsonify({"message": "Admin updated successfully"})

    if request.method == 'DELETE':
        if current_user['id'] == admin_id:
            return jsonify({'message': 'Cannot delete yourself'}), 403
            
        original_len = len(admins)
        admin_email = next((admin['email'] for admin in admins if admin.get("id") == admin_id), "Unknown")
        admins = [admin for admin in admins if admin.get("id") != admin_id]
        if len(admins) == original_len: return jsonify({"error": "Admin not found"}), 404
        redis.set('admins', json.dumps(admins))
        add_log_entry(current_user['email'], f"Admin Deleted: {admin_email}")
        return jsonify({"message": "Admin deleted successfully"})

# SETTINGS
@app.route('/api/settings', methods=['GET', 'PUT'])
@token_required
def handle_settings(current_user):
    @role_required(['superuser'])
    def get(current_user):
        settings_json = redis.get('settings')
        settings = json.loads(settings_json) if settings_json else {}
        return jsonify(settings)

    @role_required(['superuser'])
    def put(current_user):
        new_settings = request.get_json()
        redis.set('settings', json.dumps(new_settings))
        add_log_entry(current_user['email'], f"Settings Updated: {', '.join(new_settings.keys())}")
        return jsonify(new_settings)

    if request.method == 'GET':
        return get(current_user)
    if request.method == 'PUT':
        return put(current_user)


# CORE ACTIONS
@app.route('/api/trigger-reminder', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def trigger_reminder(current_user):
    data = request.get_json()
    custom_template = data.get('message') if data else None

    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    if not flats:
        return jsonify({"message": "No residents to remind."}), 400
    
    current_index = int(redis.get('current_turn_index') or 0)
    person_on_duty = flats[current_index % len(flats)]
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}

    # Use custom message if provided, otherwise use the saved template
    template_to_use = custom_template or settings.get("reminder_template", "Reminder: It's your turn for bin duty.")
    
    # Generate formatted messages
    text_message = generate_text_message(template_to_use, person_on_duty, settings)
    html_message = generate_html_message(template_to_use, person_on_duty, settings, "Bin Duty Reminder")

    # Send messages
    contact_info = person_on_duty.get('contact', {})
    if contact_info.get('whatsapp'): send_whatsapp_message(contact_info['whatsapp'], text_message)
    if contact_info.get('sms'): send_sms_message(contact_info['sms'], text_message)
    if contact_info.get('email'): send_email_message(contact_info['email'], "Bin Duty Reminder", html_message)
    
    redis.set('last_reminder_date', date.today().isoformat())
    add_log_entry(current_user['email'], f"Reminder Sent to {person_on_duty['name']}")
    return jsonify({"message": f"Reminder sent to {person_on_duty['name']}."})

@app.route('/api/announcements', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def send_announcement(current_user):
    data = request.get_json()
    subject = data.get('subject')
    message_template = data.get('message')
    if not subject or not message_template:
        return jsonify({"message": "Subject and message are required."}), 400

    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    settings_json = redis.get('settings')
    settings = json.loads(settings_json) if settings_json else {}
    
    recipient_names = []
    for resident in flats:
        recipient_names.append(resident['name'])
        # Generate formatted messages for each resident
        text_message = generate_text_message(message_template, resident, settings, subject)
        html_message = generate_html_message(message_template, resident, settings, subject)
        
        contact_info = resident.get('contact', {})
        if contact_info.get('whatsapp'): send_whatsapp_message(contact_info['whatsapp'], text_message)
        if contact_info.get('sms'): send_sms_message(contact_info['sms'], text_message)
        if contact_info.get('email'): send_email_message(contact_info['email'], subject, html_message)
        
    add_log_entry(current_user['email'], f"Announcement Sent: '{subject}' to {len(recipient_names)} residents")
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
        add_log_entry(current_user['email'], f"Duty Turn Set to {flats[new_index]['name']}")
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
    
    add_log_entry(current_user['email'], f"Duty Turn Skipped for {skipped_person_name}")
    return jsonify({"message": "Turn skipped successfully."})

@app.route('/api/toggle-pause', methods=['POST'])
@token_required
@role_required(['superuser', 'editor'])
def toggle_pause(current_user):
    is_paused = json.loads(redis.get('reminders_paused') or 'false')
    new_status = not is_paused
    redis.set('reminders_paused', json.dumps(new_status))
    status_text = "paused" if new_status else "resumed"
    add_log_entry(current_user['email'], f"Reminders Toggled: {status_text}")
    return jsonify({"message": f"Reminders are now {status_text}.", "reminders_paused": new_status})

# This is a one-time setup route, you might want to protect or remove it in production.
@app.route('/api/initialize-data')
def initialize_data():
    try:
        # Check if settings already exist
        if redis.exists('settings'):
            return "Database already initialized."

        # Initialize default settings
        default_settings = {
            "owner_name": "Admin",
            "owner_contact_number": "",
            "owner_contact_email": "admin@example.com",
            "owner_contact_whatsapp": "",
            "report_issue_link": "http://localhost:9002/report",
            "reminder_template": "Hi {first_name}, this is a reminder that it's your turn for bin duty for flat {flat_number} this week."
        }
        redis.set('settings', json.dumps(default_settings))

        # Initialize default admin user if none exist
        if not redis.exists('admins'):
            superuser_password_hash = generate_password_hash("your-secure-password", method='pbkdf2:sha256')
            admin_id = str(uuid.uuid4())
            admins = [{"id": admin_id, "email": "admin@example.com", "password_hash": superuser_password_hash, "role": "superuser"}]
            redis.set('admins', json.dumps(admins))
            add_log_entry("System", f"Default admin user created: admin@example.com")

        # Initialize other data structures as empty lists
        if not redis.exists('flats'):
            redis.set('flats', json.dumps([]))
        if not redis.exists('issues'):
            redis.set('issues', json.dumps([]))
        if not redis.exists('logs'):
            redis.set('logs', json.dumps([]))
        if not redis.exists('current_turn_index'):
            redis.set('current_turn_index', 0)
        if not redis.exists('reminders_paused'):
            redis.set('reminders_paused', json.dumps(False))

        add_log_entry("System", "Database initialized with default values.")
        return "Database initialized successfully."
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)

    