# app.py

import os
import json
from flask import Flask, jsonify, request
from upstash_redis import Redis
from datetime import datetime, date
import uuid
from flask_cors import CORS

# --- Initialize Redis Client with the correct Vercel KV environment variables ---
redis = Redis(
    url=os.environ.get('KV_REST_API_URL'),
    token=os.environ.get('KV_REST_API_TOKEN')
)

# --- Import Sending Functions ---
from send_whatsapp import send_whatsapp_message
from send_sms import send_sms_message
from send_email import send_email_message

app = Flask(__name__)
CORS(app) # Enable CORS for your separate frontend

# --- Helper Function for Logging ---
def add_log_entry(message):
    """Adds a new entry to the logs in the database."""
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    new_entry = f"[{timestamp}] {message}"
    logs.insert(0, new_entry)
    
    if len(logs) > 50:
        logs = logs[:50]
        
    redis.set('logs', json.dumps(logs))

# --- Main Endpoints ---

@app.route('/')
def home():
    return "Bin Reminder API is running."

@app.route('/api/initialize-data')
def initialize_data():
    """One-time setup to initialize the database."""
    try:
        residents_to_add = [
            {
              "id": "flat_1",
              "name": "Cuthbert Ndikudze",
              "contact": { "whatsapp": "+27621841122", "sms": "+27621841122", "email": "cutbertndikudze@gmail.com" }
            }
        ]
        redis.set('flats', json.dumps(residents_to_add))
        redis.set('current_turn_index', 0)
        redis.set('last_reminder_date', "2000-01-01")
        redis.set('reminders_paused', False)
        redis.set('logs', json.dumps([]))
        add_log_entry("System initialized successfully.")
        return "Database has been initialized successfully."
    except Exception as e:
        return f"An error occurred during setup: {e}", 500

# --- Resident Management ---

@app.route('/api/residents', methods=['GET', 'POST'])
def handle_residents():
    if request.method == 'GET':
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        return jsonify(flats)
    
    if request.method == 'POST':
        data = request.get_json()
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        new_resident = {"id": str(uuid.uuid4()), "name": data.get("name"), "contact": data.get("contact", {})}
        flats.append(new_resident)
        redis.set('flats', json.dumps(flats))
        add_log_entry(f"Added new resident: {new_resident['name']}")
        return jsonify(new_resident), 201

@app.route('/api/residents/<resident_id>', methods=['PUT', 'DELETE'])
def handle_specific_resident(resident_id):
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    
    if request.method == 'PUT':
        data = request.get_json()
        resident_found = False
        for i, flat in enumerate(flats):
            if flat.get("id") == resident_id:
                flats[i]["name"] = data.get("name", flat["name"])
                flats[i]["contact"] = data.get("contact", flat["contact"])
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

# --- Dashboard & System Status ---

@app.route('/api/dashboard')
def get_dashboard_info():
    try:
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        current_index = int(redis.get('current_turn_index') or 0)
        last_run_date = redis.get('last_reminder_date') or "N/A"
        reminders_paused = json.loads(redis.get('reminders_paused') or 'false')

        if not flats:
            return jsonify({"current_duty": {"name": "N/A"}, "next_in_rotation": {"name": "N/A"}, "system_status": {"last_reminder_run": "N/A", "reminders_paused": reminders_paused}})

        current_person = flats[current_index]
        next_person = flats[(current_index + 1) % len(flats)]

        dashboard_data = {
            "current_duty": {"name": current_person["name"]},
            "next_in_rotation": {"name": next_person["name"]},
            "system_status": {"last_reminder_run": last_run_date, "reminders_paused": reminders_paused}
        }
        return jsonify(dashboard_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Core Reminder & Announcement Logic ---

@app.route('/api/trigger-reminder', methods=['GET', 'POST'])
def trigger_reminder():
    try:
        reminders_paused = json.loads(redis.get('reminders_paused') or 'false')
        if reminders_paused and request.method == 'GET':
            add_log_entry("Automatic reminder skipped: System is paused (Vacation Mode).")
            return "Reminders are paused.", 200

        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        if not flats: return "Error: No flats configured.", 500

        current_index = int(redis.get('current_turn_index') or 0)
        if current_index >= len(flats): current_index = 0
        person_on_duty = flats[current_index]
        
        custom_message_body = request.get_json().get('message') if request.method == 'POST' and request.is_json else None
        first_name = person_on_duty['name'].split()[0]
        message = custom_message_body or f"Hi {first_name}! Just a friendly reminder that it's your turn to take out the dustbin today. Thank you!"
        
        subject = "Bin Duty Reminder"
        
        if person_on_duty['contact'].get('whatsapp'):
            send_whatsapp_message(person_on_duty['contact']['whatsapp'], message)
        if person_on_duty['contact'].get('sms'):
            send_sms_message(person_on_duty['contact']['sms'], message)
        if person_on_duty['contact'].get('email'):
            send_email_message(person_on_duty['contact']['email'], subject, message)

        add_log_entry(f"Reminder sent to {person_on_duty['name']}.")

        new_index = (current_index + 1) % len(flats)
        redis.set('current_turn_index', new_index)
        redis.set('last_reminder_date', date.today().isoformat())
        
        return "Reminder sent successfully."
    except Exception as e:
        add_log_entry(f"Error during reminder trigger: {e}")
        return f"An error occurred: {e}", 500

@app.route('/api/announcements', methods=['POST'])
def send_announcement():
    try:
        data = request.get_json()
        message = data.get('message')
        if not message: return jsonify({"error": "Message cannot be empty."}), 400
        
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        if not flats: return jsonify({"error": "No flats configured."}), 500

        subject = data.get('subject', 'Important Announcement')
        for person in flats:
            contact = person.get('contact', {})
            if contact.get('whatsapp'):
                send_whatsapp_message(contact['whatsapp'], message)
            if contact.get('sms'):
                send_sms_message(contact['sms'], message)
            if contact.get('email'):
                send_email_message(contact['email'], subject, message)
        
        add_log_entry(f"Sent announcement: '{message[:30]}...'")
        return jsonify({"message": "Announcement sent to all residents."})
    except Exception as e:
        add_log_entry(f"Error sending announcement: {e}")
        return jsonify({"error": str(e)}), 500

# --- New Feature Endpoints ---

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Retrieves the history log."""
    logs_json = redis.get('logs')
    logs = json.loads(logs_json) if logs_json else []
    return jsonify(logs)

@app.route('/api/set-current-turn/<resident_id>', methods=['POST'])
def set_current_turn(resident_id):
    """Manually sets the current person on duty."""
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    for i, flat in enumerate(flats):
        if flat.get("id") == resident_id:
            redis.set('current_turn_index', i)
            add_log_entry(f"Manual rotation: Set {flat['name']} as current.")
            return jsonify({"message": f"{flat['name']} is now set as current."})
    return jsonify({"error": "Resident not found"}), 404

@app.route('/api/skip-turn', methods=['POST'])
def skip_turn():
    """Skips the current person's turn."""
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    if not flats: return "Error: No flats configured.", 500
    current_index = int(redis.get('current_turn_index') or 0)
    skipped_person_name = flats[current_index]['name']
    new_index = (current_index + 1) % len(flats)
    redis.set('current_turn_index', new_index)
    add_log_entry(f"Skipped turn for {skipped_person_name}.")
    return jsonify({"message": f"Successfully skipped turn for {skipped_person_name}."})

@app.route('/api/toggle-pause', methods=['POST'])
def toggle_pause():
    """Toggles the vacation mode (pause reminders)."""
    current_status = json.loads(redis.get('reminders_paused') or 'false')
    new_status = not current_status
    redis.set('reminders_paused', json.dumps(new_status))
    status_text = "paused" if new_status else "resumed"
    add_log_entry(f"System {status_text}.")
    return jsonify({"message": f"System has been {status_text}.", "reminders_paused": new_status})
