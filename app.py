# app.py

import os
import json
from flask import Flask, jsonify, request
from upstash_redis import Redis # Using the direct Upstash library
from datetime import date
import uuid

# --- Explicitly initialize the Redis client with credentials from environment variables ---
# This is the final, most reliable way to connect.
redis = Redis(
    url=os.environ.get('UPSTASH_REDIS_REST_URL'),
    token=os.environ.get('UPSTASH_REDIS_REST_TOKEN')
)

# Import our sending functions
from send_whatsapp import send_whatsapp_message
from send_sms import send_sms_message
from send_email import send_email_message

app = Flask(__name__)

@app.route('/')
def home():
    """A simple homepage to confirm the API is running."""
    return "Bin Reminder API is running."

@app.route('/api/initialize-data')
def initialize_data():
    """
    A one-time setup endpoint to initialize the database with your resident data.
    Visit this URL once after deploying to set up your initial information.
    """
    try:
        residents_to_add = [
            {
              "id": "flat_1",
              "name": "Cuthbert Ndikudze",
              "contact": { 
                  "whatsapp": "+27621841122", 
                  "sms": "+27621841122", 
                  "email": "cutbertndikudze@gmail.com" 
              }
            }
        ]
        
        # Redis stores strings, so we convert our list to a JSON string
        redis.set('flats', json.dumps(residents_to_add))
        redis.set('current_turn_index', 0)
        redis.set('last_reminder_date', "2000-01-01")
        
        return "Database has been initialized successfully with your information."
    except Exception as e:
        return f"An error occurred during setup: {e}", 500

# --- Resident Management API Endpoints ---

@app.route('/api/residents', methods=['GET'])
def get_residents():
    """Gets the list of all residents."""
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    return jsonify(flats)

@app.route('/api/residents', methods=['POST'])
def add_resident():
    """Adds a new resident."""
    data = request.get_json()
    flats_json = redis.get('flats')
    flats = json.loads(flats_json) if flats_json else []
    
    new_resident = {
        "id": str(uuid.uuid4()),
        "name": data.get("name"),
        "contact": data.get("contact", {})
    }
    flats.append(new_resident)
    redis.set('flats', json.dumps(flats))
    
    if redis.get('current_turn_index') is None:
        redis.set('current_turn_index', 0)
        
    return jsonify(new_resident), 201

# ... (Other resident management endpoints would be updated similarly) ...


# --- Dashboard, Reminder, and Announcement Endpoints ---

@app.route('/api/dashboard')
def get_dashboard_info():
    """Provides live data for the dashboard."""
    try:
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        
        current_index_str = redis.get('current_turn_index')
        current_index = int(current_index_str) if current_index_str else 0
        
        last_run_date = redis.get('last_reminder_date') or "N/A"
        
        if not flats:
            return jsonify({"current_duty": {"name": "N/A"}, "next_in_rotation": {"name": "N/A"}, "system_status": {"last_reminder_run": "N/A"}})

        current_person = flats[current_index]
        next_index = (current_index + 1) % len(flats)
        next_person = flats[next_index]

        dashboard_data = {
            "current_duty": {"name": current_person["name"]},
            "next_in_rotation": {"name": next_person["name"]},
            "system_status": {"last_reminder_run": last_run_date}
        }
        return jsonify(dashboard_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/trigger-reminder', methods=['GET', 'POST'])
def trigger_reminder():
    """
    Sends the weekly reminder.
    """
    try:
        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        if not flats:
            return "Error: No flats configured.", 500

        last_date_str = redis.get('last_reminder_date') or "2000-01-01"
        last_date = date.fromisoformat(last_date_str)
        if request.method == 'GET' and (date.today() - last_date).days < 6:
             return f"Reminder already sent on {last_date_str}.", 200

        current_index_str = redis.get('current_turn_index')
        current_index = int(current_index_str) if current_index_str else 0
        
        if current_index >= len(flats):
            current_index = 0

        person_on_duty = flats[current_index]
        
        custom_message_body = None
        if request.method == 'POST' and request.is_json:
            custom_message_body = request.get_json().get('message')

        if custom_message_body:
            message = custom_message_body
        else:
            first_name = person_on_duty['name'].split()[0]
            message = f"Hi {first_name}! Just a friendly reminder that it's your turn to take out the dustbin today. Thank you!"
        
        subject = "Bin Duty Reminder"

        if person_on_duty['contact'].get('whatsapp'):
            send_whatsapp_message(person_on_duty['contact']['whatsapp'], message)
        if person_on_duty['contact'].get('sms'):
            send_sms_message(person_on_duty['contact']['sms'], message)
        if person_on_duty['contact'].get('email'):
            send_email_message(person_on_duty['contact']['email'], subject, message)

        new_index = (current_index + 1) % len(flats)
        redis.set('current_turn_index', new_index)
        redis.set('last_reminder_date', date.today().isoformat())
        
        return "Reminder sent successfully."
    except Exception as e:
        return f"An error occurred: {e}", 500


@app.route('/api/announcements', methods=['POST'])
def send_announcement():
    """Handles sending a message to everyone."""
    try:
        data = request.get_json()
        message = data.get('message')
        subject = data.get('subject', 'Important Announcement')

        if not message:
            return jsonify({"error": "Message cannot be empty."}), 400

        flats_json = redis.get('flats')
        flats = json.loads(flats_json) if flats_json else []
        if not flats:
            return jsonify({"error": "No flats configured."}), 500

        for person in flats:
            contact = person.get('contact', {})
            if contact.get('whatsapp'):
                send_whatsapp_message(contact['whatsapp'], message)
            if contact.get('sms'):
                send_sms_message(contact['sms'], message)
            if contact.get('email'):
                send_email_message(contact['email'], subject, message)
        
        return jsonify({"message": "Announcement sent to all residents."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
