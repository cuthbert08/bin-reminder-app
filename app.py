# app.py

from flask import Flask, jsonify, request

# Import our sending functions
# Note: These will be used later when we connect the database
# from send_whatsapp import send_whatsapp_reminder
# from send_sms import send_sms_reminder
# from send_email import send_email_reminder

app = Flask(__name__)

@app.route('/')
def home():
    # A simple homepage to confirm the API is running
    return "Bin Reminder API is running."

@app.route('/api/dashboard')
def get_dashboard_info():
    # This will provide data for your dashboard's main view.
    # For now, we return placeholder data.
    dashboard_data = {
        "current_duty": {"flat": "Flat 1", "name": "Alice Johnson (Sample)"},
        "next_in_rotation": {"flat": "Flat 2", "name": "Bob Williams (Sample)"},
        "system_status": {"last_reminder_run": "2025-07-22"}
    }
    return jsonify(dashboard_data)

@app.route('/api/trigger-reminder')
def trigger_reminder():
    # This is the endpoint our Vercel Cron Job will call.
    # We will add the logic here later.
    print("Weekly reminder job triggered.")
    return jsonify({"status": "success", "message": "Reminder job triggered."})

@app.route('/api/announcements', methods=['POST'])
def send_announcement():
    # This endpoint will handle sending messages to everyone.
    # We will add the logic here later.
    message = request.json.get('message', '')
    print(f"Announcement triggered with message: {message}")
    return jsonify({"status": "success", "message": "Announcement sent."})