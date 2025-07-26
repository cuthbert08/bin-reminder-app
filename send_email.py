import smtplib
import os
from email.mime.text import MIMEText

# Credentials are loaded from Vercel's environment variables
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_email_message(recipient_email, subject, message_body):
    """Sends an email using a Gmail account."""
    if not all([EMAIL_SENDER, EMAIL_PASSWORD]):
        print("Email credentials are not fully configured.")
        return False

    msg = MIMEText(message_body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"Email sent successfully to {recipient_email}")
        return True
    except Exception as e:
        print(f"Error sending email to {recipient_email}: {e}")
        return False