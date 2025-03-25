import os
import json
from flask import Flask, render_template, jsonify
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request  # 🔹 FIXED: Missing import
from transformers import pipeline
import base64

# 🔹 Load AI Model for Phishing Detection
nlp_model = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

# 🔹 Gmail API Scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def get_gmail_service():
    """Authenticate and connect to Gmail API."""
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)

def get_emails(service, max_results=10):
    """Retrieve latest emails from Gmail, extracting full body text."""
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])
    email_data = []
    
    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        headers = msg_data.get("payload", {}).get("headers", [])
        payload = msg_data.get("payload", {})

        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "Unknown Sender")

        email_body = ""
        if "parts" in payload:
            for part in payload["parts"]:
                if part.get("mimeType") == "text/plain":
                    data = part["body"].get("data", "")
                    email_body = base64.urlsafe_b64decode(data).decode("utf-8")

        email_data.append({
            "subject": subject,
            "sender": sender,
            "body": email_body
        })
    
    return email_data

def detect_phishing(emails):
    """Scan emails for phishing content using AI."""
    flagged_emails = []
    for email in emails:
        if not email["body"]:  # Skip empty emails
            continue

        result = nlp_model(email["body"])[0]
        score = result['score'] if result['label'] == 'LABEL_1' else 1 - result['score']

        if score > 0.7:  # 🔹 Adjust sensitivity as needed
            email['phishing_score'] = round(score, 2)
            flagged_emails.append(email)

    return flagged_emails

# 🔹 Flask App Setup
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_emails():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail API authentication failed."})

    emails = get_emails(service)
    phishing_emails = detect_phishing(emails)
    return jsonify(phishing_emails)

if __name__ == "__main__":
    app.run(debug=True)
