"""
One-time script to generate Gmail OAuth token.
Run this LOCALLY (not in Docker) — it opens a browser for authorization.

Usage:
    python generate_gmail_token.py
"""
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
CREDENTIALS_PATH = 'credentials/gmail_credentials.json'
TOKEN_PATH = 'credentials/gmail_token.json'

flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
creds = flow.run_local_server(port=0)

with open(TOKEN_PATH, 'w') as f:
    f.write(creds.to_json())

print(f"Token saved to {TOKEN_PATH}")
