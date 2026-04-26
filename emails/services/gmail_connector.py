"""
Gmail API connector for Stratos BEP.
Handles OAuth authentication and email fetching from Gmail.
"""
import json
import logging
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from emails.models import Email

logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']


class GmailConnector:
    """Connects to Gmail API for email ingestion."""

    def __init__(self):
        self.service = self._authenticate()

    def _authenticate(self):
        """
        Load credentials from GMAIL_CREDENTIALS_PATH env var.
        Load/save token from GMAIL_TOKEN_PATH env var.
        Use InstalledAppFlow for initial auth.
        Build and return Gmail API service resource.

        Raises FileNotFoundError if credentials.json is missing.
        """
        credentials_path = os.environ.get(
            'GMAIL_CREDENTIALS_PATH', 'credentials/credentials.json'
        )
        token_path = os.environ.get(
            'GMAIL_TOKEN_PATH', 'credentials/token.json'
        )

        if not os.path.exists(credentials_path):
            raise FileNotFoundError(
                f"Gmail credentials not found at {credentials_path}. "
                "Please set up OAuth credentials: "
                "https://console.cloud.google.com/apis/credentials\n"
                "Set GMAIL_CREDENTIALS_PATH in .env to point to your "
                "credentials.json file."
            )

        creds = None

        # Load existing token
        if os.path.exists(token_path):
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)

        # Refresh or create credentials
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, SCOPES
                )
                creds = flow.run_local_server(port=0)

            # Save token for next run
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            with open(token_path, 'w') as token_file:
                token_file.write(creds.to_json())

        return build('gmail', 'v1', credentials=creds)

    def fetch_new_emails(self, max_results: int = 10) -> list[dict]:
        """
        Fetch new emails from INBOX and SPAM, skipping those already in DB.

        Spam is included so Stratos still analyzes messages that Gmail's
        own filter intercepts — a real BEP gateway would see those before
        any filter ran, so excluding them would understate detection.

        Args:
            max_results: Maximum number of messages to list from Gmail.

        Returns:
            List of raw Gmail API message dicts (full format) for new emails.
        """
        results = self.service.users().messages().list(
            userId='me', q='in:inbox OR in:spam', maxResults=max_results
        ).execute()

        messages = results.get('messages', [])
        new_messages = []

        for msg_stub in messages:
            msg_id = msg_stub['id']
            if Email.objects.filter(gmail_id=msg_id).exists():
                continue
            full_message = self.get_message(msg_id)
            new_messages.append(full_message)

        return new_messages

    def get_message(self, gmail_message_id: str) -> dict:
        """
        Get a full message from Gmail API.

        Args:
            gmail_message_id: The Gmail message ID.

        Returns:
            Raw Gmail API message dict in full format.
        """
        return self.service.users().messages().get(
            userId='me', id=gmail_message_id, format='full'
        ).execute()

    def mark_as_read(self, gmail_message_id: str) -> None:
        """
        Remove UNREAD label from a message.

        Args:
            gmail_message_id: The Gmail message ID.
        """
        self.service.users().messages().modify(
            userId='me',
            id=gmail_message_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

    def _fetch_attachment_data(self, gmail_message_id: str, attachment_id: str) -> bytes:
        """
        Fetch large attachment data via separate API call.

        Args:
            gmail_message_id: The Gmail message ID.
            attachment_id: The attachment ID from the message part.

        Returns:
            Decoded attachment bytes.
        """
        import base64

        attachment = self.service.users().messages().attachments().get(
            userId='me', messageId=gmail_message_id, id=attachment_id
        ).execute()

        data = attachment.get('data', '')
        return base64.urlsafe_b64decode(data)
