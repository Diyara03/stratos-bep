"""
Email parser for Stratos BEP.
Parses raw Gmail API message dicts into Email model instances.
"""
import base64
import hashlib
import logging
import re
from datetime import datetime
from email.header import decode_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from bs4 import BeautifulSoup
from django.utils import timezone

from emails.models import Email

logger = logging.getLogger(__name__)


class EmailParser:
    """Parses raw Gmail API messages into structured Email data."""

    def parse_gmail_message(self, raw_message: dict) -> tuple:
        """
        Parse a raw Gmail API message dict into an unsaved Email instance
        and a list of attachment dicts.

        Args:
            raw_message: Raw Gmail API message dict (full format).

        Returns:
            Tuple of (unsaved Email instance, list of attachment dicts).
            Each attachment dict has keys:
            {filename, content_type, size_bytes, content, sha256_hash, md5_hash}
        """
        payload = raw_message.get('payload', {})
        headers = payload.get('headers', [])

        # Extract all fields
        message_id = self._extract_message_id(headers)
        if not message_id:
            message_id = raw_message.get('id', '')

        from_display_name, from_address = self._extract_from(headers)
        to_addresses = self._extract_to(headers)
        cc_addresses = self._extract_cc(headers)
        subject = self._extract_subject(headers)
        received_at = self._extract_date(headers)
        reply_to = self._extract_reply_to(headers)
        body_text, body_html = self._extract_body(payload)
        urls_extracted = self._extract_urls(body_text, body_html)
        received_chain = self._extract_received_chain(headers)
        attachments = self._extract_attachments(payload)

        email_instance = Email(
            message_id=message_id,
            gmail_id=raw_message.get('id', ''),
            from_address=from_address,
            from_display_name=from_display_name,
            to_addresses=to_addresses,
            cc_addresses=cc_addresses,
            reply_to=reply_to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            headers_raw=headers,
            received_chain=received_chain,
            urls_extracted=urls_extracted,
            status='PENDING',
            received_at=received_at,
        )

        return email_instance, attachments

    def _extract_header_value(self, headers: list, name: str) -> str:
        """
        Get a single header value by name from Gmail headers list.

        Args:
            headers: List of {name: str, value: str} dicts.
            name: Header name to find (case-insensitive).

        Returns:
            Header value string, or empty string if not found.
        """
        name_lower = name.lower()
        for header in headers:
            if header.get('name', '').lower() == name_lower:
                return header.get('value', '')
        return ''

    def _extract_message_id(self, headers: list) -> str:
        """
        Get Message-ID header, strip angle brackets.

        Args:
            headers: Gmail headers list.

        Returns:
            Message-ID string without < >, or empty string.
        """
        raw = self._extract_header_value(headers, 'Message-ID')
        return raw.strip('<>').strip()

    def _extract_from(self, headers: list) -> tuple:
        """
        Parse From header into display name and email address.

        Args:
            headers: Gmail headers list.

        Returns:
            Tuple of (display_name, email_address).
        """
        raw_from = self._extract_header_value(headers, 'From')
        display_name, email_address = parseaddr(raw_from)
        return display_name, email_address

    def _extract_to(self, headers: list) -> list:
        """
        Parse To header into list of email addresses.

        Args:
            headers: Gmail headers list.

        Returns:
            List of email address strings.
        """
        raw_to = self._extract_header_value(headers, 'To')
        if not raw_to:
            return []
        addresses = getaddresses([raw_to])
        return list(dict.fromkeys(addr for _, addr in addresses if addr))

    def _extract_cc(self, headers: list) -> list:
        """
        Parse Cc header into list of email addresses.

        Args:
            headers: Gmail headers list.

        Returns:
            List of email address strings, or empty list.
        """
        raw_cc = self._extract_header_value(headers, 'Cc')
        if not raw_cc:
            return []
        addresses = getaddresses([raw_cc])
        return list(dict.fromkeys(addr for _, addr in addresses if addr))

    def _extract_subject(self, headers: list) -> str:
        """
        Get Subject header. Decode RFC 2047 encoded words.

        Args:
            headers: Gmail headers list.

        Returns:
            Decoded subject string.
        """
        raw_subject = self._extract_header_value(headers, 'Subject')
        if not raw_subject:
            return ''
        decoded_parts = decode_header(raw_subject)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(encoding or 'utf-8', errors='replace'))
            else:
                result.append(part)
        return ''.join(result)

    def _extract_date(self, headers: list) -> datetime:
        """
        Parse Date header to timezone-aware datetime.

        Args:
            headers: Gmail headers list.

        Returns:
            Timezone-aware datetime. Falls back to now() on failure.
        """
        raw_date = self._extract_header_value(headers, 'Date')
        if not raw_date:
            return timezone.now()
        try:
            dt = parsedate_to_datetime(raw_date)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt)
            return dt
        except (ValueError, TypeError):
            return timezone.now()

    def _extract_reply_to(self, headers: list):
        """
        Extract Reply-To header email address.

        Args:
            headers: Gmail headers list.

        Returns:
            Email address string, or None if not present.
        """
        raw = self._extract_header_value(headers, 'Reply-To')
        if not raw:
            return None
        _, email_address = parseaddr(raw)
        return email_address if email_address else None

    def _extract_body(self, payload: dict) -> tuple:
        """
        Extract email body from Gmail payload structure.

        Handles multipart/alternative, multipart/mixed, and simple messages.
        Gmail encodes body.data as URL-safe base64.

        Args:
            payload: Gmail message payload dict.

        Returns:
            Tuple of (body_text, body_html).
        """
        body_text = ''
        body_html = ''

        def _traverse(part):
            nonlocal body_text, body_html
            mime_type = part.get('mimeType', '')
            body_data = part.get('body', {}).get('data', '')

            if mime_type == 'text/plain' and body_data and not body_text:
                body_text = base64.urlsafe_b64decode(body_data).decode(
                    'utf-8', errors='replace'
                )
            elif mime_type == 'text/html' and body_data and not body_html:
                body_html = base64.urlsafe_b64decode(body_data).decode(
                    'utf-8', errors='replace'
                )

            # Recurse into sub-parts
            for sub_part in part.get('parts', []):
                _traverse(sub_part)

        _traverse(payload)
        return body_text, body_html

    def _extract_urls(self, body_text: str, body_html: str) -> list:
        """
        Extract URLs from email body text and HTML.

        Args:
            body_text: Plain text body.
            body_html: HTML body.

        Returns:
            Deduplicated list of URL strings.
        """
        urls = []
        seen = set()

        # Extract from plain text
        if body_text:
            text_urls = re.findall(r'https?://[^\s<>"\']+', body_text)
            for url in text_urls:
                if url not in seen:
                    urls.append(url)
                    seen.add(url)

        # Extract from HTML
        if body_html:
            soup = BeautifulSoup(body_html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith(('http://', 'https://')) and href not in seen:
                    urls.append(href)
                    seen.add(href)

        return urls

    def _extract_attachments(self, payload: dict, service=None,
                             gmail_message_id: str = None) -> list:
        """
        Extract attachment metadata and content from Gmail payload.

        Args:
            payload: Gmail message payload dict.
            service: Gmail API service (for fetching large attachments).
            gmail_message_id: Gmail message ID (for fetching large attachments).

        Returns:
            List of attachment dicts with keys:
            {filename, content_type, size_bytes, content, sha256_hash, md5_hash}
        """
        attachments = []

        def _traverse(part):
            filename = part.get('filename', '')
            if filename:
                body = part.get('body', {})
                content_type = part.get('mimeType', 'application/octet-stream')
                size_bytes = body.get('size', 0)
                data = body.get('data', '')
                attachment_id = body.get('attachmentId', '')

                content = b''
                if data:
                    content = base64.urlsafe_b64decode(data)
                elif attachment_id and service and gmail_message_id:
                    # Large attachment -- needs separate API call
                    try:
                        att_response = service.users().messages().attachments().get(
                            userId='me',
                            messageId=gmail_message_id,
                            id=attachment_id
                        ).execute()
                        att_data = att_response.get('data', '')
                        if att_data:
                            content = base64.urlsafe_b64decode(att_data)
                    except Exception:
                        logger.warning(
                            "Failed to fetch attachment %s for message %s",
                            attachment_id, gmail_message_id
                        )

                sha256_hash, md5_hash = self._compute_hashes(content)

                attachments.append({
                    'filename': filename,
                    'content_type': content_type,
                    'size_bytes': size_bytes,
                    'content': content,
                    'sha256_hash': sha256_hash,
                    'md5_hash': md5_hash,
                })

            for sub_part in part.get('parts', []):
                _traverse(sub_part)

        _traverse(payload)
        return attachments

    def _compute_hashes(self, content: bytes) -> tuple:
        """
        Compute SHA-256 and MD5 hex digests.

        Args:
            content: Raw bytes to hash.

        Returns:
            Tuple of (sha256_hex, md5_hex).
        """
        sha256_hex = hashlib.sha256(content).hexdigest()
        md5_hex = hashlib.md5(content).hexdigest()
        return sha256_hex, md5_hex

    def _extract_received_chain(self, headers: list) -> list:
        """
        Parse all Received headers into structured list.

        Args:
            headers: Gmail headers list.

        Returns:
            List of dicts with {from_server, by_server, timestamp_str}.
        """
        chain = []
        for header in headers:
            if header.get('name', '').lower() == 'received':
                value = header.get('value', '')
                from_match = re.search(r'from\s+([\w.\-]+)', value)
                by_match = re.search(r'by\s+([\w.\-]+)', value)
                # Timestamp is typically after the semicolon
                timestamp_str = ''
                if ';' in value:
                    timestamp_str = value.split(';', 1)[1].strip()

                chain.append({
                    'from_server': from_match.group(1) if from_match else '',
                    'by_server': by_match.group(1) if by_match else '',
                    'timestamp_str': timestamp_str,
                })
        return chain

    def _extract_auth_results(self, headers: list) -> dict:
        """
        Parse Authentication-Results header for SPF, DKIM, DMARC results.

        Args:
            headers: Gmail headers list.

        Returns:
            Dict with keys: spf, dkim, dmarc.
            Each value is one of: 'pass', 'fail', 'softfail', 'none'.
        """
        result = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        auth_header = self._extract_header_value(headers, 'Authentication-Results')
        if not auth_header:
            return result

        spf_match = re.search(r'spf=(\w+)', auth_header)
        dkim_match = re.search(r'dkim=(\w+)', auth_header)
        dmarc_match = re.search(r'dmarc=(\w+)', auth_header)

        if spf_match:
            result['spf'] = spf_match.group(1).lower()
        if dkim_match:
            result['dkim'] = dkim_match.group(1).lower()
        if dmarc_match:
            result['dmarc'] = dmarc_match.group(1).lower()

        return result
