"""
Checker for Stratos BEP.
Stage 2 of the analysis pipeline: keyword scanning, URL analysis,
attachment inspection, and received chain anomaly detection.
"""
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from emails.models import ExtractedIOC
from threat_intel.models import MaliciousDomain, MaliciousHash

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    keyword_score: int = 0
    keywords_matched: list = field(default_factory=list)
    url_score: int = 0
    url_findings: list = field(default_factory=list)
    attachment_score: int = 0
    attachment_findings: list = field(default_factory=list)
    chain_score: int = 0
    chain_findings: dict = field(default_factory=dict)
    total_check_score: int = 0
    has_known_malware: bool = False


class Checker:
    """Runs content-level threat detection checks on an email."""

    KEYWORDS: list[str] = [
        'verify your account', 'urgent action required', 'confirm your identity',
        'unusual activity', 'suspended account', 'click here immediately',
        'update your payment', 'security alert', 'unauthorized access',
        'reset your password', 'limited time offer', 'act now',
        'your account will be closed', 'verify your information',
        'important security update', 'confirm your email',
        'invoice attached', 'wire transfer', 'bank account details',
        'confidential request', 'gift card', 'bitcoin payment',
        'do not share with anyone', 'reply urgently',
    ]  # 24 keywords

    DANGEROUS_EXTENSIONS: set[str] = {
        '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1',
        '.hta', '.com', '.dll', '.msi', '.pif', '.wsf',
    }

    URL_SHORTENERS: set[str] = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
        'ow.ly', 'buff.ly', 'short.io', 'rebrand.ly',
    }

    def check_all(self, email) -> CheckResult:
        """
        Run all content checks on the given email.

        Never raises exceptions to the caller. On any error, returns a safe
        default CheckResult with all zeros.

        Args:
            email: Email model instance with subject, body_text,
                   urls_extracted, received_chain populated.

        Returns:
            CheckResult dataclass with scores and findings.
        """
        try:
            result = CheckResult()

            # 1. Keyword check
            try:
                result.keyword_score, result.keywords_matched = self._check_keywords(email)
            except Exception:
                logger.exception("Keyword check failed for email %s", email.id)

            # 2. URL check
            try:
                result.url_score, result.url_findings = self._check_urls(email)
            except Exception:
                logger.exception("URL check failed for email %s", email.id)

            # 3. Attachment check
            try:
                result.attachment_score, result.attachment_findings, result.has_known_malware = (
                    self._check_attachments(email)
                )
            except Exception:
                logger.exception("Attachment check failed for email %s", email.id)

            # 4. Received chain check
            try:
                result.chain_score, result.chain_findings = self._check_received_chain(email)
            except Exception:
                logger.exception("Received chain check failed for email %s", email.id)

            result.total_check_score = (
                result.keyword_score
                + result.url_score
                + result.attachment_score
                + result.chain_score
            )

            return result

        except Exception:
            logger.exception("Checker.check_all() failed for email %s", getattr(email, 'id', '?'))
            return CheckResult()

    def _check_keywords(self, email) -> tuple[int, list[str]]:
        """
        Scan email subject and body for phishing keywords.

        Returns:
            (capped_score, list_of_matched_keywords)
        """
        subject = email.subject or ''
        body = email.body_text or ''
        combined = (subject + ' ' + body).lower()

        matched = []
        for keyword in self.KEYWORDS:
            if keyword in combined:
                matched.append(keyword)

        score = min(len(matched) * 2, 20)
        return score, matched

    def _check_urls(self, email) -> tuple[int, list[dict]]:
        """
        Analyse URLs extracted from the email for threat indicators.

        Returns:
            (capped_score, findings_list)
        """
        urls = email.urls_extracted
        if not urls:
            return 0, []

        score = 0
        findings = []
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = (parsed.hostname or '').lower()
                if not hostname:
                    continue

                # MaliciousDomain match
                if MaliciousDomain.objects.filter(domain__iexact=hostname).exists():
                    score += 30
                    findings.append({
                        'url': url, 'type': 'malicious_domain', 'domain': hostname,
                    })
                    # Create ExtractedIOC for malicious domain
                    ExtractedIOC.objects.create(
                        email=email,
                        ioc_type='DOMAIN',
                        value=hostname,
                        severity='HIGH',
                        source_checker='url_checker',
                    )

                # IP-based URL
                if ip_pattern.match(hostname):
                    score += 10
                    findings.append({
                        'url': url, 'type': 'ip_url', 'ip': hostname,
                    })

                # URL shortener
                if hostname in self.URL_SHORTENERS:
                    score += 5
                    findings.append({
                        'url': url, 'type': 'shortener', 'service': hostname,
                    })

            except Exception:
                logger.exception("Error checking URL: %s", url)
                continue

        capped = min(score, 40)
        return capped, findings

    def _check_attachments(self, email) -> tuple[int, list[dict], bool]:
        """
        Inspect email attachments for malware indicators.

        Returns:
            (capped_score, findings_list, has_known_malware)
        """
        attachments = email.attachments.all()
        if not attachments:
            return 0, [], False

        score = 0
        findings = []
        has_known_malware = False

        for attachment in attachments:
            try:
                filename = attachment.filename or ''
                sha256 = attachment.sha256_hash or ''

                # a. MaliciousHash match
                if sha256:
                    malicious_hash = MaliciousHash.objects.filter(
                        sha256_hash=sha256
                    ).first()
                    if malicious_hash:
                        score += 50
                        has_known_malware = True
                        attachment.ti_match = malicious_hash.source
                        findings.append({
                            'filename': filename,
                            'type': 'known_malware',
                            'sha256': sha256,
                            'malware_family': malicious_hash.malware_family,
                        })
                        # Create ExtractedIOC for malicious hash
                        ExtractedIOC.objects.create(
                            email=email,
                            ioc_type='HASH',
                            value=sha256,
                            severity=malicious_hash.severity,
                            source_checker='attachment_checker',
                        )

                # b. Dangerous extension
                parts = filename.rsplit('.', 1)
                ext = ('.' + parts[-1]).lower() if len(parts) > 1 else ''
                if ext in self.DANGEROUS_EXTENSIONS:
                    score += 15
                    attachment.is_dangerous_ext = True
                    findings.append({
                        'filename': filename,
                        'type': 'dangerous_ext',
                        'extension': ext,
                    })

                # c. Double extension
                name_parts = filename.split('.')
                if len(name_parts) >= 3:
                    last_ext = '.' + name_parts[-1].lower()
                    if last_ext in self.DANGEROUS_EXTENSIONS:
                        score += 20
                        attachment.is_double_ext = True
                        ext_chain = '.' + '.'.join(name_parts[1:])
                        findings.append({
                            'filename': filename,
                            'type': 'double_ext',
                            'extensions': ext_chain,
                        })

                # d. MIME mismatch
                if attachment.file_magic and attachment.content_type:
                    if attachment.content_type != attachment.file_magic:
                        score += 10
                        attachment.is_mime_mismatch = True
                        findings.append({
                            'filename': filename,
                            'type': 'mime_mismatch',
                            'declared': attachment.content_type,
                            'actual': attachment.file_magic,
                        })

                # e. YARA matches
                if attachment.yara_matches:
                    rule_names = attachment.yara_matches
                    if isinstance(rule_names, list) and len(rule_names) > 0:
                        score += 25 * len(rule_names)
                        findings.append({
                            'filename': filename,
                            'type': 'yara_match',
                            'rules': rule_names,
                        })

                # f. Save attachment with updated flags
                attachment.save()

            except Exception:
                logger.exception("Error checking attachment %s", getattr(attachment, 'id', '?'))
                continue

        capped = min(score, 50)
        return capped, findings, has_known_malware

    def _check_received_chain(self, email) -> tuple[int, dict]:
        """
        Analyse the received chain for anomalies.

        Returns:
            (capped_score, findings_dict)
        """
        chain = email.received_chain
        if not chain:
            return 0, {}

        score = 0
        findings = {}

        # Hop count check
        if len(chain) > 7:
            score += 5
            findings['excessive_hops'] = True
            findings['hop_count'] = len(chain)

        # Private IP check
        private_ips = []
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for hop in chain:
            hop_text = ''
            if isinstance(hop, dict):
                hop_text = str(hop.get('from', '')) + ' ' + str(hop.get('by', ''))
            elif isinstance(hop, str):
                hop_text = hop

            for ip_match in ip_pattern.findall(hop_text):
                try:
                    addr = ipaddress.ip_address(ip_match)
                    if addr.is_private:
                        private_ips.append(ip_match)
                except ValueError:
                    continue

        if private_ips:
            score += 5
            findings['private_ip_in_chain'] = True
            findings['ips'] = private_ips

        # Timestamp disorder check
        timestamps = []
        for hop in chain:
            ts = None
            if isinstance(hop, dict):
                ts = hop.get('timestamp')
            if ts is not None:
                timestamps.append(ts)

        if len(timestamps) >= 2:
            for i in range(len(timestamps) - 1):
                try:
                    if str(timestamps[i]) > str(timestamps[i + 1]):
                        score += 5
                        findings['timestamp_disorder'] = True
                        break
                except Exception:
                    continue

        capped = min(score, 15)
        return capped, findings
