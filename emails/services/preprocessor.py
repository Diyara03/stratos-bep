"""
Preprocessor for Stratos BEP.
Stage 1 of the analysis pipeline: whitelist/blacklist lookup,
SPF/DKIM/DMARC header parsing, BEC signal detection.
"""
import logging
import re
from dataclasses import dataclass, field

from threat_intel.models import BlacklistEntry, WhitelistEntry

logger = logging.getLogger(__name__)


@dataclass
class PreprocessResult:
    score: int = 0
    findings: dict = field(default_factory=dict)
    verdict_override: str | None = None
    spf_result: str = 'none'
    dkim_result: str = 'none'
    dmarc_result: str = 'none'
    is_reply_to_mismatch: bool = False
    is_display_spoof: bool = False


class Preprocessor:
    """Runs fast preprocess checks on an email and returns a PreprocessResult."""

    def process(self, email) -> PreprocessResult:
        """
        Run all preprocess checks on the given email.

        Never raises exceptions to the caller. On any error, returns a safe
        default PreprocessResult with score=0.

        Args:
            email: Email model instance with from_address, reply_to,
                   from_display_name, headers_raw populated.

        Returns:
            PreprocessResult dataclass with score and findings.
        """
        try:
            result = PreprocessResult()

            # 1. Whitelist check -- short-circuits if matched
            whitelisted, whitelist_result = self._check_whitelist(email.from_address)
            if whitelisted:
                return whitelist_result

            # 2. Blacklist check -- a match still goes through the rest of
            # preprocessing for score accumulation (so combined-signal tests
            # behave the same), but flips verdict_override to MALICIOUS so
            # the analyzer short-circuits to MALICIOUS/BLOCK regardless of
            # what the Checker would otherwise score.
            blacklist_findings, blacklist_score, is_blacklisted = self._check_blacklist(email.from_address)
            result.score += blacklist_score
            result.findings.update(blacklist_findings)
            if is_blacklisted:
                result.verdict_override = 'MALICIOUS'

            # 3. Email authentication check
            auth_findings, auth_score, spf, dkim, dmarc = self._check_email_auth(
                email.headers_raw
            )
            result.score += auth_score
            result.findings.update(auth_findings)
            result.spf_result = spf
            result.dkim_result = dkim
            result.dmarc_result = dmarc

            # 4. Reply-To mismatch check
            is_mismatch, mismatch_score, mismatch_findings = self._check_reply_to_mismatch(email)
            result.score += mismatch_score
            result.is_reply_to_mismatch = is_mismatch
            result.findings.update(mismatch_findings)

            # 5. Display name spoof check
            is_spoof, spoof_score, spoof_findings = self._check_display_spoof(email)
            result.score += spoof_score
            result.is_display_spoof = is_spoof
            result.findings.update(spoof_findings)

            return result

        except Exception:
            logger.exception("Preprocessor.process() failed for email %s", getattr(email, 'id', '?'))
            return PreprocessResult()

    def _check_whitelist(self, email_address: str) -> tuple[bool, PreprocessResult | None]:
        """
        Check if the email address or its domain is whitelisted.

        Returns:
            (True, PreprocessResult) if whitelisted, (False, None) otherwise.
        """
        try:
            domain = email_address.rsplit('@', 1)[-1].lower()

            # Check email whitelist
            email_match = WhitelistEntry.objects.filter(
                entry_type='EMAIL', value__iexact=email_address
            ).first()
            if email_match:
                return True, PreprocessResult(
                    score=0,
                    verdict_override='CLEAN',
                    findings={'whitelist': {'matched': True, 'value': email_match.value, 'type': 'EMAIL'}},
                )

            # Check domain whitelist
            domain_match = WhitelistEntry.objects.filter(
                entry_type='DOMAIN', value__iexact=domain
            ).first()
            if domain_match:
                return True, PreprocessResult(
                    score=0,
                    verdict_override='CLEAN',
                    findings={'whitelist': {'matched': True, 'value': domain_match.value, 'type': 'DOMAIN'}},
                )

            return False, None

        except Exception:
            logger.exception("Whitelist check failed for %s", email_address)
            return False, None

    def _check_blacklist(self, email_address: str) -> tuple[dict, int, bool]:
        """
        Check if the email address or its domain is blacklisted.

        Returns:
            (findings_dict, total_blacklist_score, is_blacklisted)
        """
        try:
            domain = email_address.rsplit('@', 1)[-1].lower()
            findings = {}
            score = 0
            matched = False

            if BlacklistEntry.objects.filter(
                entry_type='EMAIL', value__iexact=email_address
            ).exists():
                score += 40
                findings['blacklist_email'] = True
                matched = True

            if BlacklistEntry.objects.filter(
                entry_type='DOMAIN', value__iexact=domain
            ).exists():
                score += 30
                findings['blacklist_domain'] = True
                matched = True

            return findings, score, matched

        except Exception:
            logger.exception("Blacklist check failed for %s", email_address)
            return {}, 0, False

    def _check_email_auth(self, headers_raw) -> tuple[dict, int, str, str, str]:
        """
        Parse Authentication-Results header from headers_raw.

        Args:
            headers_raw: List of {name, value} dicts from Gmail API.

        Returns:
            (findings_dict, auth_score, spf_result, dkim_result, dmarc_result)
        """
        try:
            spf = 'none'
            dkim = 'none'
            dmarc = 'none'

            # Find Authentication-Results header
            auth_header = None
            if isinstance(headers_raw, list):
                for header in headers_raw:
                    if isinstance(header, dict) and header.get('name', '').lower() == 'authentication-results':
                        auth_header = header.get('value', '')
                        break

            if auth_header:
                # Parse SPF
                spf_match = re.search(r'spf=(\w+)', auth_header)
                if spf_match:
                    spf_val = spf_match.group(1).lower()
                    if spf_val in ('pass', 'fail', 'softfail', 'none'):
                        spf = spf_val

                # Parse DKIM
                dkim_match = re.search(r'dkim=(\w+)', auth_header)
                if dkim_match:
                    dkim_val = dkim_match.group(1).lower()
                    if dkim_val in ('pass', 'fail', 'none'):
                        dkim = dkim_val

                # Parse DMARC
                dmarc_match = re.search(r'dmarc=(\w+)', auth_header)
                if dmarc_match:
                    dmarc_val = dmarc_match.group(1).lower()
                    if dmarc_val in ('pass', 'fail', 'none'):
                        dmarc = dmarc_val

            # Calculate score
            spf_scores = {'pass': 0, 'softfail': 5, 'fail': 15, 'none': 10}
            dkim_scores = {'pass': 0, 'fail': 15, 'none': 5}
            dmarc_scores = {'pass': 0, 'fail': 15, 'none': 5}

            auth_score = spf_scores[spf] + dkim_scores[dkim] + dmarc_scores[dmarc]

            findings = {
                'auth': {
                    'spf': spf,
                    'dkim': dkim,
                    'dmarc': dmarc,
                    'score_contribution': auth_score,
                }
            }

            return findings, auth_score, spf, dkim, dmarc

        except Exception:
            logger.exception("Email auth check failed")
            return {}, 0, 'none', 'none', 'none'

    def _check_reply_to_mismatch(self, email) -> tuple[bool, int, dict]:
        """
        Check if Reply-To domain differs from From domain.

        Returns:
            (is_mismatch, score_contribution, findings_dict)
        """
        try:
            if not email.reply_to:
                return False, 0, {}

            from_domain = email.from_address.rsplit('@', 1)[-1].lower()
            reply_to_domain = email.reply_to.rsplit('@', 1)[-1].lower()

            if from_domain != reply_to_domain:
                findings = {
                    'reply_to_mismatch': {
                        'from_domain': from_domain,
                        'reply_to_domain': reply_to_domain,
                    }
                }
                return True, 10, findings

            return False, 0, {}

        except Exception:
            logger.exception("Reply-To mismatch check failed")
            return False, 0, {}

    def _check_display_spoof(self, email) -> tuple[bool, int, dict]:
        """
        Check if display name contains a foreign domain (spoof indicator).

        Returns:
            (is_spoof, score_contribution, findings_dict)
        """
        try:
            display_name = email.from_display_name
            if not display_name:
                return False, 0, {}

            from_domain = email.from_address.rsplit('@', 1)[-1].lower()

            # Check for @ sign in display name
            if '@' in display_name:
                # Extract the domain from the email-like pattern in display name
                at_match = re.search(r'@([\w.-]+)', display_name)
                if at_match:
                    spoofed_domain = at_match.group(1).lower()
                    if spoofed_domain != from_domain:
                        findings = {
                            'display_spoof': {
                                'display_name': display_name,
                                'actual_domain': from_domain,
                                'spoofed_domain': spoofed_domain,
                            }
                        }
                        return True, 10, findings

            # Check for domain-like pattern
            domain_pattern = r'\b[\w.-]+\.(com|org|net|edu|gov|io|co|uk|ru|info|biz)\b'
            domain_match = re.search(domain_pattern, display_name, re.IGNORECASE)
            if domain_match:
                spoofed_domain = domain_match.group(0).lower()
                if spoofed_domain != from_domain:
                    findings = {
                        'display_spoof': {
                            'display_name': display_name,
                            'actual_domain': from_domain,
                            'spoofed_domain': spoofed_domain,
                        }
                    }
                    return True, 10, findings

            return False, 0, {}

        except Exception:
            logger.exception("Display spoof check failed")
            return False, 0, {}
