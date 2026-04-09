"""
Email analyzer for Stratos BEP.
Orchestrates the analysis pipeline: Preprocessor -> Checker -> Decider.
"""
import logging
import time

from django.utils import timezone

from emails.models import AnalysisResult, Email, QuarantineEntry
from emails.services.checker import CheckResult, Checker
from emails.services.decider import Decider, DecisionResult
from emails.services.preprocessor import Preprocessor, PreprocessResult

logger = logging.getLogger(__name__)

ACTION_STATUS_MAP = {
    'DELIVER': 'DELIVERED',
    'QUARANTINE': 'QUARANTINED',
    'BLOCK': 'BLOCKED',
}


class EmailAnalyzer:
    """Orchestrates the email analysis pipeline."""

    def analyze(self, email_id: int) -> None:
        """
        Run the full analysis pipeline on an email.

        Pipeline stages:
            1. Set Email.status = 'ANALYZING'
            2. Run Preprocessor
            3. If whitelist match: finalize as CLEAN/DELIVERED
            4. Else: save preprocess result, run Checker, run Decider, finalize

        Args:
            email_id: Primary key of the Email to analyze.

        Raises:
            Email.DoesNotExist: If email_id is invalid.
        """
        start = time.time()
        email = Email.objects.select_related('analysis').get(id=email_id)
        email.status = 'ANALYZING'
        email.save(update_fields=['status', 'updated_at'])

        preprocess_result = Preprocessor().process(email)

        if preprocess_result.verdict_override == 'CLEAN':
            # Whitelist short-circuit
            self._finalize(
                email,
                verdict='CLEAN',
                score=0,
                confidence='HIGH',
                action='DELIVER',
                preprocess_result=preprocess_result,
                check_result=None,
                duration_ms=int((time.time() - start) * 1000),
            )
            return

        self._save_preprocess_result(email, preprocess_result)

        check_result = Checker().check_all(email)
        self._save_check_result(email, check_result)

        decision = Decider().decide(preprocess_result, check_result)

        self._finalize(
            email,
            verdict=decision.verdict,
            score=decision.total_score,
            confidence=decision.confidence,
            action=decision.action,
            preprocess_result=preprocess_result,
            check_result=check_result,
            duration_ms=int((time.time() - start) * 1000),
        )

    def _finalize(self, email: Email, verdict: str, score: int,
                  confidence: str, action: str,
                  preprocess_result: PreprocessResult,
                  check_result: CheckResult | None,
                  duration_ms: int) -> None:
        """
        Finalize analysis: update AnalysisResult with total_score and duration,
        set email verdict/status, create QuarantineEntry if needed.

        Args:
            email: Email model instance.
            verdict: Final verdict (CLEAN/SUSPICIOUS/MALICIOUS).
            score: Total combined score.
            confidence: Confidence level (LOW/MEDIUM/HIGH).
            action: Recommended action (DELIVER/QUARANTINE/BLOCK).
            preprocess_result: PreprocessResult from the Preprocessor.
            check_result: CheckResult from the Checker (None for whitelist short-circuit).
            duration_ms: Pipeline duration in milliseconds.
        """
        # Build defaults for AnalysisResult
        defaults = {
            'preprocess_score': preprocess_result.score,
            'spf_result': preprocess_result.spf_result,
            'dkim_result': preprocess_result.dkim_result,
            'dmarc_result': preprocess_result.dmarc_result,
            'is_reply_to_mismatch': preprocess_result.is_reply_to_mismatch,
            'is_display_spoof': preprocess_result.is_display_spoof,
            'total_score': score,
            'pipeline_duration_ms': duration_ms,
        }

        if check_result is not None:
            defaults.update({
                'keyword_score': check_result.keyword_score,
                'keywords_matched': check_result.keywords_matched,
                'url_score': check_result.url_score,
                'url_findings': check_result.url_findings,
                'attachment_score': check_result.attachment_score,
                'attachment_findings': check_result.attachment_findings,
                'chain_score': check_result.chain_score,
                'chain_findings': check_result.chain_findings,
            })

        AnalysisResult.objects.update_or_create(
            email=email,
            defaults=defaults,
        )

        # Update email fields
        email.verdict = verdict
        email.score = score
        email.confidence = confidence
        email.analyzed_at = timezone.now()
        email.status = ACTION_STATUS_MAP.get(action, 'DELIVERED')
        email.save(update_fields=[
            'verdict', 'status', 'confidence', 'score', 'analyzed_at', 'updated_at',
        ])

        # Create QuarantineEntry for QUARANTINE or BLOCK actions
        if action in ('QUARANTINE', 'BLOCK'):
            QuarantineEntry.objects.get_or_create(
                email=email,
                defaults={
                    'status': 'PENDING',
                    'action': action,
                },
            )

    def _save_preprocess_result(self, email: Email, result: PreprocessResult) -> None:
        """
        Save preprocess results to AnalysisResult without finalizing the email.

        Does NOT set total_score (Decider does that in _finalize).
        Leaves email.status as 'ANALYZING'.

        Args:
            email: Email model instance.
            result: PreprocessResult from the Preprocessor.
        """
        AnalysisResult.objects.update_or_create(
            email=email,
            defaults={
                'preprocess_score': result.score,
                'spf_result': result.spf_result,
                'dkim_result': result.dkim_result,
                'dmarc_result': result.dmarc_result,
                'is_reply_to_mismatch': result.is_reply_to_mismatch,
                'is_display_spoof': result.is_display_spoof,
            },
        )

    def _save_check_result(self, email: Email, check_result: CheckResult) -> None:
        """
        Save Checker results to the existing AnalysisResult.

        Does NOT set total_score or verdict -- that is the Decider's job in _finalize.

        Args:
            email: Email model instance.
            check_result: CheckResult from the Checker.
        """
        AnalysisResult.objects.filter(email=email).update(
            keyword_score=check_result.keyword_score,
            keywords_matched=check_result.keywords_matched,
            url_score=check_result.url_score,
            url_findings=check_result.url_findings,
            attachment_score=check_result.attachment_score,
            attachment_findings=check_result.attachment_findings,
            chain_score=check_result.chain_score,
            chain_findings=check_result.chain_findings,
        )
