"""
Decider for Stratos BEP.
Stage 3 of the analysis pipeline: combines Preprocessor and Checker scores
to produce a final verdict, confidence level, and recommended action.
"""
from dataclasses import dataclass

from django.conf import settings

from emails.services.checker import CheckResult
from emails.services.preprocessor import PreprocessResult


@dataclass
class DecisionResult:
    verdict: str  # CLEAN, SUSPICIOUS, or MALICIOUS
    total_score: int  # 0-100 capped
    confidence: str  # HIGH, MEDIUM, or LOW
    action: str  # DELIVER, QUARANTINE, or BLOCK
    preprocess_score: int
    check_score: int
    override_reason: str | None = None


class Decider:
    """Produces a final verdict from Preprocessor and Checker results."""

    CLEAN_THRESHOLD = getattr(settings, 'CLEAN_THRESHOLD', 25)
    MALICIOUS_THRESHOLD = getattr(settings, 'MALICIOUS_THRESHOLD', 70)

    def decide(self, preprocess_result: PreprocessResult, check_result: CheckResult) -> DecisionResult:
        """
        Combine preprocess and check scores to produce a final decision.

        Decision logic:
            1. Known malware override: if check_result.has_known_malware,
               force MALICIOUS/100/HIGH/BLOCK.
            2. Normal scoring: raw = preprocess_score + check_score, capped at 100.
            3. Thresholds: >=70 MALICIOUS, >=25 SUSPICIOUS, <25 CLEAN.

        Args:
            preprocess_result: PreprocessResult from the Preprocessor stage.
            check_result: CheckResult from the Checker stage.

        Returns:
            DecisionResult with verdict, score, confidence, and action.
        """
        preprocess_score = preprocess_result.score
        check_score = check_result.total_check_score

        # 1. Known malware override
        if check_result.has_known_malware:
            return DecisionResult(
                verdict='MALICIOUS',
                total_score=100,
                confidence='HIGH',
                action='BLOCK',
                preprocess_score=preprocess_score,
                check_score=check_score,
                override_reason='known_malware_hash',
            )

        # 2. Normal scoring
        raw = preprocess_score + check_score
        total = min(raw, 100)

        # 3. Verdict thresholds
        if total >= self.MALICIOUS_THRESHOLD:
            confidence = 'HIGH' if total >= 90 else 'MEDIUM'
            return DecisionResult(
                verdict='MALICIOUS',
                total_score=total,
                confidence=confidence,
                action='BLOCK',
                preprocess_score=preprocess_score,
                check_score=check_score,
            )

        if total >= self.CLEAN_THRESHOLD:
            return DecisionResult(
                verdict='SUSPICIOUS',
                total_score=total,
                confidence='LOW',
                action='QUARANTINE',
                preprocess_score=preprocess_score,
                check_score=check_score,
            )

        # total < 25
        confidence = 'HIGH' if total < 10 else 'MEDIUM'
        return DecisionResult(
            verdict='CLEAN',
            total_score=total,
            confidence=confidence,
            action='DELIVER',
            preprocess_score=preprocess_score,
            check_score=check_score,
        )
