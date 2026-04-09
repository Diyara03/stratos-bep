"""
Phase 8 — Decider Boundary Tests.
Direct unit tests on Decider.decide() covering all threshold boundaries.
"""
from django.test import TestCase

from emails.services.checker import CheckResult
from emails.services.decider import Decider
from emails.services.preprocessor import PreprocessResult


class DeciderBoundaryTests(TestCase):
    """Test exact boundary values for the Decider scoring thresholds."""

    def _pre(self, score=0):
        return PreprocessResult(score=score)

    def _chk(self, total=0, has_known_malware=False):
        return CheckResult(total_check_score=total, has_known_malware=has_known_malware)

    def test_ac_201_score_24_is_clean(self):
        """AC-201: total=24 -> CLEAN (just below SUSPICIOUS threshold)."""
        d = Decider().decide(self._pre(12), self._chk(12))
        self.assertEqual(d.verdict, 'CLEAN')
        self.assertEqual(d.total_score, 24)
        self.assertEqual(d.action, 'DELIVER')

    def test_ac_202_score_25_is_suspicious(self):
        """AC-202: total=25 -> SUSPICIOUS (exact threshold)."""
        d = Decider().decide(self._pre(13), self._chk(12))
        self.assertEqual(d.verdict, 'SUSPICIOUS')
        self.assertEqual(d.total_score, 25)
        self.assertEqual(d.action, 'QUARANTINE')

    def test_ac_203_score_69_is_suspicious(self):
        """AC-203: total=69 -> SUSPICIOUS (just below MALICIOUS threshold)."""
        d = Decider().decide(self._pre(34), self._chk(35))
        self.assertEqual(d.verdict, 'SUSPICIOUS')
        self.assertEqual(d.total_score, 69)

    def test_ac_204_score_70_is_malicious(self):
        """AC-204: total=70 -> MALICIOUS (exact threshold)."""
        d = Decider().decide(self._pre(35), self._chk(35))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 70)
        self.assertEqual(d.action, 'BLOCK')

    def test_ac_205_score_100_malicious_high(self):
        """AC-205: total=100 -> MALICIOUS, HIGH confidence."""
        d = Decider().decide(self._pre(50), self._chk(50))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 100)
        self.assertEqual(d.confidence, 'HIGH')

    def test_ac_206_score_0_clean_high(self):
        """AC-206: total=0 -> CLEAN, HIGH confidence."""
        d = Decider().decide(self._pre(0), self._chk(0))
        self.assertEqual(d.verdict, 'CLEAN')
        self.assertEqual(d.total_score, 0)
        self.assertEqual(d.confidence, 'HIGH')

    def test_ac_207_known_malware_overrides_score_0(self):
        """AC-207: has_known_malware=True with low scores -> MALICIOUS, score=100."""
        d = Decider().decide(self._pre(0), self._chk(0, has_known_malware=True))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 100)
        self.assertEqual(d.confidence, 'HIGH')
        self.assertEqual(d.action, 'BLOCK')
        self.assertEqual(d.override_reason, 'known_malware_hash')

    def test_ac_208_known_malware_overrides_score_24(self):
        """AC-208: has_known_malware=True even when raw score=24 -> MALICIOUS."""
        d = Decider().decide(self._pre(12), self._chk(12, has_known_malware=True))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 100)

    def test_ac_209_score_89_malicious_medium(self):
        """AC-209: total=89 -> MALICIOUS, MEDIUM confidence."""
        d = Decider().decide(self._pre(44), self._chk(45))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 89)
        self.assertEqual(d.confidence, 'MEDIUM')

    def test_ac_210_score_90_malicious_high(self):
        """AC-210: total=90 -> MALICIOUS, HIGH confidence."""
        d = Decider().decide(self._pre(45), self._chk(45))
        self.assertEqual(d.verdict, 'MALICIOUS')
        self.assertEqual(d.total_score, 90)
        self.assertEqual(d.confidence, 'HIGH')

    def test_ac_211_score_9_clean_high(self):
        """AC-211: total=9 -> CLEAN, HIGH confidence."""
        d = Decider().decide(self._pre(4), self._chk(5))
        self.assertEqual(d.verdict, 'CLEAN')
        self.assertEqual(d.total_score, 9)
        self.assertEqual(d.confidence, 'HIGH')

    def test_ac_212_score_10_clean_medium(self):
        """AC-212: total=10 -> CLEAN, MEDIUM confidence."""
        d = Decider().decide(self._pre(5), self._chk(5))
        self.assertEqual(d.verdict, 'CLEAN')
        self.assertEqual(d.total_score, 10)
        self.assertEqual(d.confidence, 'MEDIUM')

    def test_ac_213_score_capped_at_100(self):
        """AC-213: raw score > 100 is capped to 100."""
        d = Decider().decide(self._pre(60), self._chk(80))
        self.assertEqual(d.total_score, 100)

    def test_ac_214_preprocess_and_check_scores_preserved(self):
        """AC-214: DecisionResult preserves individual preprocess/check scores."""
        d = Decider().decide(self._pre(15), self._chk(30))
        self.assertEqual(d.preprocess_score, 15)
        self.assertEqual(d.check_score, 30)
        self.assertEqual(d.total_score, 45)
