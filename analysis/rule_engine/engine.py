"""
SecureMailScope Cryptographic Policy & Forensic Rule Engine — Engine Orchestrator.

Orchestrates input building, independent policy pack evaluations, forensic observations,
and structured session reporting.
"""

from typing import Any, Optional
from .schema import (
    RuleInput,
    StreamRuleReport,
    SessionReport,
    PolicyResult,
    ObservationResult,
)
from .input_builder import InputBuilder
from .rules import (
    NIST52r2Evaluator,
    NIST131aEvaluator,
    MozillaModernEvaluator,
    MozillaIntermediateEvaluator,
    ObservationsEvaluator,
)


class RuleEngine:
    """
    Deterministic cryptographic policy and forensic rule engine.
    Dispatches session telemetry across independent policy evaluators
    and policy-neutral forensic observations.
    """

    def __init__(
        self,
        mode: str = "gov_only",
        trust_store_manager: Optional[Any] = None,
    ):
        """
        mode: 'gov_only' or 'citizen_facing' (for NIST SP 800-52r2 TLS 1.0 scope).
        trust_store_manager: Optional TrustStoreManager instance for trust context.
        """
        self.mode = mode
        self.trust_store_manager = trust_store_manager

        # Initialize independent policy pack evaluators
        self.nist_52r2 = NIST52r2Evaluator(mode=mode)
        self.nist_131a = NIST131aEvaluator()
        self.moz_modern = MozillaModernEvaluator()
        self.moz_interm = MozillaIntermediateEvaluator()
        self.observations = ObservationsEvaluator()

    def evaluate_stream(self, session: dict[str, Any]) -> StreamRuleReport:
        """
        Evaluates a single session dictionary from PCAPAnalyzer.analyze().
        """
        r_in: RuleInput = InputBuilder.build(session, trust_store_manager=self.trust_store_manager)

        nist_52r2_res = self.nist_52r2.evaluate_all(r_in)
        nist_131a_res = self.nist_131a.evaluate_all(r_in)
        moz_modern_res = self.moz_modern.evaluate_all(r_in)
        moz_interm_res = self.moz_interm.evaluate_all(r_in)
        obs_res = self.observations.evaluate_all(r_in)

        policy_results = {
            "NIST-52R2": nist_52r2_res,
            "NIST-131A": nist_131a_res,
            "MOZ-MODERN": moz_modern_res,
            "MOZ-INTERM": moz_interm_res,
        }

        return StreamRuleReport(
            stream_id=r_in.get("stream_id", 0),
            protocol=r_in.get("protocol", "Unknown"),
            policy_results=policy_results,
            observations=obs_res,
            input_snapshot=r_in,
        )

    def evaluate_sessions(self, sessions: dict[int, dict[str, Any]]) -> SessionReport:
        """
        Evaluates all streams in a sessions dictionary.
        """
        reports: dict[int, StreamRuleReport] = {}
        for sid, sess in sessions.items():
            reports[sid] = self.evaluate_stream(sess)

        return SessionReport(
            stream_reports=reports,
            total_streams=len(sessions),
        )

    def evaluate_pcap(self, pcap_path: str, trust_store: str = "testbed") -> SessionReport:
        """
        Convenience end-to-end evaluation method running PCAPAnalyzer on a PCAP file.
        """
        from ..parser import PCAPAnalyzer
        analyzer = PCAPAnalyzer(pcap_path, trust_store=trust_store)
        if self.trust_store_manager is None:
            self.trust_store_manager = analyzer.trust_store_manager
        sessions = analyzer.analyze()
        return self.evaluate_sessions(sessions)
