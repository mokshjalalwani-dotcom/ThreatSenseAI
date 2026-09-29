"""
EnsembleBackend — weighted combination of rules + optional zeroshot.

Weights:
  - Rules score weight: 0.6
  - ZeroShot score weight: 0.4 (only when NLP_ZEROSHOT=true)
  - If zeroshot unavailable, full weight falls to rules (1.0).
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.engines.nlp.backends.rules import RulesBackend
from app.engines.nlp.backends.zeroshot import ZeroShotBackend, _load_pipeline
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)

_RULES_W = 0.6
_ZS_W = 0.4


def _blend(a: float, b: float, wa: float, wb: float) -> float:
    return round(min(1.0, a * wa + b * wb), 4)


class EnsembleBackend(SignalBackend):
    """Weighted ensemble of rules + zeroshot backends.

    When zeroshot model is not available (NLP_ZEROSHOT!=true or model load failed),
    this is equivalent to RulesBackend with weight 1.0.
    """

    @property
    def backend_name(self) -> str:
        return "ensemble"

    async def analyze(self, text: str) -> NLPSignals:
        rules_result = await RulesBackend().analyze(text)

        if _load_pipeline() is None:
            return rules_result.model_copy(update={"backend_used": "ensemble_rules_only"})

        zs_result = await ZeroShotBackend().analyze(text)

        return NLPSignals(
            urgency=_blend(rules_result.urgency, zs_result.urgency, _RULES_W, _ZS_W),
            fear=_blend(rules_result.fear, zs_result.fear, _RULES_W, _ZS_W),
            authority=_blend(rules_result.authority, zs_result.authority, _RULES_W, _ZS_W),
            reward_scarcity=_blend(rules_result.reward_scarcity, zs_result.reward_scarcity, _RULES_W, _ZS_W),
            financial_intent=_blend(rules_result.financial_intent, zs_result.financial_intent, _RULES_W, _ZS_W),
            credential_request=_blend(rules_result.credential_request, zs_result.credential_request, _RULES_W, _ZS_W),
            manipulation=_blend(rules_result.manipulation, zs_result.manipulation, _RULES_W, _ZS_W),
            phishing_intent=_blend(rules_result.phishing_intent, zs_result.phishing_intent, _RULES_W, _ZS_W),
            scam_intent=_blend(rules_result.scam_intent, zs_result.scam_intent, _RULES_W, _ZS_W),
            investment_context=_blend(rules_result.investment_context, zs_result.investment_context, _RULES_W, _ZS_W),
            recruitment_context=_blend(rules_result.recruitment_context, zs_result.recruitment_context, _RULES_W, _ZS_W),
            tech_support_context=_blend(rules_result.tech_support_context, zs_result.tech_support_context, _RULES_W, _ZS_W),
            government_service_claim=_blend(rules_result.government_service_claim, zs_result.government_service_claim, _RULES_W, _ZS_W),
            claimed_org=rules_result.claimed_org or zs_result.claimed_org,
            payment_request=_blend(rules_result.payment_request, zs_result.payment_request, _RULES_W, _ZS_W),
            remote_access_request=_blend(rules_result.remote_access_request, zs_result.remote_access_request, _RULES_W, _ZS_W),
            evidence_spans=rules_result.evidence_spans,  # spans only from rules for now
            backend_used="ensemble",
            language_hint=rules_result.language_hint,
            text_length=rules_result.text_length,
        )
