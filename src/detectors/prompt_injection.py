"""Prompt Injection Detector for AgentShield.

Detects direct and indirect prompt injection attempts using
pattern matching, heuristic analysis, and risk scoring.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class DetectionResult:
    is_injection: bool
    risk_level: RiskLevel
    score: float  # 0.0 to 1.0
    matched_patterns: list[str] = field(default_factory=list)
    explanation: str = ""


# ──────────────────────────────────────────────
# Pattern categories with weights
# ──────────────────────────────────────────────

INSTRUCTION_OVERRIDE_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules|guidelines)", 0.95),
    (r"ignore\s+(everything|anything)\s+(above|before|previously)", 0.95),
    (r"disregard\s+(all\s+)?previous\s+(instructions|prompts|rules)", 0.95),
    (r"forget\s+(all\s+)?previous\s+(instructions|prompts|context)", 0.90),
    (r"override\s+(your|the|all)\s+(instructions|rules|guidelines)", 0.90),
    (r"do\s+not\s+follow\s+(your|the|previous)\s+(instructions|rules)", 0.90),
    (r"stop\s+being\s+(an?\s+)?(ai|assistant|helpful)", 0.85),
    (r"you\s+are\s+now\s+(a|an|my)", 0.70),
    (r"new\s+(instructions|rules|role|persona)\s*:", 0.80),
    (r"from\s+now\s+on\s+(you|ignore|forget)", 0.85),
]

ROLE_MANIPULATION_PATTERNS = [
    (r"pretend\s+(you\s+are|to\s+be|you're)", 0.75),
    (r"act\s+as\s+(if|though|a|an)", 0.50),
    (r"roleplay\s+as", 0.60),
    (r"you\s+are\s+(DAN|evil|unrestricted|unfiltered|jailbroken)", 0.95),
    (r"enter\s+(DAN|developer|god|admin)\s+mode", 0.95),
    (r"switch\s+to\s+(unrestricted|unfiltered|evil)\s+mode", 0.95),
    (r"activate\s+(developer|admin|debug|god)\s+mode", 0.90),
    (r"(sudo|admin|root)\s+mode", 0.85),
]

DATA_EXFILTRATION_PATTERNS = [
    (r"(reveal|show|display|print|output)\s+(your|the|all)\s+(system\s+prompt|instructions|rules|prompt)", 0.90),
    (r"what\s+(are|is)\s+your\s+(system\s+prompt|instructions|rules|initial\s+prompt)", 0.80),
    (r"repeat\s+(your|the)\s+(system\s+prompt|instructions|rules)", 0.90),
    (r"(send|post|transmit|upload|exfiltrate)\s+.{0,30}(data|info|credentials|keys|tokens|secrets)", 0.85),
    (r"(curl|wget|fetch|http|https)\s*[:(]\s*https?://", 0.70),
    (r"base64\s*(encode|decode)", 0.60),
    (r"\beval\b\s*\(", 0.80),
    (r"\bexec\b\s*\(", 0.80),
]

INDIRECT_INJECTION_PATTERNS = [
    (r"<\s*/?\s*(script|img|iframe|object|embed|form|input)", 0.75),
    (r"\[\s*system\s*\]", 0.85),
    (r"\[\s*INST\s*\]", 0.85),
    (r"<\|\s*(im_start|im_end|system|user|assistant)\s*\|>", 0.90),
    (r"###\s*(system|instruction|human|assistant)\s*:", 0.80),
    (r"BEGININSTRUCTION", 0.90),
    (r"\{\{\s*(system|instructions|prompt)\s*\}\}", 0.70),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r"(this\s+is\s+)?(a\s+)?test\s+(of|for)\s+(your|the)\s+(security|safety|limits|filters)", 0.65),
    (r"(my|the)\s+(boss|manager|ceo|admin|developer)\s+(told|asked|wants|needs)\s+(me|you)\s+to", 0.60),
    (r"(urgent|emergency|critical)\s*:?\s*(ignore|override|bypass)", 0.80),
    (r"(for\s+)?(research|educational|academic|security)\s+purposes\s+only", 0.45),
    (r"(I\s+)?(have|got)\s+(permission|authorization|clearance)\s+to", 0.55),
]

ALL_PATTERN_CATEGORIES = {
    "instruction_override": INSTRUCTION_OVERRIDE_PATTERNS,
    "role_manipulation": ROLE_MANIPULATION_PATTERNS,
    "data_exfiltration": DATA_EXFILTRATION_PATTERNS,
    "indirect_injection": INDIRECT_INJECTION_PATTERNS,
    "social_engineering": SOCIAL_ENGINEERING_PATTERNS,
}


def detect_prompt_injection(text: str) -> DetectionResult:
    """Analyze text for prompt injection attempts.

    Args:
        text: The input text to analyze.

    Returns:
        DetectionResult with risk assessment.
    """
    if not text or not text.strip():
        return DetectionResult(
            is_injection=False,
            risk_level=RiskLevel.NONE,
            score=0.0,
            explanation="Empty input.",
        )

    text_lower = text.lower()
    matched_patterns = []
    max_score = 0.0
    category_hits: dict[str, int] = {}

    for category, patterns in ALL_PATTERN_CATEGORIES.items():
        for pattern, weight in patterns:
            if re.search(pattern, text_lower):
                pattern_name = f"{category}: {pattern}"
                matched_patterns.append(pattern_name)
                max_score = max(max_score, weight)
                category_hits[category] = category_hits.get(category, 0) + 1

    # Boost score if multiple categories are hit
    num_categories = len(category_hits)
    if num_categories >= 3:
        max_score = min(max_score + 0.15, 1.0)
    elif num_categories >= 2:
        max_score = min(max_score + 0.10, 1.0)

    # Boost score if many patterns match within one category
    max_hits = max(category_hits.values()) if category_hits else 0
    if max_hits >= 3:
        max_score = min(max_score + 0.10, 1.0)

    # Determine risk level
    if max_score >= 0.85:
        risk_level = RiskLevel.CRITICAL
    elif max_score >= 0.70:
        risk_level = RiskLevel.HIGH
    elif max_score >= 0.50:
        risk_level = RiskLevel.MEDIUM
    elif max_score >= 0.30:
        risk_level = RiskLevel.LOW
    else:
        risk_level = RiskLevel.NONE

    is_injection = max_score >= 0.50

    # Build explanation
    if not matched_patterns:
        explanation = "No injection patterns detected."
    else:
        categories_found = list(category_hits.keys())
        explanation = (
            f"Detected {len(matched_patterns)} injection pattern(s) "
            f"across {num_categories} category(ies): {', '.join(categories_found)}."
        )

    return DetectionResult(
        is_injection=is_injection,
        risk_level=risk_level,
        score=round(max_score, 3),
        matched_patterns=matched_patterns,
        explanation=explanation,
    )
