"""Prompt Injection Detector for AgentShield."""

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
    score: float
    matched_patterns: list[str] = field(default_factory=list)
    explanation: str = ""


INSTRUCTION_OVERRIDE_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules|guidelines)", 0.95),
    (r"ignore\s+(everything|anything)\s+(above|before)", 0.95),
    (r"disregard\s+(all\s+)?previous\s+(instructions|prompts|rules|guidelines)", 0.95),
    (r"forget\s+(all\s+)?previous\s+(instructions|prompts|context|rules)", 0.90),
    (r"override\s+(your|the|all)\s+(instructions|rules|safety)", 0.90),
    (r"do\s+not\s+follow\s+(your|the)\s+(instructions|rules)", 0.90),
    (r"stop\s+being\s+(an?\s+)?(ai|assistant|helpful)", 0.85),
    (r"you\s+are\s+now\s+(a|an|my)", 0.70),
    (r"new\s+(instructions|rules|role|persona)\s*:", 0.80),
    (r"from\s+now\s+on\s+(you|ignore|forget)", 0.85),
]

ROLE_MANIPULATION_PATTERNS = [
    (r"pretend\s+(you\s+are|to\s+be|you're)", 0.75),
    (r"act\s+as\s+(if|though|a|an)", 0.50),
    (r"roleplay\s+as", 0.60),
    (r"you\s+are\s+(dan|evil|unrestricted|unfiltered|jailbroken)", 0.95),
    (r"enter\s+(dan|developer|god|admin)\s+mode", 0.95),
    (r"switch\s+to\s+(unrestricted|unfiltered|evil)\s+mode", 0.95),
    (r"activate\s+(developer|admin|debug|god)\s+mode", 0.90),
    (r"(sudo|admin|root)\s+mode", 0.85),
]

DATA_EXFILTRATION_PATTERNS = [
    (r"(reveal|show|display|print|output)\s+(your|the|all|my)\s+(system\s+prompt|instructions|rules|prompt)", 0.90),
    (r"(reveal|show|display|print|output)\s+.{0,20}(password|secret|key|token|credential|api.?key)", 0.90),
    (r"what\s+(are|is)\s+your\s+(system\s+prompt|instructions|rules|password|secret)", 0.80),
    (r"repeat\s+(your|the)\s+(system\s+prompt|instructions|rules)", 0.90),
    (r"(send|post|transmit|upload|exfiltrate)\s+.{0,30}(data|info|credentials|keys|tokens)", 0.85),
    (r"(curl|wget|fetch)\s+https?://", 0.70),
    (r"https?://[^\s]+\?(data|secret|key|token|password)=", 0.75),
    (r"base64\s*(encode|decode)", 0.60),
    (r"\beval\b\s*\(", 0.80),
    (r"\bexec\b\s*\(", 0.80),
]

SYSTEM_ACCESS_PATTERNS = [
    (r"/etc/(passwd|shadow|hosts|sudoers)", 0.90),
    (r"(cat|less|more|head|tail|vi|nano)\s+/", 0.75),
    (r"\b(rm|chmod|chown|kill|shutdown|reboot)\s+-", 0.85),
    (r"\.\.(/|\\)", 0.70),
    (r"(cmd|powershell|bash|sh|zsh)\s*(\.exe)?\s+(-c|-e|/c)", 0.85),
    (r"(os\.system|subprocess|popen|shell_exec|system)\s*\(", 0.90),
    (r"import\s+(os|subprocess|shutil|sys)", 0.65),
    (r"__import__\s*\(", 0.90),
    (r"(environment|env)\s*(variable|var)s?", 0.50),
    (r"\.(env|config|ini|key|pem|crt)\b", 0.60),
    (r"(ssh|rsa|private).?(key|id)", 0.80),
    (r"(access|secret|api).?(key|token)", 0.75),
]

INDIRECT_INJECTION_PATTERNS = [
    (r"<\s*/?\s*(script|img|iframe|object|embed|form)", 0.75),
    (r"\[\s*system\s*\]", 0.85),
    (r"\[\s*INST\s*\]", 0.85),
    (r"<\|\s*(im_start|im_end|system|user)\s*\|>", 0.90),
    (r"###\s*(system|instruction|human|assistant)\s*:", 0.80),
    (r"BEGININSTRUCTION", 0.90),
    (r"\{\{\s*(system|instructions|prompt)\s*\}\}", 0.70),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r"(this\s+is\s+)?(a\s+)?test\s+(of|for)\s+(your|the)\s+(security|safety|limits)", 0.65),
    (r"(my|the)\s+(boss|manager|ceo|admin)\s+(told|asked|wants|needs)\s+(me|you)\s+to", 0.60),
    (r"(urgent|emergency|critical)\s*:?\s*(ignore|override|bypass)", 0.80),
    (r"(for\s+)?(research|educational|academic)\s+purposes\s+only", 0.45),
    (r"(I\s+)?(have|got)\s+(permission|authorization)\s+to", 0.55),
]

ALL_PATTERN_CATEGORIES = {
    "instruction_override": INSTRUCTION_OVERRIDE_PATTERNS,
    "role_manipulation": ROLE_MANIPULATION_PATTERNS,
    "data_exfiltration": DATA_EXFILTRATION_PATTERNS,
    "system_access": SYSTEM_ACCESS_PATTERNS,
    "indirect_injection": INDIRECT_INJECTION_PATTERNS,
    "social_engineering": SOCIAL_ENGINEERING_PATTERNS,
}


def detect_prompt_injection(text: str) -> DetectionResult:
    """Analyze text for prompt injection attempts."""
    if not text or not text.strip():
        return DetectionResult(
            is_injection=False,
            risk_level=RiskLevel.NONE,
            score=0.0,
            explanation="Empty input.",
        )

    text_lower = text.lower()
    matched_patterns: list[str] = []
    max_score = 0.0
    category_hits: dict[str, int] = {}

    for category, patterns in ALL_PATTERN_CATEGORIES.items():
        for pattern, weight in patterns:
            if re.search(pattern, text_lower):
                matched_patterns.append(f"{category}: {pattern}")
                max_score = max(max_score, weight)
                category_hits[category] = category_hits.get(category, 0) + 1

    num_categories = len(category_hits)
    if num_categories >= 3:
        max_score = min(max_score + 0.15, 1.0)
    elif num_categories >= 2:
        max_score = min(max_score + 0.10, 1.0)

    max_hits = max(category_hits.values()) if category_hits else 0
    if max_hits >= 3:
        max_score = min(max_score + 0.10, 1.0)

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

    if not matched_patterns:
        explanation = "No injection patterns detected."
    else:
        cats = list(category_hits.keys())
        explanation = (
            f"Detected {len(matched_patterns)} pattern(s) "
            f"across {num_categories} category(ies): "
            f"{', '.join(cats)}."
        )

    return DetectionResult(
        is_injection=is_injection,
        risk_level=risk_level,
        score=round(max_score, 3),
        matched_patterns=matched_patterns,
        explanation=explanation,
    )
