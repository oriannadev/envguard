"""Secret detection rules engine.

Each rule defines a regex pattern that matches a specific type of secret,
along with metadata for severity classification and reporting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Severity levels for detected secrets.

    Uses integer ordering so that filtering by minimum severity
    is a simple comparison: ``finding.severity >= threshold``.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity level from a case-insensitive string."""
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(
                f"Unknown severity '{value}'. Valid options: {valid}"
            ) from None


@dataclass(frozen=True)
class Rule:
    """A single secret-detection rule.

    Attributes:
        name:        Short identifier shown in reports (e.g. "openai-api-key").
        pattern:     Compiled regex used to match against each line.
        severity:    How critical a leak of this type would be.
        description: Human-readable explanation shown in reports.
    """

    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------
# Patterns are intentionally written to minimise false positives on common
# codebases while still catching the most dangerous secret formats.
# Each pattern uses a *raw* string and re.IGNORECASE where appropriate.
# ---------------------------------------------------------------------------

BUILT_IN_RULES: list[Rule] = [
    # -- Provider-specific API keys -----------------------------------------
    Rule(
        name="openai-api-key",
        pattern=re.compile(r"""sk-[A-Za-z0-9]{20,}"""),
        severity=Severity.CRITICAL,
        description="OpenAI API key (starts with sk-)",
    ),
    Rule(
        name="anthropic-api-key",
        pattern=re.compile(r"""sk-ant-[A-Za-z0-9\-]{20,}"""),
        severity=Severity.CRITICAL,
        description="Anthropic API key (starts with sk-ant-)",
    ),
    Rule(
        name="aws-access-key",
        pattern=re.compile(r"""(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"""),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID (starts with AKIA)",
    ),
    Rule(
        name="github-token",
        pattern=re.compile(r"""(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{16,}"""),
        severity=Severity.HIGH,
        description="GitHub personal access token or OAuth token",
    ),
    Rule(
        name="stripe-secret-key",
        pattern=re.compile(r"""(?:sk_live_|sk_test_)[A-Za-z0-9]{20,}"""),
        severity=Severity.CRITICAL,
        description="Stripe secret key",
    ),
    Rule(
        name="stripe-publishable-key",
        pattern=re.compile(r"""(?:pk_live_|pk_test_)[A-Za-z0-9]{20,}"""),
        severity=Severity.LOW,
        description="Stripe publishable key (generally safe, but worth reviewing)",
    ),
    Rule(
        name="slack-token",
        pattern=re.compile(r"""xox[bpors]-[A-Za-z0-9\-]{10,}"""),
        severity=Severity.HIGH,
        description="Slack bot, user, or app token",
    ),
    Rule(
        name="jwt-token",
        pattern=re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"""),
        severity=Severity.HIGH,
        description="JSON Web Token (JWT)",
    ),
    # -- Private keys -------------------------------------------------------
    Rule(
        name="private-key",
        pattern=re.compile(
            r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""
        ),
        severity=Severity.CRITICAL,
        description="Private key header (RSA, EC, DSA, or OpenSSH)",
    ),
    # -- Database connection strings ----------------------------------------
    Rule(
        name="database-url",
        pattern=re.compile(
            r"""(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:]+:[^\s@]+@[^\s]+""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Database connection string with embedded credentials",
    ),
    # -- Generic credential assignments -------------------------------------
    Rule(
        name="generic-api-key",
        pattern=re.compile(
            r"""(?i)(?:api_key|apikey|api-key)\s*[:=]\s*['"][A-Za-z0-9\-_./+=]{16,}['"]""",
        ),
        severity=Severity.HIGH,
        description="Generic API key assigned to a variable",
    ),
    Rule(
        name="generic-secret",
        pattern=re.compile(
            r"""(?i)(?:secret|password|passwd|pwd|token|auth_token|access_token|secret_key)\s*[:=]\s*['"][A-Za-z0-9\-_./+=]{8,}['"]""",
        ),
        severity=Severity.MEDIUM,
        description="Generic secret or password assigned to a variable",
    ),
]


def get_rules() -> list[Rule]:
    """Return the full list of built-in detection rules.

    This is the public API that the scanner consumes.  Keeping it as a
    function (rather than exposing the list directly) leaves room for
    future rule-loading from config files or plugins.
    """
    return list(BUILT_IN_RULES)
