"""Turn ATT&CK description markup into plain text (grill-decisions Q7)."""

import re

_CITATION = re.compile(r"\(Citation:[^)]*\)")
# Only real formatting tags. Placeholders such as <username> or <PID> inside
# paths and commands are content and must survive.
_FORMAT_TAG = re.compile(r"</?(?:code|b)>|<br\s*/?>", re.IGNORECASE)
_SPACES = re.compile(r"[ \t]+")


def convert_attack_links(text: str) -> str:
    """Rewrite markdown links to ATT&CK pages as "name (ID)".

    [Visual Basic](https://attack.mitre.org/techniques/T1059/005) -> Visual Basic (T1059.005)
    [Empire](https://attack.mitre.org/software/S0363)             -> Empire (S0363)
    [Execution](https://attack.mitre.org/tactics/TA0002)          -> Execution (TA0002)
    """
    # TODO(human): implement this conversion; tests/test_clean.py says exactly what's expected
    raise NotImplementedError


def clean_text(text: str) -> str:
    """Plain text ready for a Passage: no citations, links rewritten, tags stripped."""
    text = _CITATION.sub("", text)
    text = convert_attack_links(text)
    text = _FORMAT_TAG.sub("", text)
    return _SPACES.sub(" ", text).strip()
