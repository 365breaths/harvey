"""The List-Unsubscribe header on every outgoing email.

The visible footer (postal address and opt-out line) lives in config
(compliance_footer_lines) and is added by the Sender. This header is the
other half: it gives mail clients their own "Unsubscribe" button, which
sends an email Harvey reads like any other opt-out.
"""

from harvey.config import compliance_of


def unsubscribe_address(config) -> str:
    """Where opt-out emails go: compliance.unsubscribe_email, else the
    sending mailbox itself (the handler reads it either way)."""
    explicit = (getattr(compliance_of(config), "unsubscribe_email", "") or "").strip()
    persona = getattr(config, "persona", None)
    return explicit or (getattr(persona, "email", "") or "").strip()


def list_unsubscribe_header(config, fallback_address: str = "") -> str:
    """RFC 2369 List-Unsubscribe value: a mailto the mail client's own
    "Unsubscribe" button sends. Harvey runs locally with no public web
    server, so there is no https one-click (RFC 8058) link to offer."""
    address = unsubscribe_address(config) or (fallback_address or "").strip()
    if not address:
        return ""
    return f"<mailto:{address}?subject=unsubscribe>"
