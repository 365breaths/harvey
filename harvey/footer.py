"""Compliance footer: sender identity, postal address, opt-out line.

CAN-SPAM and CASL both require every commercial email to carry the
sender's physical postal address and a working way to opt out. Harvey
appends the footer in code at send time, so no generated draft can leave
it out, and the native send path holds everything while it is missing.
"""

import re

PLACEHOLDER_RE = re.compile(r"PUT_\w+_HERE")


def build_footer(config) -> str | None:
    """The footer text, or None when the postal address isn't set yet."""
    footer = config.compliance.footer
    address = (footer.postal_address or "").strip()
    if not address or PLACEHOLDER_RE.search(address):
        return None
    persona = config.persona
    lines = [
        "--",
        getattr(persona, "from_name", "") or persona.name,
        persona.email,
        address,
        "",
        (footer.opt_out_line or "").strip(),
    ]
    return "\n".join(line for line in lines if line is not None).strip()


def unsubscribe_address(config) -> str:
    """Where opt-out emails go: compliance.footer.unsubscribe_email, else
    the sending mailbox itself (the handler reads it either way)."""
    footer = getattr(getattr(config, "compliance", None), "footer", None)
    explicit = (getattr(footer, "unsubscribe_email", "") or "").strip()
    return explicit or (getattr(config.persona, "email", "") or "").strip()


def list_unsubscribe_header(config, fallback_address: str = "") -> str:
    """RFC 2369 List-Unsubscribe value: a mailto the mail client's own
    "Unsubscribe" button sends. Harvey runs locally with no public web
    server, so there is no https one-click (RFC 8058) link to offer."""
    address = unsubscribe_address(config) or (fallback_address or "").strip()
    if not address:
        return ""
    return f"<mailto:{address}?subject=unsubscribe>"


def with_footer(body: str, footer: str) -> str:
    """Append the footer once (idempotent, so retries don't stack it)."""
    body = (body or "").rstrip()
    if footer in body:
        return body
    return f"{body}\n\n{footer}"


def strip_quoted(text: str, config=None) -> str:
    """Drop quoted lines and our own footer from an inbound reply.

    Replies usually quote the original email, footer included, so a
    reply would otherwise always contain "unsubscribe" and be treated
    as an opt-out.
    """
    lines = [ln for ln in (text or "").splitlines() if not ln.lstrip().startswith(">")]
    out = "\n".join(lines)
    footer = getattr(getattr(config, "compliance", None), "footer", None)
    if footer is not None:
        line = (footer.opt_out_line or "").strip()
        if line:
            # Whitespace-tolerant: mail clients re-wrap quoted text.
            pattern = r"\s+".join(re.escape(w) for w in line.split())
            out = re.sub(pattern, " ", out, flags=re.IGNORECASE)
    return out
