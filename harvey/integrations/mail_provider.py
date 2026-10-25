"""Mail provider abstraction — Harvey owns its sending, Instantly optional.

A MailProvider gives Harvey full inbox control: send, read replies,
thread. Two native providers ship:

- ``gmail``  — a Google Workspace / Gmail mailbox via the Gmail REST API
  (recommended: a real mailbox on a dedicated secondary domain is the
  most deliverable way to send <50 cold emails/day).
- ``microsoft`` — a Microsoft 365 / Outlook mailbox via Microsoft Graph
  (OAuth; Exchange Online no longer accepts passwords over IMAP).
- ``smtp``   — any mailbox that speaks SMTP + IMAP (AgentMail, Fastmail,
  a Workspace app-mailbox, self-hosted). Configuration via .env.

``instantly`` remains supported through the legacy Sender/Handler path —
it isn't a MailProvider because Instantly owns sequencing/sending itself.
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.message import Message
from email.utils import parseaddr

logger = logging.getLogger("harvey.mail")

NATIVE_PROVIDERS = ("gmail", "smtp", "microsoft")

# What happened to one send attempt. "Accepted" only means the server took
# the message; whether it reached the inbox shows up later (bounce, reply).
ACCEPTED = "accepted"
RECIPIENT_REJECTED = "recipient_rejected"  # 5xx on this address: never retry it
SENDER_REJECTED = "sender_rejected"        # 5xx on us or the content: pause sending
TEMPORARY = "temporary"                    # 4xx: retry later with backoff
PROVIDER_ERROR = "provider_error"          # connect/login failed before anything was sent
UNCERTAIN = "uncertain"                    # lost mid-DATA: may have gone out, never resend


@dataclass
class SendResult:
    ok: bool
    message_id: str = ""     # RFC Message-ID (or provider id) of the sent mail
    thread_ref: str = ""     # provider thread handle (Gmail threadId, etc.)
    error: str = ""
    # Set by providers that can tell rejections apart (SMTP). Empty means
    # "unknown": a failure is then simply recorded as failed.
    outcome: str = ""
    smtp_code: int = 0
    smtp_response: str = ""


@dataclass
class InboundMessage:
    provider_id: str         # provider-unique id, used for reply dedup
    from_email: str
    subject: str = ""
    body: str = ""
    message_id: str = ""     # RFC Message-ID header
    in_reply_to: str = ""    # RFC In-Reply-To header (bounce/thread matching)
    thread_ref: str = ""
    date: str = ""
    is_bounce: bool = False
    headers: dict = field(default_factory=dict)
    references: str = ""     # RFC References header (reply matching)
    # Parsed from a bounce report (RFC 3464 DSN) when there is one.
    bounce_recipients: list[str] = field(default_factory=list)
    bounce_status: str = ""  # enhanced status code, e.g. "5.1.1"
    bounce_action: str = ""  # failed | delayed | delivered | relayed | expanded
    original_message_id: str = ""


BOUNCE_SENDERS = ("mailer-daemon", "postmaster", "mail delivery subsystem")
BOUNCE_SUBJECTS = (
    "delivery status notification", "undeliverable", "returned mail",
    "delivery failure", "failure notice", "could not be delivered",
    "delivery incomplete", "address not found",
)


def looks_like_bounce(from_email: str, subject: str) -> bool:
    f = (from_email or "").lower()
    s = (subject or "").lower()
    return any(m in f for m in BOUNCE_SENDERS) or any(m in s for m in BOUNCE_SUBJECTS)


ENHANCED_STATUS_RE = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")
MESSAGE_ID_RE = re.compile(r"^Message-ID:\s*(<[^>\s]+>)", re.IGNORECASE | re.MULTILINE)
# qmail-style "failure notice": "<jane@acme.com>:" opens each failed address.
QMAIL_RECIPIENT_RE = re.compile(r"^<([^<>@\s]+@[^<>\s]+)>:", re.MULTILINE)
DELAY_SUBJECTS = ("delay", "warning", "will retry", "still trying")


def enhanced_status(text: str) -> str:
    """The first RFC 3463 status code (e.g. "5.1.1") in a server message."""
    m = ENHANCED_STATUS_RE.search(text or "")
    return ".".join(m.groups()) if m else ""


def _dsn_address(value) -> str:
    """'rfc822; jane@acme.com' -> 'jane@acme.com'."""
    return parseaddr(str(value).split(";", 1)[-1].strip())[1].lower()


def parse_bounce_report(msg: Message, body: str = "") -> dict:
    """Pull the failed recipients, status and original Message-ID out of a
    bounce. Reads the machine-readable DSN part when the server sent one
    (RFC 3464), the X-Failed-Recipients header (Exim), and falls back to
    the text of the bounce. Every field may come back empty."""
    out = {"is_report": False, "recipients": [], "status": "", "action": "",
           "original_message_id": ""}

    for addr in str(msg.get("X-Failed-Recipients", "") or "").split(","):
        addr = parseaddr(addr.strip())[1].lower()
        if addr and addr not in out["recipients"]:
            out["recipients"].append(addr)

    if msg.get_content_type() == "multipart/report" and (
        (msg.get_param("report-type") or "").lower() == "delivery-status"
    ):
        out["is_report"] = True

    for part in msg.walk():
        ptype = part.get_content_type()
        if ptype == "message/delivery-status":
            out["is_report"] = True
            blocks = part.get_payload()
            if not isinstance(blocks, list):
                continue
            for block in blocks:
                recipient = block.get("Final-Recipient") or block.get("Original-Recipient")
                if recipient:
                    addr = _dsn_address(recipient)
                    if addr and addr not in out["recipients"]:
                        out["recipients"].append(addr)
                action = str(block.get("Action", "") or "").strip().lower()
                status = enhanced_status(str(block.get("Status", "") or ""))
                # One failed recipient makes the whole report a failure.
                if action and out["action"] != "failed":
                    out["action"] = action
                if status and not out["status"].startswith("5"):
                    out["status"] = status
        elif ptype == "message/rfc822" and not out["original_message_id"]:
            inner = part.get_payload()
            if isinstance(inner, list) and inner:
                out["original_message_id"] = str(inner[0].get("Message-ID", "") or "").strip()
        elif ptype == "text/rfc822-headers" and not out["original_message_id"]:
            try:
                m = MESSAGE_ID_RE.search(part.get_content())
            except Exception:
                m = None
            if m:
                out["original_message_id"] = m.group(1)

    # Plain-text bounces (no DSN part): best effort from the text itself.
    if not out["original_message_id"]:
        m = MESSAGE_ID_RE.search(body or "")
        if m:
            out["original_message_id"] = m.group(1)
    if not out["recipients"]:
        for addr in QMAIL_RECIPIENT_RE.findall(body or ""):
            addr = addr.lower()
            if addr not in out["recipients"]:
                out["recipients"].append(addr)
    if not out["status"]:
        out["status"] = enhanced_status(body)
    return out


def is_permanent_bounce(msg: InboundMessage) -> bool:
    """A hard failure (suppress the address) vs a delay or success notice.

    DSNs also report delays and successful relays; only "failed" or a 5.x.x
    status is a real bounce. With nothing machine-readable, a delay-ish
    subject is treated as temporary and anything else as a hard bounce.
    """
    action = (msg.bounce_action or "").lower()
    status = msg.bounce_status or ""
    if action == "failed" or status.startswith("5"):
        return True
    if action in ("delayed", "delivered", "relayed", "expanded") or status.startswith(("2", "4")):
        return False
    return not any(w in (msg.subject or "").lower() for w in DELAY_SUBJECTS)


class MailProvider(ABC):
    """A mailbox Harvey can send from and read replies out of."""

    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether required credentials are present (no network)."""

    @abstractmethod
    async def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        thread_ref: str = "",
        in_reply_to: str = "",
    ) -> SendResult:
        """Send one plain-text email. Reply threading when refs are given.

        Providers whose ``make_message_id()`` returns an id also accept a
        ``message_id=`` keyword and must send with exactly that id."""

    def make_message_id(self) -> str:
        """A Message-ID to record BEFORE sending, so a crash between the
        send and the bookkeeping still leaves the id on file. Empty when the
        provider assigns its own id."""
        return ""

    @abstractmethod
    async def get_replies(self, limit: int = 50) -> list[InboundMessage]:
        """Fetch recent inbound messages (dedup is the caller's job)."""

    @abstractmethod
    async def test_connection(self) -> tuple[bool, str]:
        """Cheap end-to-end credential check. Returns (ok, detail)."""


def get_mail_provider(config, env) -> MailProvider | None:
    """Build the configured native provider, or None for instantly/unknown."""
    provider = (config.channels.email.provider or "").strip().lower()
    if provider == "gmail":
        from harvey.integrations.gmail import GmailProvider
        return GmailProvider(config, env)
    if provider == "smtp":
        from harvey.integrations.smtp_mail import SmtpImapProvider
        return SmtpImapProvider(config, env)
    if provider == "microsoft":
        from harvey.integrations.microsoft import MicrosoftProvider
        return MicrosoftProvider(config, env)
    return None
