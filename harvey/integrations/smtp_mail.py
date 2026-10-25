"""Generic SMTP + IMAP mailbox provider.

Works with any real mailbox: Hostinger, AgentMail (their IMAP/SMTP relay),
Fastmail, a Google Workspace account with an app password, or self-hosted
mail.

.env:
    SMTP_HOST=            IMAP_HOST=
    SMTP_PORT=587         IMAP_PORT=993
    SMTP_USERNAME=        IMAP_USERNAME=   (defaults to SMTP_USERNAME)
    SMTP_PASSWORD=        IMAP_PASSWORD=   (defaults to SMTP_PASSWORD)

Sending walks the SMTP conversation one command at a time (MAIL, RCPT,
DATA) so every answer can be told apart: a refused address, a refused
sender or message, a temporary 4xx, or a connection lost in the middle of
DATA (the one case where the email may or may not have gone out).

Reading never changes the mailbox: folders are opened read-only and
messages fetched with BODY.PEEK, so mail you open yourself is still seen
by Harvey, and a message Harvey couldn't handle yet is fetched again next
cycle. Dedup is by Message-ID against what Harvey already processed.
INBOX and the junk folder are both read: bounces and replies land in spam
too.
"""

import asyncio
import email
import email.policy
import imaplib
import logging
import re
from datetime import date, timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr

import aiosmtplib

from harvey.footer import list_unsubscribe_header
from harvey.integrations.mail_provider import (
    ACCEPTED,
    PROVIDER_ERROR,
    RECIPIENT_REJECTED,
    SENDER_REJECTED,
    TEMPORARY,
    UNCERTAIN,
    InboundMessage,
    MailProvider,
    SendResult,
    enhanced_status,
    looks_like_bounce,
    parse_bounce_report,
)

logger = logging.getLogger("harvey.smtp")

# How far back each poll looks. Already-processed messages are skipped by
# Message-ID, so this only bounds how long Harvey can be off without
# missing mail.
LOOKBACK_DAYS = 30
FETCH_BATCH = 200
JUNK_NAMES = ("junk", "spam", "junk e-mail", "junk email", "bulk mail")
LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>.+)$')
UID_RE = re.compile(rb"UID (\d+)")
# IMAP dates are English regardless of the machine's locale.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def classify_rejection(phase: str, code: int, message: str) -> str:
    """Map an SMTP refusal to what Harvey should do about it."""
    if phase == "connect" or code < 400:
        return PROVIDER_ERROR
    if code < 500:
        return TEMPORARY
    status = enhanced_status(message)
    if phase == "rcpt":
        # 5.7.x is policy (relay denied, sender blocked, limits): about us,
        # not the address.
        return SENDER_REJECTED if status.startswith("5.7") else RECIPIENT_REJECTED
    if phase == "data" and status.startswith("5.1."):
        return RECIPIENT_REJECTED
    return SENDER_REJECTED


def _imap_date(d: date) -> str:
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"


def _quote_mailbox(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _dedup_key(from_email: str, subject: str, message_id: str) -> str:
    return message_id or f"{from_email}:{subject}"


class SmtpImapProvider(MailProvider):
    name = "smtp"

    def __init__(self, config, env):
        self.config = config
        self.smtp_host = getattr(env, "smtp_host", "")
        self.smtp_port = int(getattr(env, "smtp_port", 587) or 587)
        self.smtp_user = getattr(env, "smtp_username", "")
        self.smtp_pass = getattr(env, "smtp_password", "")
        self.imap_host = getattr(env, "imap_host", "") or self.smtp_host
        self.imap_port = int(getattr(env, "imap_port", 993) or 993)
        self.imap_user = getattr(env, "imap_username", "") or self.smtp_user
        self.imap_pass = getattr(env, "imap_password", "") or self.smtp_pass
        # Set by the Handler: async (key) -> bool, True when a message was
        # already processed, so its body isn't downloaded again.
        self.is_known = None

    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_pass)

    def _from_address(self) -> str:
        return self.config.persona.email or self.smtp_user

    def make_message_id(self) -> str:
        return make_msgid(domain=self._from_address().split("@")[-1])

    def _own_addresses(self) -> set[str]:
        return {a.strip().lower() for a in (self.smtp_user, self.config.persona.email) if a}

    # ── Sending ──

    async def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        thread_ref: str = "",
        in_reply_to: str = "",
        message_id: str = "",
    ) -> SendResult:
        persona = self.config.persona
        from_address = self._from_address()
        msg = EmailMessage()
        msg["To"] = to_email
        from_name = getattr(persona, "from_name", "") or persona.name
        msg["From"] = formataddr((from_name, from_address))
        msg["Subject"] = subject
        message_id = message_id or self.make_message_id()
        msg["Message-ID"] = message_id
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
            msg["References"] = in_reply_to
        unsubscribe = list_unsubscribe_header(self.config, self.smtp_user)
        if unsubscribe:
            msg["List-Unsubscribe"] = unsubscribe
        msg.set_content(body)

        smtp = aiosmtplib.SMTP(
            hostname=self.smtp_host,
            port=self.smtp_port,
            start_tls=(self.smtp_port == 587),
            use_tls=(self.smtp_port == 465),
            timeout=30,
        )
        phase = "connect"
        try:
            await smtp.connect()
            await smtp.login(self.smtp_user, self.smtp_pass)
            phase = "mail"
            await smtp.mail(from_address)
            phase = "rcpt"
            await smtp.rcpt(to_email)
            phase = "data"
            response = await smtp.data(msg.as_bytes(policy=email.policy.SMTP))
        except aiosmtplib.SMTPResponseException as e:
            # The server answered with a refusal: nothing was accepted.
            outcome = classify_rejection(phase, e.code, e.message)
            logger.error(f"SMTP {phase} refused for {to_email}: {e.code} {e.message}")
            return SendResult(
                ok=False, message_id=message_id, outcome=outcome,
                smtp_code=e.code, smtp_response=str(e.message)[:500],
                error=f"{phase}: {e.code} {e.message}"[:300],
            )
        except Exception as e:
            # No answer. Before DATA nothing could have gone out; during DATA
            # the server may already have queued it.
            outcome = UNCERTAIN if phase == "data" else PROVIDER_ERROR
            logger.error(f"SMTP {phase} failed for {to_email}: {e}")
            return SendResult(
                ok=False, message_id=message_id, outcome=outcome,
                error=f"{phase}: {e}"[:300],
            )
        finally:
            try:
                await smtp.quit()
            except Exception:
                pass
        return SendResult(
            ok=True, message_id=message_id, thread_ref=message_id,
            outcome=ACCEPTED, smtp_code=response.code,
            smtp_response=str(response.message)[:500],
        )

    # ── Reading ──

    async def get_replies(self, limit: int = 50) -> list[InboundMessage]:
        """Recent messages Harvey hasn't processed yet, oldest first.

        Raises when the mailbox can't be read: the heartbeat then holds all
        sending, since an unread reply can't have stopped its follow-ups.
        """
        loop = asyncio.get_running_loop()
        listed = await loop.run_in_executor(None, self._list_recent)
        fresh: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for folder, uid, key in listed:
            if key in seen:
                continue
            seen.add(key)
            if self.is_known is not None and await self.is_known(key):
                continue
            fresh.append((folder, uid))
            if len(fresh) >= limit:
                break
        if not fresh:
            return []
        raws = await loop.run_in_executor(None, self._fetch_bodies, fresh)
        return [m for m in (self._parse_rfc822(raw) for raw in raws) if m]

    def _connect_imap(self):
        conn = imaplib.IMAP4_SSL(self.imap_host, self.imap_port, timeout=30)
        conn.login(self.imap_user, self.imap_pass)
        return conn

    @staticmethod
    def _logout(conn):
        try:
            conn.logout()
        except Exception:
            pass

    def _junk_folders(self, conn) -> list[str]:
        """Folders flagged \\Junk, or named like a spam folder. Best effort."""
        found = []
        try:
            status, data = conn.list()
            if status != "OK":
                return []
            for raw in data or []:
                line = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                m = LIST_RE.match(line.strip())
                if not m:
                    continue
                flags = m.group("flags").lower()
                name = m.group("name").strip()
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                delim = m.group("delim").strip('"')
                leaf = name.split(delim)[-1] if delim and delim != "NIL" else name
                if name.upper() == "INBOX" or "\\noselect" in flags:
                    continue
                if "\\junk" in flags or leaf.lower() in JUNK_NAMES:
                    found.append(name)
        except Exception as e:
            logger.debug(f"IMAP folder listing failed: {e}")
        return found

    def _list_recent(self) -> list[tuple[str, bytes, str]]:
        """(folder, uid, dedup key) for every recent message, headers only."""
        own = self._own_addresses()
        since = _imap_date(date.today() - timedelta(days=LOOKBACK_DAYS))
        out: list[tuple[str, bytes, str]] = []
        conn = self._connect_imap()
        try:
            for folder in ["INBOX"] + self._junk_folders(conn):
                required = folder == "INBOX"
                try:
                    status, _ = conn.select(_quote_mailbox(folder), readonly=True)
                    if status != "OK":
                        raise RuntimeError(f"could not open {folder}")
                    status, data = conn.uid("SEARCH", None, "SINCE", since)
                    if status != "OK":
                        raise RuntimeError(f"search failed in {folder}")
                    uids = data[0].split() if data and data[0] else []
                    for i in range(0, len(uids), FETCH_BATCH):
                        chunk = b",".join(uids[i:i + FETCH_BATCH]).decode()
                        status, parts = conn.uid(
                            "FETCH", chunk,
                            "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM SUBJECT)])",
                        )
                        if status != "OK":
                            raise RuntimeError(f"header fetch failed in {folder}")
                        for part in parts or []:
                            if not isinstance(part, tuple):
                                continue
                            m = UID_RE.search(part[0])
                            if not m:
                                continue
                            headers = email.message_from_bytes(
                                part[1], policy=email.policy.default
                            )
                            from_email = parseaddr(str(headers.get("From", "")))[1].lower()
                            if not from_email or from_email in own:
                                continue
                            key = _dedup_key(
                                from_email,
                                str(headers.get("Subject", "")),
                                str(headers.get("Message-ID", "")).strip(),
                            )
                            out.append((folder, m.group(1), key))
                except Exception:
                    if required:
                        raise
                    logger.warning(f"IMAP: skipped folder {folder!r} this cycle.")
        finally:
            self._logout(conn)
        return out

    def _fetch_bodies(self, wanted: list[tuple[str, bytes]]) -> list[bytes]:
        raws: list[bytes] = []
        by_folder: dict[str, list[bytes]] = {}
        for folder, uid in wanted:
            by_folder.setdefault(folder, []).append(uid)
        conn = self._connect_imap()
        try:
            for folder, uids in by_folder.items():
                status, _ = conn.select(_quote_mailbox(folder), readonly=True)
                if status != "OK":
                    if folder == "INBOX":
                        raise RuntimeError("could not open INBOX")
                    continue
                for uid in uids:
                    status, parts = conn.uid("FETCH", uid.decode(), "(BODY.PEEK[])")
                    if status != "OK" or not parts or not isinstance(parts[0], tuple):
                        continue
                    raws.append(parts[0][1])
        finally:
            self._logout(conn)
        return raws

    @staticmethod
    def _parse_rfc822(raw: bytes) -> InboundMessage | None:
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception:
            return None
        from_email = parseaddr(str(msg.get("From", "")))[1].lower()
        if not from_email:
            return None
        subject = str(msg.get("Subject", ""))

        body = ""
        try:
            part = msg.get_body(preferencelist=("plain", "html"))
            if part is not None:
                body = part.get_content()
                if part.get_content_type() == "text/html":
                    body = re.sub(r"<[^>]+>", " ", body)
        except Exception:
            pass

        message_id = str(msg.get("Message-ID", "")).strip()
        report = parse_bounce_report(msg, body)
        is_bounce = (
            report["is_report"]
            or bool(msg.get("X-Failed-Recipients"))
            or looks_like_bounce(from_email, subject)
        )
        inbound = InboundMessage(
            provider_id=_dedup_key(from_email, subject, message_id),
            from_email=from_email,
            subject=subject,
            body=(body or "")[:5000],
            message_id=message_id,
            in_reply_to=str(msg.get("In-Reply-To", "")).strip(),
            thread_ref=str(msg.get("In-Reply-To", "")).strip(),
            date=str(msg.get("Date", "")),
            is_bounce=is_bounce,
            references=str(msg.get("References", "")).strip(),
        )
        if is_bounce:
            inbound.bounce_recipients = report["recipients"]
            inbound.bounce_status = report["status"]
            inbound.bounce_action = report["action"]
            inbound.original_message_id = report["original_message_id"]
        return inbound

    async def test_connection(self) -> tuple[bool, str]:
        if not self.is_configured():
            return False, "SMTP_HOST / SMTP_USERNAME / SMTP_PASSWORD missing from .env"
        # SMTP handshake
        try:
            smtp = aiosmtplib.SMTP(
                hostname=self.smtp_host, port=self.smtp_port,
                start_tls=(self.smtp_port == 587),
                use_tls=(self.smtp_port == 465), timeout=15,
            )
            await smtp.connect()
            await smtp.login(self.smtp_user, self.smtp_pass)
            await smtp.quit()
        except Exception as e:
            return False, f"SMTP login failed: {str(e)[:200]}"
        # IMAP handshake
        loop = asyncio.get_running_loop()

        def _imap_check():
            self._logout(self._connect_imap())

        try:
            await loop.run_in_executor(None, _imap_check)
        except Exception as e:
            return False, f"SMTP OK but IMAP login failed: {str(e)[:200]}"
        return True, f"SMTP + IMAP connected as {self.smtp_user}"
