"""Sending safeguards: SMTP outcome classification, bounce reports, IMAP
reading that never changes the mailbox, the per-email kill switch,
suppression, retries, crash-safe claiming and the attempt log.

No test opens a network connection: aiosmtplib.SMTP and imaplib.IMAP4_SSL
are replaced with fakes."""

import email
import email.policy
import os
import tempfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from types import SimpleNamespace

import aiosmtplib
import pytest
import pytest_asyncio

from harvey.config import ComplianceConfig, FooterConfig
from harvey.integrations import smtp_mail
from harvey.integrations.mail_provider import (
    ACCEPTED,
    PROVIDER_ERROR,
    RECIPIENT_REJECTED,
    SENDER_REJECTED,
    TEMPORARY,
    UNCERTAIN,
    InboundMessage,
    SendResult,
    is_permanent_bounce,
)
from harvey.integrations.smtp_mail import SmtpImapProvider, classify_rejection
from harvey.state import StateManager
from tests.test_outbox_native import (
    FakeProvider,
    make_handler,
    make_sender,
    seed_campaign,
    seed_prospect,
)


def _now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@pytest_asyncio.fixture
async def state():
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = StateManager(os.path.join(tmpdir, "test.db"))
        await sm.init_db()
        yield sm


def smtp_config():
    return SimpleNamespace(
        persona=SimpleNamespace(name="Dan", from_name="", email="dan@send.test"),
        compliance=ComplianceConfig(footer=FooterConfig(postal_address="1 Test St")),
    )


def smtp_env(port=587):
    return SimpleNamespace(
        smtp_host="smtp.test", smtp_port=port, smtp_username="dan@send.test",
        smtp_password="x", imap_host="imap.test", imap_port=993,
        imap_username="", imap_password="",
    )


# ── SMTP: every server answer is told apart ──


def test_classify_rejection():
    assert classify_rejection("connect", 535, "auth failed") == PROVIDER_ERROR
    assert classify_rejection("rcpt", 450, "4.2.0 greylisted") == TEMPORARY
    assert classify_rejection("rcpt", 550, "5.1.1 user unknown") == RECIPIENT_REJECTED
    assert classify_rejection("rcpt", 550, "5.7.1 relay denied") == SENDER_REJECTED
    assert classify_rejection("mail", 550, "sender blocked") == SENDER_REJECTED
    assert classify_rejection("data", 554, "5.7.1 spam") == SENDER_REJECTED
    assert classify_rejection("data", 550, "5.1.1 no such user") == RECIPIENT_REJECTED


class FakeSMTP:
    """Stands in for aiosmtplib.SMTP; `script` decides each phase."""
    script: dict = {}
    sent_data: list = []

    def __init__(self, **kwargs):
        pass

    async def connect(self):
        self._phase("connect")

    async def login(self, *_):
        self._phase("login")

    async def mail(self, sender):
        self._phase("mail")

    async def rcpt(self, recipient):
        self._phase("rcpt")

    async def data(self, message):
        FakeSMTP.sent_data.append(message)
        self._phase("data")
        return SimpleNamespace(code=250, message="2.0.0 Ok: queued as ABC123")

    async def quit(self):
        pass

    def _phase(self, name):
        action = FakeSMTP.script.get(name)
        if action is not None:
            raise action


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.script = {}
    FakeSMTP.sent_data = []
    monkeypatch.setattr(smtp_mail.aiosmtplib, "SMTP", FakeSMTP)
    return FakeSMTP


@pytest.mark.asyncio
async def test_smtp_accepted_keeps_server_answer_and_headers(fake_smtp):
    p = SmtpImapProvider(smtp_config(), smtp_env())
    preset = p.make_message_id()
    r = await p.send_email("jane@acme.com", "hi", "Body", message_id=preset)
    assert r.ok and r.outcome == ACCEPTED
    assert r.smtp_code == 250 and "queued as ABC123" in r.smtp_response
    assert r.message_id == preset
    sent = email.message_from_bytes(fake_smtp.sent_data[0], policy=email.policy.default)
    assert sent["Message-ID"] == preset
    assert sent["List-Unsubscribe"] == "<mailto:dan@send.test?subject=unsubscribe>"


@pytest.mark.asyncio
async def test_smtp_outcomes(fake_smtp):
    p = SmtpImapProvider(smtp_config(), smtp_env())

    fake_smtp.script = {"rcpt": aiosmtplib.SMTPRecipientRefused(550, "5.1.1 no such user", "x")}
    r = await p.send_email("bad@acme.com", "s", "b")
    assert not r.ok and r.outcome == RECIPIENT_REJECTED and r.smtp_code == 550

    fake_smtp.script = {"rcpt": aiosmtplib.SMTPRecipientRefused(451, "4.7.1 try later", "x")}
    assert (await p.send_email("a@acme.com", "s", "b")).outcome == TEMPORARY

    fake_smtp.script = {"connect": aiosmtplib.SMTPConnectError("refused")}
    assert (await p.send_email("a@acme.com", "s", "b")).outcome == PROVIDER_ERROR

    fake_smtp.script = {"login": aiosmtplib.SMTPAuthenticationError(535, "bad creds")}
    assert (await p.send_email("a@acme.com", "s", "b")).outcome == PROVIDER_ERROR

    # Lost during DATA: the server may already have it.
    fake_smtp.script = {"data": aiosmtplib.SMTPServerDisconnected("gone")}
    assert (await p.send_email("a@acme.com", "s", "b")).outcome == UNCERTAIN

    fake_smtp.script = {"data": aiosmtplib.SMTPDataError(554, "5.7.1 rejected as spam")}
    assert (await p.send_email("a@acme.com", "s", "b")).outcome == SENDER_REJECTED


# ── Bounce reports (RFC 3464) ──


def _dsn(action="failed", status="5.1.1", recipient="jane@acme.com",
         original_id="<orig@send.test>", subject="Undelivered Mail Returned to Sender"):
    raw = (
        "From: MAILER-DAEMON@mx.test\r\n"
        f"Subject: {subject}\r\n"
        "Message-ID: <bounce1@mx.test>\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/report; report-type=delivery-status; boundary="B"\r\n'
        "\r\n--B\r\nContent-Type: text/plain\r\n\r\nThis is the mail system.\r\n"
        "\r\n--B\r\nContent-Type: message/delivery-status\r\n\r\n"
        "Reporting-MTA: dns; mx.test\r\n\r\n"
        f"Final-Recipient: rfc822; {recipient}\r\nAction: {action}\r\n"
        f"Status: {status}\r\nDiagnostic-Code: smtp; 550 {status} user unknown\r\n"
        "\r\n--B\r\nContent-Type: text/rfc822-headers\r\n\r\n"
        f"From: dan@send.test\r\nTo: {recipient}\r\nMessage-ID: {original_id}\r\n"
        "\r\n--B--\r\n"
    )
    return raw.encode()


def test_dsn_is_parsed():
    m = SmtpImapProvider._parse_rfc822(_dsn())
    assert m.is_bounce
    assert m.bounce_recipients == ["jane@acme.com"]
    assert m.bounce_status == "5.1.1" and m.bounce_action == "failed"
    assert m.original_message_id == "<orig@send.test>"
    assert is_permanent_bounce(m)


def test_delay_notice_is_not_a_hard_bounce():
    m = SmtpImapProvider._parse_rfc822(_dsn(action="delayed", status="4.4.1",
                                            subject="Delayed Mail (still being retried)"))
    assert m.is_bounce and not is_permanent_bounce(m)
    plain = InboundMessage(provider_id="x", from_email="mailer-daemon@x",
                           subject="Delivery Status Notification (Delay)", is_bounce=True)
    assert not is_permanent_bounce(plain)


def test_plain_text_bounce_fallbacks():
    raw = (
        "From: MAILER-DAEMON@mx.test\r\nSubject: failure notice\r\n"
        "X-Failed-Recipients: gone@acme.com\r\n\r\n"
        "<gone@acme.com>:\r\n550 5.1.1 mailbox unavailable\r\n\r\n"
        "--- Below this line is a copy of the message.\r\n"
        "Message-ID: <orig2@send.test>\r\n"
    ).encode()
    m = SmtpImapProvider._parse_rfc822(raw)
    assert m.is_bounce and m.bounce_recipients == ["gone@acme.com"]
    assert m.original_message_id == "<orig2@send.test>"
    assert m.bounce_status == "5.1.1"


# ── IMAP: read-only, PEEK, junk folder, errors raise ──


def _raw(mid, frm="jane@acme.com", subject="Re: hi", body="Sounds good"):
    return (f"From: {frm}\r\nSubject: {subject}\r\nMessage-ID: {mid}\r\n"
            f"In-Reply-To: <orig@send.test>\r\n\r\n{body}\r\n").encode()


class FakeIMAP:
    folders = {}
    calls = []
    fail_inbox = False

    def __init__(self, host, port, timeout=None):
        self.current = None

    def login(self, *_):
        FakeIMAP.calls.append(("login",))

    def list(self):
        return "OK", [b'(\\HasNoChildren) "." "INBOX"',
                      b'(\\HasNoChildren \\Junk) "." "INBOX.Spam"']

    def select(self, name, readonly=False):
        FakeIMAP.calls.append(("select", name, readonly))
        name = name.strip('"')
        if FakeIMAP.fail_inbox and name == "INBOX":
            return "NO", [b"nope"]
        self.current = name
        return "OK", [b"1"]

    def uid(self, command, *args):
        FakeIMAP.calls.append(("uid", command) + args)
        msgs = FakeIMAP.folders.get(self.current, {})
        if command == "SEARCH":
            return "OK", [b" ".join(msgs.keys())]
        uids = args[0].split(",")
        out = []
        for u in uids:
            raw = msgs[u.encode()]
            if "HEADER.FIELDS" in args[1]:
                head = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                out += [(b"1 (UID " + u.encode() + b" BODY[HEADER.FIELDS] {1}", head), b")"]
            else:
                out += [(b"1 (UID " + u.encode() + b" BODY[] {1}", raw), b")"]
        return "OK", out

    def logout(self):
        pass


@pytest.fixture
def fake_imap(monkeypatch):
    FakeIMAP.folders = {}
    FakeIMAP.calls = []
    FakeIMAP.fail_inbox = False
    monkeypatch.setattr(smtp_mail.imaplib, "IMAP4_SSL", FakeIMAP)
    return FakeIMAP


@pytest.mark.asyncio
async def test_imap_reads_without_touching_flags(fake_imap):
    fake_imap.folders = {
        "INBOX": {b"1": _raw("<a@x>"), b"2": _raw("<own@x>", frm="dan@send.test")},
        "INBOX.Spam": {b"7": _raw("<b@x>", frm="bob@acme.com")},
    }
    p = SmtpImapProvider(smtp_config(), smtp_env())
    known = {"<a@x>"}

    async def is_known(key):
        return key in known

    p.is_known = is_known
    msgs = await p.get_replies()
    # Already-processed <a@x> skipped, our own message skipped, spam read.
    assert [m.message_id for m in msgs] == ["<b@x>"]
    assert msgs[0].in_reply_to == "<orig@send.test>"
    selects = [c for c in fake_imap.calls if c[0] == "select"]
    assert selects and all(readonly for _, _, readonly in selects)
    fetches = [c for c in fake_imap.calls if c[:2] == ("uid", "FETCH")]
    assert fetches and all("PEEK" in c[3] for c in fetches)


@pytest.mark.asyncio
async def test_imap_inbox_failure_raises(fake_imap):
    fake_imap.fail_inbox = True
    p = SmtpImapProvider(smtp_config(), smtp_env())
    with pytest.raises(Exception):
        await p.get_replies()


@pytest.mark.asyncio
async def test_unreadable_mailbox_means_handler_not_complete(state):
    class Down(FakeProvider):
        async def get_replies(self, limit=50):
            raise RuntimeError("imap down")

    handler = make_handler(state, Down())
    assert await handler._run_native() is False


# ── Sender: kill switch, suppression, outcomes, attempt log ──


class ScriptedProvider(FakeProvider):
    """Returns queued SendResults; preset Message-IDs like the SMTP one."""

    def __init__(self, results=(), on_send=None):
        super().__init__()
        self.results = list(results)
        self.on_send = on_send
        self.n = 0

    def make_message_id(self):
        self.n += 1
        return f"<preset{self.n}@x>"

    async def send_email(self, to_email, subject, body, thread_ref="",
                         in_reply_to="", message_id=""):
        self.sent.append({"to": to_email, "message_id": message_id, "body": body})
        if self.on_send:
            await self.on_send()
        if self.results:
            return self.results.pop(0)
        return SendResult(ok=True, message_id=message_id, outcome=ACCEPTED,
                          smtp_code=250, smtp_response="2.0.0 queued")


async def _approved(state, pid, email="jane@acme.com", step=1, campaign="c1"):
    return await state.add_outbox_item(
        prospect_id=pid, to_email=email, subject="hello",
        body="Fine body. Question?", send_at=_now_iso(), status="approved",
        campaign_id=campaign, step=step,
    )


@pytest.mark.asyncio
async def test_kill_switch_checked_before_every_email(state):
    for i in range(3):
        pid = await seed_prospect(state, email=f"p{i}@acme.com")
        await _approved(state, pid, email=f"p{i}@acme.com", campaign=f"c{i}")

    async def pause():
        await state.set_setting("sending_paused", "paused from dashboard")

    provider = ScriptedProvider(on_send=pause)
    await make_sender(state, provider)._drain_due()
    assert len(provider.sent) == 1          # paused right after the first
    assert len(await state.get_outbox(status="approved")) == 2


@pytest.mark.asyncio
async def test_suppressed_address_never_sent(state):
    pid = await seed_prospect(state)
    await _approved(state, pid)
    await state.add_suppression("@acme.com", "asked by phone", "cli")
    provider = ScriptedProvider()
    await make_sender(state, provider)._drain_due()
    assert provider.sent == []
    cancelled = await state.get_outbox(status="cancelled")
    assert cancelled and "suppressed" in cancelled[0]["error"]


@pytest.mark.asyncio
async def test_stage_skips_suppressed(state):
    pid = await seed_prospect(state)
    await seed_campaign(state, [pid])
    await state.add_suppression("jane@acme.com", "opted_out", "test")
    await make_sender(state, ScriptedProvider())._run_native()
    assert await state.get_outbox(status="pending_review") == []


@pytest.mark.asyncio
async def test_success_logged_with_server_answer(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    await make_sender(state, ScriptedProvider())._drain_due()
    row = await state.get_outbox_item(item_id)
    assert row["status"] == "sent" and row["message_id"] == "<preset1@x>"
    assert row["smtp_code"] == 250
    attempts = await state.get_send_attempts(item_id)
    assert len(attempts) == 1 and attempts[0]["outcome"] == ACCEPTED
    assert attempts[0]["smtp_response"] == "2.0.0 queued"


@pytest.mark.asyncio
async def test_recipient_rejected_suppresses_and_cancels_followups(state):
    pid = await seed_prospect(state)
    await _approved(state, pid, step=1)
    later = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=3)).isoformat()
    await state.add_outbox_item(
        prospect_id=pid, to_email="jane@acme.com", subject="s2", body="b",
        send_at=later, status="approved", campaign_id="c1", step=2,
    )
    provider = ScriptedProvider([SendResult(
        ok=False, outcome=RECIPIENT_REJECTED, smtp_code=550,
        smtp_response="5.1.1 no such user", error="rcpt: 550",
    )])
    await make_sender(state, provider)._drain_due()
    assert await state.get_suppression("jane@acme.com")
    assert (await state.get_prospect(pid)).email_status == "invalid"
    assert len(await state.get_outbox(status="cancelled")) == 1   # step 2
    assert await state.get_setting("bounce_count") == "1"


@pytest.mark.asyncio
async def test_temporary_failure_retries_with_backoff_then_gives_up(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    temp = SendResult(ok=False, outcome=TEMPORARY, smtp_code=451, smtp_response="4.7.1 later")
    provider = ScriptedProvider([temp])
    sender = make_sender(state, provider)
    await sender._drain_due()
    row = await state.get_outbox_item(item_id)
    assert row["status"] == "approved" and row["attempts"] == 1
    assert row["send_at"] > _now_iso()          # pushed into the future

    # Last allowed attempt fails too -> failed, never retried again.
    await state.update_outbox_item(item_id, attempts=2, send_at=_now_iso())
    provider.results = [temp]
    await sender._drain_due()
    row = await state.get_outbox_item(item_id)
    assert row["status"] == "failed" and "gave up after 3" in row["error"]


@pytest.mark.asyncio
async def test_sender_rejected_pauses_sending(state):
    pid = await seed_prospect(state)
    await _approved(state, pid)
    provider = ScriptedProvider([SendResult(
        ok=False, outcome=SENDER_REJECTED, smtp_code=554, smtp_response="5.7.1 spam",
    )])
    await make_sender(state, provider)._drain_due()
    assert "refused to send" in await state.get_setting("sending_paused")


@pytest.mark.asyncio
async def test_provider_error_holds_without_counting(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    provider = ScriptedProvider([SendResult(ok=False, outcome=PROVIDER_ERROR, error="connect")])
    await make_sender(state, provider)._drain_due()
    row = await state.get_outbox_item(item_id)
    assert row["status"] == "approved" and row["attempts"] == 0


@pytest.mark.asyncio
async def test_uncertain_send_is_never_retried(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    provider = ScriptedProvider([SendResult(ok=False, outcome=UNCERTAIN, error="data: gone")])
    sender = make_sender(state, provider)
    await sender._drain_due()
    assert (await state.get_outbox_item(item_id))["status"] == "uncertain"
    await sender._drain_due()
    assert len(provider.sent) == 1


@pytest.mark.asyncio
async def test_crash_mid_send_does_not_resend(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    # Simulate a crash: claimed, server call made, outcome never written.
    assert await state.claim_outbox_item(item_id, "<preset@x>")
    old = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)).isoformat()
    async with state._connect() as db:
        await db.execute("UPDATE outbox SET updated_at = ? WHERE id = ?", (old, item_id))
        await db.commit()
    provider = ScriptedProvider()
    await make_sender(state, provider)._drain_due()
    assert provider.sent == []
    row = await state.get_outbox_item(item_id)
    assert row["status"] == "uncertain" and row["message_id"] == "<preset@x>"
    # A second claim on the same row is impossible.
    assert not await state.claim_outbox_item(item_id)


@pytest.mark.asyncio
async def test_daily_cap_counts_uncertain(state):
    pid = await seed_prospect(state)
    item_id = await _approved(state, pid)
    await state.update_outbox_item(item_id, status="uncertain")
    assert await state.count_outbox_sent_today() == 1


# ── Handler: header matching, opt-outs, bounces ──


@pytest.mark.asyncio
async def test_reply_from_alias_matched_by_header_and_opt_out_suppressed(state):
    pid = await seed_prospect(state, status="contacted")
    item_id = await _approved(state, pid)
    await state.update_outbox_item(item_id, status="sent", message_id="<sent1@x>")
    provider = FakeProvider()
    provider.inbound = [InboundMessage(
        provider_id="r1", from_email="jane.doe@personal.test", subject="Re: hello",
        body="Please remove me from your list", message_id="<r1@p>",
        in_reply_to="<sent1@x>",
    )]
    await make_handler(state, provider)._run_native()
    assert (await state.get_prospect(pid)).status == "opted_out"
    assert await state.get_suppression("jane@acme.com")
    assert await state.get_suppression("jane.doe@personal.test")


@pytest.mark.asyncio
async def test_opt_out_from_unknown_sender_is_suppressed(state):
    provider = FakeProvider()
    provider.inbound = [InboundMessage(
        provider_id="r2", from_email="stranger@else.test", subject="unsubscribe",
        body="This message was sent by the mail client's unsubscribe button.",
    )]
    await make_handler(state, provider)._run_native()
    assert await state.get_suppression("stranger@else.test")


@pytest.mark.asyncio
async def test_list_unsubscribe_mail_from_prospect(state):
    pid = await seed_prospect(state, status="contacted")
    provider = FakeProvider()
    provider.inbound = [InboundMessage(
        provider_id="r3", from_email="jane@acme.com", subject="unsubscribe",
        body="(sent automatically)",
    )]
    await make_handler(state, provider, intent="interested")._run_native()
    assert (await state.get_prospect(pid)).status == "opted_out"


@pytest.mark.asyncio
async def test_bounce_matched_by_dsn_recipient_only(state):
    pid = await seed_prospect(state, status="contacted")
    provider = FakeProvider()
    provider.inbound = [SmtpImapProvider._parse_rfc822(_dsn(original_id="<unknown@x>"))]
    await make_handler(state, provider)._run_native()
    assert (await state.get_prospect(pid)).email_status == "invalid"
    assert await state.get_suppression("jane@acme.com")


@pytest.mark.asyncio
async def test_delay_notice_does_not_suppress(state):
    pid = await seed_prospect(state, status="contacted")
    provider = FakeProvider()
    provider.inbound = [SmtpImapProvider._parse_rfc822(
        _dsn(action="delayed", status="4.4.1", subject="Delayed Mail"))]
    await make_handler(state, provider)._run_native()
    assert (await state.get_prospect(pid)).email_status == "verified"
    assert not await state.get_suppression("jane@acme.com")
    assert await state.get_setting("bounce_count", "0") == "0"


# ── Suppression list ──


@pytest.mark.asyncio
async def test_domain_suppression_and_removal(state):
    assert await state.add_suppression("@acme.com", "competitor", "cli")
    assert not await state.add_suppression("@ACME.com", "again", "cli")
    assert "competitor" in await state.get_suppression("Bob@Acme.com")
    assert await state.get_suppression("bob@other.com") == ""
    assert await state.remove_suppression("@acme.com")
    assert await state.get_suppression("bob@acme.com") == ""
