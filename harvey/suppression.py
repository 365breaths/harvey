"""Suppression and the bounce kill switch, shared by Sender and Handler.

A bad address can surface two ways: the server refuses it while sending
(5xx on RCPT), or a bounce report arrives in the mailbox later. Both must
end the same way: the address is suppressed for good, everything still
queued for that person is cancelled, and the bounce counts toward the
rate that trips the global kill switch.
"""

import logging

logger = logging.getLogger("harvey.suppression")

KILL_SWITCH_KEY = "sending_paused"
BOUNCE_COUNT_KEY = "bounce_count"
# Kill switch only engages after this many sends (a tiny sample lies).
MIN_SENDS_FOR_KILL_SWITCH = 10


async def suppress(state, emails, reason: str, source: str) -> int:
    """Add each non-empty address to the suppression list. Returns how many
    were new."""
    added = 0
    for email in {(e or "").strip().lower() for e in emails}:
        if email and await state.add_suppression(email, reason, source):
            added += 1
    return added


async def record_hard_bounce(state, config, prospect, emails, reason: str, source: str) -> str:
    """Suppress, invalidate, cancel, count. Returns the kill-switch reason
    if this bounce tripped it, else ''."""
    addresses = list(emails)
    if prospect is not None and prospect.email:
        addresses.append(prospect.email)
    await suppress(state, addresses, reason, source)

    if prospect is not None:
        await state.update_prospect_email(prospect.id, prospect.email, "invalid")
        cancelled = await state.cancel_pending_outbox_for_prospect(
            prospect.id, reason="bounced"
        )
        if cancelled:
            logger.warning(
                f"Cancelled {cancelled} queued email(s) for {prospect.email} (bounced)."
            )

    bounces = await state.increment_setting(BOUNCE_COUNT_KEY)
    total = await state.count_delivery_attempts()
    await state.log_action(
        action_type="bounce",
        agent=source,
        details={"prospect": prospect.email if prospect else "unknown",
                 "addresses": sorted({a.lower() for a in addresses if a}),
                 "reason": reason[:200], "bounces": bounces, "total_sent": total},
    )

    max_rate = getattr(config.channels.email, "max_bounce_rate", 0.05)
    if max_rate > 0 and total >= MIN_SENDS_FOR_KILL_SWITCH and bounces / total > max_rate:
        why = (
            f"bounce rate {bounces}/{total} exceeded {max_rate:.0%} — "
            "check list quality before resuming"
        )
        await pause_sending(state, why)
        return why
    return ""


async def pause_sending(state, reason: str):
    """Flip the global kill switch. The sender checks it before every email."""
    await state.set_setting(KILL_SWITCH_KEY, reason)
    logger.error(f"KILL SWITCH ENGAGED — {reason}")
