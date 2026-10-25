"""Compliance footer: built from config, appended once, never read as an opt-out."""

from types import SimpleNamespace

from harvey.config import ComplianceConfig, FooterConfig
from harvey.footer import build_footer, strip_quoted, with_footer


def _config(address="123 Main St, Montreal, QC H2X 1Y4, Canada"):
    return SimpleNamespace(
        persona=SimpleNamespace(name="Daniel", from_name="Daniel – Co", email="d@co.test"),
        compliance=ComplianceConfig(footer=FooterConfig(postal_address=address)),
    )


def test_footer_has_address_and_opt_out():
    footer = build_footer(_config())
    assert "123 Main St" in footer
    assert "unsubscribe" in footer
    assert "Daniel – Co" in footer


def test_missing_or_placeholder_address_blocks():
    assert build_footer(_config("")) is None
    assert build_footer(_config("PUT_POSTAL_ADDRESS_HERE")) is None


def test_with_footer_is_idempotent():
    footer = build_footer(_config())
    once = with_footer("Hi there", footer)
    assert with_footer(once, footer) == once


def test_quoted_footer_is_not_an_opt_out():
    config = _config()
    footer = build_footer(config)
    gmail_reply = "Sounds good, call me Tuesday.\n\n" + "\n".join("> " + ln for ln in footer.splitlines())
    outlook_reply = "Sounds good.\n\nFrom: Daniel\n" + footer.replace("Reply ", "Reply\n")
    for reply in (gmail_reply, outlook_reply):
        assert "unsubscribe" not in strip_quoted(reply, config).lower()
    assert "unsubscribe" in strip_quoted("please unsubscribe me", config).lower()
