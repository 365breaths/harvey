"""Postal-address readiness and the List-Unsubscribe header."""

from types import SimpleNamespace

from harvey.config import ComplianceConfig, postal_address_ready
from harvey.footer import list_unsubscribe_header


def _config(address="123 Main St, Montreal, QC H2X 1Y4, Canada", unsubscribe_email=""):
    return SimpleNamespace(
        persona=SimpleNamespace(name="Daniel", email="d@co.test"),
        compliance=ComplianceConfig(postal_address=address,
                                    unsubscribe_email=unsubscribe_email),
    )


def test_real_address_is_ready():
    assert postal_address_ready(_config())


def test_missing_or_placeholder_address_is_not_ready():
    assert not postal_address_ready(_config(""))
    assert not postal_address_ready(_config("PUT_POSTAL_ADDRESS_HERE"))


def test_list_unsubscribe_points_at_the_sending_mailbox():
    assert list_unsubscribe_header(_config()) == "<mailto:d@co.test?subject=unsubscribe>"


def test_list_unsubscribe_uses_an_explicit_address():
    header = list_unsubscribe_header(_config(unsubscribe_email="optout@co.test"))
    assert header == "<mailto:optout@co.test?subject=unsubscribe>"
