"""Tests for v2 message format: key_identifier in buy/sell/cancel, nonce-free body
for all other nonce-bearing messages.
"""
import pytest
from coincurve import PrivateKey

from zex.transactions import (
    BuyMessage,
    CancelMessage,
    PauseWithdrawMessage,
    SellMessage,
    TransferMessage,
    WithdrawMessage,
)
from zex.transactions.add_public_key_message import AddPublicKeyMessage, KeyMode
from zex.transactions.remove_public_key_message import RemovePublicKeyMessage
from zex.utils.zex_types import ChainName, SignatureType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DUMMY_SIG = (
    "f1182b8a9ae8add78d385c9801c266da2daddd4fd61c7b0bc0dcf3ceb6e95721"
    "e4db89f141386f98cc9f9c9eb7c2f2eef835f7316c75a12ea6b3812eb1c2dea7"
)
SECP256K1_PUBKEY = bytes(range(33))


def _make_buy_v2(sig: str | None = DUMMY_SIG) -> BuyMessage:
    return BuyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=0,
        price_mantissa=5,
        price_exponent=4,
        time=10_000,
        nonce=None,
        user_id=1,
        signature_hex=sig,
        key_identifier=42,
    )


def _make_cancel_v2(sig: str | None = DUMMY_SIG) -> CancelMessage:
    return CancelMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        order_nonce=42,
        user_id=7,
        signature_hex=sig,
        key_identifier=3,
    )


# ---------------------------------------------------------------------------
# BuyMessage v2
# ---------------------------------------------------------------------------


def test_buy_v2_round_trip() -> None:
    original = _make_buy_v2()
    reconstructed = BuyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.key_identifier == 42
    assert reconstructed.base_token == "BTC"
    assert reconstructed.quote_token == "USDT"
    assert reconstructed.time == 10_000
    assert reconstructed.user_id == 1
    assert reconstructed.signature_hex == DUMMY_SIG


def test_buy_v2_nonce_raises() -> None:
    msg = _make_buy_v2()
    with pytest.raises(AttributeError, match="v2"):
        _ = msg.nonce


def test_buy_v1_key_identifier_raises(dummy_signature_hex: str) -> None:
    msg = BuyMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=0,
        price_mantissa=5,
        price_exponent=4,
        time=10_000,
        nonce=7,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )
    with pytest.raises(AttributeError, match="v1"):
        _ = msg.key_identifier


def test_buy_v2_requires_key_identifier() -> None:
    with pytest.raises(Exception):
        BuyMessage(
            version=2,
            signature_type=SignatureType.SECP256K1,
            base_token="BTC",
            quote_token="USDT",
            amount_mantissa=1,
            amount_exponent=0,
            price_mantissa=5,
            price_exponent=4,
            time=10_000,
            nonce=None,
            user_id=1,
            signature_hex=DUMMY_SIG,
            key_identifier=None,
        )


def test_buy_v2_sign_and_verify(private_key: PrivateKey) -> None:
    msg = _make_buy_v2(sig=None)
    msg.sign(private_key)
    assert msg.verify_signature(private_key.public_key.format(compressed=True))


def test_buy_v2_to_bytes_caches() -> None:
    msg = _make_buy_v2()
    assert msg.to_bytes() is msg.to_bytes()


# ---------------------------------------------------------------------------
# SellMessage v2
# ---------------------------------------------------------------------------


def test_sell_v2_round_trip() -> None:
    original = SellMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        base_token="ETH",
        quote_token="USDC",
        amount_mantissa=2,
        amount_exponent=0,
        price_mantissa=3,
        price_exponent=3,
        time=20_000,
        nonce=None,
        user_id=5,
        signature_hex=DUMMY_SIG,
        key_identifier=7,
    )
    reconstructed = SellMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.key_identifier == 7
    assert reconstructed.user_id == 5


# ---------------------------------------------------------------------------
# CancelMessage v2
# ---------------------------------------------------------------------------


def test_cancel_v2_round_trip() -> None:
    original = _make_cancel_v2()
    reconstructed = CancelMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.order_nonce == 42
    assert reconstructed.user_id == 7
    assert reconstructed.key_identifier == 3
    assert reconstructed.signature_hex == DUMMY_SIG


def test_cancel_v2_order_nonce_accessible() -> None:
    msg = _make_cancel_v2()
    assert msg.order_nonce == 42


def test_cancel_v1_key_identifier_raises(dummy_signature_hex: str) -> None:
    msg = CancelMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        order_nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )
    with pytest.raises(AttributeError, match="v1"):
        _ = msg.key_identifier


def test_cancel_v2_sign_and_verify(private_key: PrivateKey) -> None:
    msg = _make_cancel_v2(sig=None)
    msg.sign(private_key)
    assert msg.verify_signature(private_key.public_key.format(compressed=True))


# ---------------------------------------------------------------------------
# TransferMessage v2
# ---------------------------------------------------------------------------


def test_transfer_v2_round_trip() -> None:
    original = TransferMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        amount_mantissa=1,
        amount_exponent=0,
        recipient_id=99,
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = TransferMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.user_id == 1
    assert reconstructed.recipient_id == 99


def test_transfer_v2_nonce_raises() -> None:
    msg = TransferMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        amount_mantissa=1,
        amount_exponent=0,
        recipient_id=99,
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    with pytest.raises(AttributeError):
        _ = msg.nonce


# ---------------------------------------------------------------------------
# WithdrawMessage v2
# ---------------------------------------------------------------------------


def test_withdraw_v2_round_trip() -> None:
    original = WithdrawMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        chain_name=ChainName.Bitcoin,
        amount_mantissa=1,
        amount_exponent=0,
        destination_wallet=b"\x01\x23\x45",
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = WithdrawMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.destination_wallet == b"\x01\x23\x45"


def test_withdraw_v2_nonce_raises() -> None:
    msg = WithdrawMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        chain_name=ChainName.Bitcoin,
        amount_mantissa=1,
        amount_exponent=0,
        destination_wallet=b"\x01\x23\x45",
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    with pytest.raises(AttributeError):
        _ = msg.nonce


# ---------------------------------------------------------------------------
# PauseWithdrawMessage v2
# ---------------------------------------------------------------------------


def test_pause_v2_round_trip() -> None:
    original = PauseWithdrawMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        is_set=True,
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = PauseWithdrawMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.is_set is True


def test_pause_v2_nonce_raises() -> None:
    msg = PauseWithdrawMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        is_set=False,
        time=1_000,
        nonce=None,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    with pytest.raises(AttributeError):
        _ = msg.nonce


# ---------------------------------------------------------------------------
# AddPublicKeyMessage v2
# ---------------------------------------------------------------------------


def test_add_public_key_v2_permanent_round_trip() -> None:
    original = AddPublicKeyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        key_identifier=10,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=SECP256K1_PUBKEY,
        nonce=None,
        time=1_000_000,
        user_id=42,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.key_identifier == 10
    assert reconstructed.key_mode == KeyMode.PERMANENT
    assert reconstructed.expiry is None
    assert reconstructed.public_key == SECP256K1_PUBKEY


def test_add_public_key_v2_temporary_round_trip() -> None:
    original = AddPublicKeyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        key_identifier=11,
        key_mode=KeyMode.TEMPORARY,
        expiry=2_000_000_000,
        public_key=SECP256K1_PUBKEY,
        nonce=None,
        time=1_000_000,
        user_id=42,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.key_mode == KeyMode.TEMPORARY
    assert reconstructed.expiry == 2_000_000_000


def test_add_public_key_v2_nonce_raises() -> None:
    msg = AddPublicKeyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        key_identifier=10,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=SECP256K1_PUBKEY,
        nonce=None,
        time=1_000_000,
        user_id=42,
        signature_hex=DUMMY_SIG,
    )
    with pytest.raises(AttributeError):
        _ = msg.nonce


# ---------------------------------------------------------------------------
# RemovePublicKeyMessage v2
# ---------------------------------------------------------------------------


def test_remove_public_key_v2_round_trip() -> None:
    original = RemovePublicKeyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        key_identifier=10,
        nonce=None,
        time=1_000_000,
        user_id=42,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = RemovePublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.key_identifier == 10
    assert reconstructed.user_id == 42


def test_remove_public_key_v2_nonce_raises() -> None:
    msg = RemovePublicKeyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        key_identifier=10,
        nonce=None,
        time=1_000_000,
        user_id=42,
        signature_hex=DUMMY_SIG,
    )
    with pytest.raises(AttributeError):
        _ = msg.nonce
