"""Tests for v2 message format: time field is 8 bytes (u64) instead of 4 bytes (u32)."""
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
from zex.transactions.exceptions import MessageValidationError
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
        user_id=1,
        signature_hex=sig,
    )


def _make_cancel_v2(sig: str | None = DUMMY_SIG) -> CancelMessage:
    return CancelMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        order_nonce=42,
        user_id=7,
        signature_hex=sig,
    )


def _make_cancel_v3(sig: str | None = DUMMY_SIG) -> CancelMessage:
    return CancelMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        order_nonce=None,
        user_id=7,
        order_timestamp=1_700_000_000,
        key_identifier=5,
        signature_hex=sig,
    )


# ---------------------------------------------------------------------------
# BuyMessage v2
# ---------------------------------------------------------------------------


def test_buy_v2_round_trip() -> None:
    original = _make_buy_v2()
    reconstructed = BuyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.base_token == "BTC"
    assert reconstructed.quote_token == "USDT"
    assert reconstructed.time == 10_000
    assert reconstructed.user_id == 1
    assert reconstructed.signature_hex == DUMMY_SIG



def test_buy_v1_raises() -> None:
    with pytest.raises(MessageValidationError):
        BuyMessage(
            version=1,
            signature_type=SignatureType.SECP256K1,
            base_token="BTC",
            quote_token="USDT",
            amount_mantissa=1,
            amount_exponent=0,
            price_mantissa=5,
            price_exponent=4,
            time=10_000,
            user_id=1,
            signature_hex=DUMMY_SIG,
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
        user_id=5,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = SellMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
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
    assert reconstructed.signature_hex == DUMMY_SIG


def test_cancel_v2_order_nonce_accessible() -> None:
    msg = _make_cancel_v2()
    assert msg.order_nonce == 42


def test_cancel_v2_sign_and_verify(private_key: PrivateKey) -> None:
    msg = _make_cancel_v2(sig=None)
    msg.sign(private_key)
    assert msg.verify_signature(private_key.public_key.format(compressed=True))


# ---------------------------------------------------------------------------
# CancelMessage v3
# ---------------------------------------------------------------------------


def test_cancel_v3_round_trip() -> None:
    original = _make_cancel_v3()
    reconstructed = CancelMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 3
    assert reconstructed.order_timestamp == 1_700_000_000
    assert reconstructed.key_identifier == 5
    assert reconstructed.user_id == 7
    assert reconstructed.signature_hex == DUMMY_SIG


def test_cancel_v3_order_nonce_raises() -> None:
    msg = _make_cancel_v3()
    with pytest.raises(AttributeError):
        _ = msg.order_nonce


def test_cancel_v2_order_timestamp_raises() -> None:
    msg = _make_cancel_v2()
    with pytest.raises(AttributeError):
        _ = msg.order_timestamp


def test_cancel_v3_sign_and_verify(private_key: PrivateKey) -> None:
    msg = _make_cancel_v3(sig=None)
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
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = TransferMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.user_id == 1
    assert reconstructed.recipient_id == 99



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
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = WithdrawMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.destination_wallet == b"\x01\x23\x45"



# ---------------------------------------------------------------------------
# PauseWithdrawMessage v2
# ---------------------------------------------------------------------------


def test_pause_v2_round_trip() -> None:
    original = PauseWithdrawMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        is_set=True,
        time=1_000,
        user_id=1,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = PauseWithdrawMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 2
    assert reconstructed.is_set is True



# ---------------------------------------------------------------------------
# AddPublicKeyMessage v2
# ---------------------------------------------------------------------------


def test_add_public_key_v3_permanent_round_trip() -> None:
    original = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        managed_key_id=10,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=SECP256K1_PUBKEY,
        time=1_000_000,
        user_id=42,
        key_identifier=7,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 3
    assert reconstructed.managed_key_id == 10
    assert reconstructed.key_mode == KeyMode.PERMANENT
    assert reconstructed.expiry is None
    assert reconstructed.public_key == SECP256K1_PUBKEY
    assert reconstructed.key_identifier == 7


def test_add_public_key_v3_temporary_round_trip() -> None:
    original = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        managed_key_id=11,
        key_mode=KeyMode.TEMPORARY,
        expiry=2_000_000_000,
        public_key=SECP256K1_PUBKEY,
        time=1_000_000,
        user_id=42,
        key_identifier=3,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 3
    assert reconstructed.key_mode == KeyMode.TEMPORARY
    assert reconstructed.expiry == 2_000_000_000
    assert reconstructed.managed_key_id == 11
    assert reconstructed.key_identifier == 3


# ---------------------------------------------------------------------------
# RemovePublicKeyMessage v3
# ---------------------------------------------------------------------------


def test_remove_public_key_v3_round_trip() -> None:
    original = RemovePublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        managed_key_id=10,
        time=1_000_000,
        user_id=42,
        key_identifier=5,
        signature_hex=DUMMY_SIG,
    )
    reconstructed = RemovePublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == 3
    assert reconstructed.managed_key_id == 10
    assert reconstructed.user_id == 42
    assert reconstructed.key_identifier == 5
