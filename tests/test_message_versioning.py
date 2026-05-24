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


# ---------------------------------------------------------------------------
# BuyMessage v2
# ---------------------------------------------------------------------------


class TestBuyMessageV2:
    def _make(self, sig: str | None = DUMMY_SIG) -> BuyMessage:
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

    def test_round_trip(self) -> None:
        original = self._make()
        reconstructed = BuyMessage.from_bytes(original.to_bytes())

        assert reconstructed.version == 2
        assert reconstructed.key_identifier == 42
        assert reconstructed.base_token == "BTC"
        assert reconstructed.quote_token == "USDT"
        assert reconstructed.time == 10_000
        assert reconstructed.user_id == 1
        assert reconstructed.signature_hex == DUMMY_SIG

    def test_nonce_raises_in_v2(self) -> None:
        msg = self._make()
        with pytest.raises(AttributeError, match="v2"):
            _ = msg.nonce

    def test_key_identifier_raises_in_v1(self, dummy_signature_hex: str) -> None:
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

    def test_v2_requires_key_identifier(self) -> None:
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

    def test_sign_and_verify(self, private_key: PrivateKey) -> None:
        msg = self._make(sig=None)
        msg.sign(private_key)
        assert msg.verify_signature(private_key.public_key.format(compressed=True))

    def test_to_bytes_caches(self) -> None:
        msg = self._make()
        assert msg.to_bytes() is msg.to_bytes()


# ---------------------------------------------------------------------------
# SellMessage v2
# ---------------------------------------------------------------------------


class TestSellMessageV2:
    def test_round_trip(self) -> None:
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


class TestCancelMessageV2:
    def _make(self, sig: str | None = DUMMY_SIG) -> CancelMessage:
        return CancelMessage(
            version=2,
            signature_type=SignatureType.SECP256K1,
            order_nonce=42,
            user_id=7,
            signature_hex=sig,
            key_identifier=3,
        )

    def test_round_trip(self) -> None:
        original = self._make()
        reconstructed = CancelMessage.from_bytes(original.to_bytes())

        assert reconstructed.version == 2
        assert reconstructed.order_nonce == 42
        assert reconstructed.user_id == 7
        assert reconstructed.key_identifier == 3
        assert reconstructed.signature_hex == DUMMY_SIG

    def test_order_nonce_accessible_in_v2(self) -> None:
        msg = self._make()
        assert msg.order_nonce == 42

    def test_key_identifier_raises_in_v1(self, dummy_signature_hex: str) -> None:
        msg = CancelMessage(
            version=1,
            signature_type=SignatureType.SECP256K1,
            order_nonce=1,
            user_id=1,
            signature_hex=dummy_signature_hex,
        )
        with pytest.raises(AttributeError, match="v1"):
            _ = msg.key_identifier

    def test_sign_and_verify(self, private_key: PrivateKey) -> None:
        msg = self._make(sig=None)
        msg.sign(private_key)
        assert msg.verify_signature(private_key.public_key.format(compressed=True))


# ---------------------------------------------------------------------------
# TransferMessage v2
# ---------------------------------------------------------------------------


class TestTransferMessageV2:
    def test_round_trip(self) -> None:
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

    def test_nonce_raises_in_v2(self) -> None:
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


class TestWithdrawMessageV2:
    def test_round_trip(self) -> None:
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

    def test_nonce_raises_in_v2(self) -> None:
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


class TestPauseWithdrawMessageV2:
    def test_round_trip(self) -> None:
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

    def test_nonce_raises_in_v2(self) -> None:
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


class TestAddPublicKeyMessageV2:
    def test_round_trip(self) -> None:
        original = AddPublicKeyMessage(
            version=2,
            signature_type=SignatureType.SECP256K1,
            key_signature_type=SignatureType.SECP256K1,
            key_identifier=10,
            key_mode=KeyMode.NAMED,
            expiry=0,
            public_key=SECP256K1_PUBKEY,
            nonce=None,
            time=1_000_000,
            user_id=42,
            signature_hex=DUMMY_SIG,
        )
        reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

        assert reconstructed.version == 2
        assert reconstructed.key_identifier == 10
        assert reconstructed.public_key == SECP256K1_PUBKEY

    def test_nonce_raises_in_v2(self) -> None:
        msg = AddPublicKeyMessage(
            version=2,
            signature_type=SignatureType.SECP256K1,
            key_signature_type=SignatureType.SECP256K1,
            key_identifier=10,
            key_mode=KeyMode.NAMED,
            expiry=0,
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


class TestRemovePublicKeyMessageV2:
    def test_round_trip(self) -> None:
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

    def test_nonce_raises_in_v2(self) -> None:
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
