import pytest

from zex.transactions import CancelMessage
from zex.utils.zex_types import SignatureType


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_cancel_message = CancelMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        order_nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_cancel_message.to_bytes()
    new_cancel_message = CancelMessage.from_bytes(transaction_bytes)

    # Then
    assert new_cancel_message.version == original_cancel_message.version
    assert new_cancel_message.signature_type == original_cancel_message.signature_type
    assert new_cancel_message.signature_hex == original_cancel_message.signature_hex
    assert new_cancel_message.order_nonce == original_cancel_message.order_nonce
    assert new_cancel_message.user_id == original_cancel_message.user_id


def test_v3_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_cancel_message = CancelMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        order_nonce=None,
        user_id=1,
        order_timestamp=999_000_000,
        key_identifier=7,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_cancel_message.to_bytes()
    new_cancel_message = CancelMessage.from_bytes(transaction_bytes)

    # Then
    assert new_cancel_message.version == original_cancel_message.version
    assert new_cancel_message.signature_type == original_cancel_message.signature_type
    assert new_cancel_message.signature_hex == original_cancel_message.signature_hex
    assert new_cancel_message.order_timestamp == original_cancel_message.order_timestamp
    assert new_cancel_message.key_identifier == original_cancel_message.key_identifier
    assert new_cancel_message.user_id == original_cancel_message.user_id


def test_v3_order_nonce_raises_attribute_error(dummy_signature_hex: str) -> None:
    msg = CancelMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        order_nonce=None,
        user_id=1,
        order_timestamp=999_000_000,
        key_identifier=7,
        signature_hex=dummy_signature_hex,
    )
    with pytest.raises(AttributeError):
        _ = msg.order_nonce


def test_v2_order_timestamp_raises_attribute_error(dummy_signature_hex: str) -> None:
    msg = CancelMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        order_nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )
    with pytest.raises(AttributeError):
        _ = msg.order_timestamp
