import pytest

from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)
from zex.transactions.transfer_message import Recipient, TransferMessage, TransferStatus


@pytest.fixture
def dummy_signature_hex() -> str:
    """Fixture providing a mock 64-byte signature in hex format."""
    return "01" * 64


@pytest.fixture
def valid_transfer_message(dummy_signature_hex: str) -> TransferMessage:
    """Fixture providing a baseline valid TransferMessage."""
    return TransferMessage(
        version=1,
        signature_type_value=1,
        token_name="BTC",
        recipients=[
            Recipient(2, 1, 1),
            Recipient(3, 2, 2),
            Recipient(4, 10, 10),
        ],
        time=1000,
        nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )


### Symmetry & Core Functionality Tests


def test_to_bytes_from_bytes_symmetry(valid_transfer_message: TransferMessage) -> None:
    """
    Test that a message packed to bytes can be
    successfully unpacked with identical properties.
    """
    # When
    transaction_bytes = valid_transfer_message.to_bytes()
    new_transfer_message = TransferMessage.from_bytes(transaction_bytes)

    # Then
    assert new_transfer_message.version == valid_transfer_message.version
    assert new_transfer_message.signature_type == valid_transfer_message.signature_type
    assert new_transfer_message.signature_hex == valid_transfer_message.signature_hex
    assert new_transfer_message.time == valid_transfer_message.time
    assert new_transfer_message.user_id == valid_transfer_message.user_id
    assert new_transfer_message.nonce == valid_transfer_message.nonce

    assert len(new_transfer_message.recipients) == len(valid_transfer_message.recipients)
    for new_r, original_r in zip(
        new_transfer_message.recipients, valid_transfer_message.recipients
    ):
        assert new_r.recipient_id == original_r.recipient_id
        assert new_r.amount_mantissa == original_r.amount_mantissa
        assert new_r.amount_exponent == original_r.amount_exponent


def test_to_bytes_uses_cached_transaction_bytes(valid_transfer_message: TransferMessage) -> None:
    """Test that calling to_bytes a second time returns the cached property."""
    first_bytes = valid_transfer_message.to_bytes()

    # Intentionally modify the cache to ensure the method returns the cached version
    valid_transfer_message._transaction_bytes = b"cached_data"

    assert valid_transfer_message.to_bytes() == b"cached_data"
    assert valid_transfer_message.to_bytes() != first_bytes


### Validation Edge Case Tests


def test_init_raises_validation_error_on_small_exponent(dummy_signature_hex: str) -> None:
    """Test that initiating with an extremely small exponent raises a ValidationError."""
    with pytest.raises(MessageValidationError, match="amount_exponent is too small"):
        TransferMessage(
            version=1,
            signature_type_value=1,
            token_name="BTC",
            recipients=[Recipient(2, 1, -99999)],  # Forcing an impossibly small exponent
            time=1000,
            nonce=1,
            user_id=1,
            signature_hex=dummy_signature_hex,
        )


def test_from_bytes_raises_error_on_short_header() -> None:
    """Test that passing bytes shorter than HEADER_LENGTH raises an error."""
    short_bytes = b"\x01\x02\x03"  # Only 3 bytes, requires 5
    with pytest.raises(HeaderFormatError, match="Transaction is too short for header."):
        TransferMessage.from_bytes(short_bytes)


def test_from_bytes_raises_error_on_unexpected_command(
    valid_transfer_message: TransferMessage,
) -> None:
    """Test that a transaction byte array with the wrong command ID is rejected."""
    transaction_bytes = bytearray(valid_transfer_message.to_bytes())

    # Mutate the command byte (index 1) to an unexpected value (e.g., 99)
    transaction_bytes[1] = 99

    with pytest.raises(UnexpectedCommandError, match="Unexpected command."):
        TransferMessage.from_bytes(bytes(transaction_bytes))


def test_from_bytes_raises_error_on_zero_token_length(
    valid_transfer_message: TransferMessage,
) -> None:
    """Test that a transaction with token length 0 is rejected."""
    transaction_bytes = bytearray(valid_transfer_message.to_bytes())

    # Mutate the token_length byte (index 3) to 0
    transaction_bytes[3] = 0

    with pytest.raises(MessageFormatError, match="Invalid token length."):
        TransferMessage.from_bytes(bytes(transaction_bytes))


def test_from_bytes_raises_error_on_short_body(valid_transfer_message: TransferMessage) -> None:
    """Test that missing body bytes raise a MessageFormatError."""
    transaction_bytes = valid_transfer_message.to_bytes()

    # Chop off the last 10 bytes of the body
    shortened_bytes = transaction_bytes[:-10]

    with pytest.raises(MessageFormatError, match="Transaction body is too short."):
        TransferMessage.from_bytes(shortened_bytes)


### Status Update Tests


def test_transfer_status_transitions(valid_transfer_message: TransferMessage) -> None:
    """Test the confirm and fail methods update the status accordingly."""
    assert valid_transfer_message.status == TransferStatus.NEW

    valid_transfer_message.confirm()
    assert valid_transfer_message.status == TransferStatus.CONFIRMED

    valid_transfer_message.fail()
    assert valid_transfer_message.status == TransferStatus.FAILED
