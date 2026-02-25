from zex.transactions import TransferMessage
from zex.utils.zex_types import SignatureType


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_transfer_message = TransferMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        amount_mantissa=1,
        amount_exponent=1,
        time=1000,
        nonce=1,
        user_id=1,
        recipient_id=2,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_transfer_message.to_bytes()
    new_transfer_message = TransferMessage.from_bytes(transaction_bytes)

    # Then
    assert new_transfer_message.version == original_transfer_message.version
    assert new_transfer_message.signature_type == original_transfer_message.signature_type
    assert new_transfer_message.signature_hex == original_transfer_message.signature_hex
    assert new_transfer_message.time == original_transfer_message.time
    assert new_transfer_message.user_id == original_transfer_message.user_id
    assert new_transfer_message.nonce == original_transfer_message.nonce
    assert new_transfer_message.amount == original_transfer_message.amount
    assert new_transfer_message.recipient_id == original_transfer_message.recipient_id
