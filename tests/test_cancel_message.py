from zex.transactions import CancelMessage


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_cancel_message = CancelMessage(
        version=1,
        signature_type_value=1,
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
