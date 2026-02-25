from zex.transactions import PauseWithdrawMessage


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_pause_withdraw_message = PauseWithdrawMessage(
        version=1,
        signature_type_value=1,
        is_set=True,
        time=1000,
        nonce=0,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_pause_withdraw_message.to_bytes()
    new_pause_withdraw_message = PauseWithdrawMessage.from_bytes(transaction_bytes)

    # Then
    assert new_pause_withdraw_message.version == original_pause_withdraw_message.version
    assert new_pause_withdraw_message.signature_type == original_pause_withdraw_message.signature_type
    assert new_pause_withdraw_message.signature_hex == original_pause_withdraw_message.signature_hex
    assert new_pause_withdraw_message.time == original_pause_withdraw_message.time
    assert new_pause_withdraw_message.nonce == original_pause_withdraw_message.nonce
    assert new_pause_withdraw_message.user_id == original_pause_withdraw_message.user_id
    assert new_pause_withdraw_message.is_set == original_pause_withdraw_message.is_set
