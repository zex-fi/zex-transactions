from zex.transactions import SellMessage


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_sell_message = SellMessage(
        version=1,
        signature_type_value=1,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=1,
        price_mantissa=1,
        price_exponent=5,
        time=10000,
        nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_sell_message.to_bytes()
    new_sell_message = SellMessage.from_bytes(transaction_bytes)

    # Then
    assert new_sell_message.version == original_sell_message.version
    assert new_sell_message.signature_type == original_sell_message.signature_type
    assert new_sell_message.base_token == original_sell_message.base_token
    assert new_sell_message.quote_token == original_sell_message.quote_token
    assert new_sell_message.amount == original_sell_message.amount
    assert new_sell_message.price == original_sell_message.price
    assert new_sell_message.time == original_sell_message.time
    assert new_sell_message.signature_hex == original_sell_message.signature_hex
    assert new_sell_message.nonce == original_sell_message.nonce
    assert new_sell_message.user_id == original_sell_message.user_id
