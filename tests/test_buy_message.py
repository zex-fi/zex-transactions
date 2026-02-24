from solders.keypair import Keypair

from zex.transactions import BuyMessage


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_buy_message = BuyMessage(
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
    transaction_bytes = original_buy_message.to_bytes()
    new_buy_message = BuyMessage.from_bytes(transaction_bytes)

    # Then
    assert new_buy_message.version == original_buy_message.version
    assert new_buy_message.signature_type == original_buy_message.signature_type
    assert new_buy_message.base_token == original_buy_message.base_token
    assert new_buy_message.quote_token == original_buy_message.quote_token
    assert new_buy_message.amount == original_buy_message.amount
    assert new_buy_message.price == original_buy_message.price
    assert new_buy_message.time == original_buy_message.time
    assert new_buy_message.signature_hex == original_buy_message.signature_hex
    assert new_buy_message.nonce == original_buy_message.nonce
    assert new_buy_message.user_id == original_buy_message.user_id


def test_ed25519_sign_and_verify(ed25519_keypair: Keypair) -> None:
    msg = BuyMessage(
        version=1,
        signature_type_value=2,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=1,
        price_mantissa=1,
        price_exponent=5,
        time=10000,
        nonce=1,
        user_id=1,
        signature_hex=None,
    )

    msg.sign(ed25519_keypair)

    assert msg.verify_signature(bytes(ed25519_keypair.pubkey()))
