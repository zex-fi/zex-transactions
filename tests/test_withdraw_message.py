from zex.transactions import WithdrawMessage
from zex.utils.zex_types import ChainName, SignatureType


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str
) -> None:
    # Given
    original_withdraw_message = WithdrawMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        token_name="BTC",
        chain_name=ChainName.Bitcoin,
        amount_mantissa=1,
        amount_exponent=1,
        destination_wallet=b"\x01\x23\x45\x67\x89\xab",
        time=1000,
        nonce=1,
        user_id=1,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_withdraw_message.to_bytes()
    new_withdraw_message = WithdrawMessage.from_bytes(transaction_bytes)

    # Then
    assert new_withdraw_message.version == original_withdraw_message.version
    assert new_withdraw_message.signature_type == original_withdraw_message.signature_type
    assert new_withdraw_message.signature_hex == original_withdraw_message.signature_hex
    assert new_withdraw_message.time == original_withdraw_message.time
    assert new_withdraw_message.user_id == original_withdraw_message.user_id
    assert new_withdraw_message.nonce == original_withdraw_message.nonce
    assert new_withdraw_message.amount == original_withdraw_message.amount
    assert new_withdraw_message.destination_wallet == original_withdraw_message.destination_wallet
    assert new_withdraw_message.chain == original_withdraw_message.chain
