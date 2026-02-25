from zex.transactions import RegisterMessage
from zex.utils.zex_types import SignatureType


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes(
    dummy_signature_hex: str, dummy_public_key_secp256k1: bytes
) -> None:
    # Given
    original_register_message = RegisterMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        referral_code="1",
        public_key=dummy_public_key_secp256k1,
        signature_hex=dummy_signature_hex,
    )

    # When
    transaction_bytes = original_register_message.to_bytes()
    new_register_message = RegisterMessage.from_bytes(transaction_bytes)

    # Then
    assert new_register_message.version == original_register_message.version
    assert new_register_message.signature_type == original_register_message.signature_type
    assert new_register_message.signature_hex == original_register_message.signature_hex
    assert new_register_message.public_key == original_register_message.public_key
    assert new_register_message.referral_code == original_register_message.referral_code
