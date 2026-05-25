from coincurve import PrivateKey
from solders.keypair import Keypair

from zex.transactions import BaseMessage, RemovePublicKeyMessage
from zex.utils.zex_types import SignatureType


def _make_msg(dummy_signature_hex: str) -> RemovePublicKeyMessage:
    return RemovePublicKeyMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        managed_key_id=1,
        nonce=1,
        time=1_000_000,
        user_id=42,
        signature_hex=dummy_signature_hex,
    )


def test_round_trip(dummy_signature_hex: str) -> None:
    original = _make_msg(dummy_signature_hex)

    reconstructed = RemovePublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == original.version
    assert reconstructed.signature_type == original.signature_type
    assert reconstructed.managed_key_id == original.managed_key_id
    assert reconstructed.nonce == original.nonce
    assert reconstructed.time == original.time
    assert reconstructed.user_id == original.user_id
    assert reconstructed.signature_hex == original.signature_hex


def test_base_message_dispatch(dummy_signature_hex: str) -> None:
    original = _make_msg(dummy_signature_hex)
    dispatched = BaseMessage.from_bytes(original.to_bytes())
    assert isinstance(dispatched, RemovePublicKeyMessage)
    assert dispatched.managed_key_id == original.managed_key_id


def test_secp256k1_sign_and_verify(private_key: PrivateKey) -> None:
    msg = RemovePublicKeyMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        managed_key_id=1,
        nonce=1,
        time=1_000_000,
        user_id=1,
        signature_hex=None,
    )

    msg.sign(private_key)

    assert msg.verify_signature(private_key.public_key.format(compressed=True))


def test_ed25519_sign_and_verify(ed25519_keypair: Keypair) -> None:
    msg = RemovePublicKeyMessage(
        version=1,
        signature_type=SignatureType.ED25519,
        managed_key_id=2,
        nonce=2,
        time=1_000_000,
        user_id=5,
        signature_hex=None,
    )

    msg.sign(ed25519_keypair)

    assert msg.verify_signature(bytes(ed25519_keypair.pubkey()))


def test_to_bytes_caches_result(dummy_signature_hex: str) -> None:
    msg = _make_msg(dummy_signature_hex)
    assert msg.to_bytes() is msg.to_bytes()
