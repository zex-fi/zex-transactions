import pytest
from coincurve import PrivateKey
from solders.keypair import Keypair

from zex.transactions import AddPublicKeyMessage, BaseMessage, KeyMode
from zex.transactions.exceptions import MessageValidationError
from zex.utils.zex_types import SignatureType


def _make_permanent(
    dummy_signature_hex: str,
    dummy_public_key_secp256k1: bytes,
) -> AddPublicKeyMessage:
    return AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        managed_key_id=1,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=dummy_public_key_secp256k1,
        time=1_000_000,
        user_id=42,
        key_identifier=99,
        signature_hex=dummy_signature_hex,
    )


def test_permanent_key_round_trip(
    dummy_signature_hex: str, dummy_public_key_secp256k1: bytes
) -> None:
    original = _make_permanent(dummy_signature_hex, dummy_public_key_secp256k1)

    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.version == original.version
    assert reconstructed.signature_type == original.signature_type
    assert reconstructed.key_signature_type == original.key_signature_type
    assert reconstructed.managed_key_id == original.managed_key_id
    assert reconstructed.key_mode == original.key_mode
    assert reconstructed.expiry is None
    assert reconstructed.public_key == original.public_key
    assert reconstructed.time == original.time
    assert reconstructed.user_id == original.user_id
    assert reconstructed.key_identifier == original.key_identifier
    assert reconstructed.signature_hex == original.signature_hex


def test_temporary_key_round_trip(
    dummy_signature_hex: str, dummy_public_key_secp256k1: bytes
) -> None:
    original = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        managed_key_id=99,
        key_mode=KeyMode.TEMPORARY,
        expiry=1_800_000_000,
        public_key=dummy_public_key_secp256k1,
        time=1_700_000_000,
        user_id=7,
        key_identifier=5,
        signature_hex=dummy_signature_hex,
    )

    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.key_mode == KeyMode.TEMPORARY
    assert reconstructed.expiry == 1_800_000_000
    assert reconstructed.managed_key_id == 99
    assert reconstructed.user_id == 7
    assert reconstructed.key_identifier == 5


def test_ed25519_secondary_key_round_trip(
    dummy_signature_hex: str,
) -> None:
    ed25519_pubkey = bytes(Keypair().pubkey())
    original = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.ED25519,
        managed_key_id=5,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=ed25519_pubkey,
        time=2_000_000,
        user_id=100,
        key_identifier=1,
        signature_hex=dummy_signature_hex,
    )

    reconstructed = AddPublicKeyMessage.from_bytes(original.to_bytes())

    assert reconstructed.key_signature_type == SignatureType.ED25519
    assert len(reconstructed.public_key) == 32
    assert reconstructed.public_key == ed25519_pubkey


def test_base_message_dispatch(
    dummy_signature_hex: str, dummy_public_key_secp256k1: bytes
) -> None:
    original = _make_permanent(dummy_signature_hex, dummy_public_key_secp256k1)
    dispatched = BaseMessage.from_bytes(original.to_bytes())
    assert isinstance(dispatched, AddPublicKeyMessage)
    assert dispatched.managed_key_id == original.managed_key_id


def test_secp256k1_sign_and_verify(
    private_key: PrivateKey, dummy_public_key_secp256k1: bytes
) -> None:
    msg = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.SECP256K1,
        key_signature_type=SignatureType.SECP256K1,
        managed_key_id=1,
        key_mode=KeyMode.PERMANENT,
        expiry=None,
        public_key=dummy_public_key_secp256k1,
        time=1_000_000,
        user_id=1,
        key_identifier=0,
        signature_hex=None,
    )

    msg.sign(private_key)

    assert msg.verify_signature(private_key.public_key.format(compressed=True))


def test_ed25519_sign_and_verify(ed25519_keypair: Keypair) -> None:
    ed25519_pubkey = bytes(ed25519_keypair.pubkey())
    msg = AddPublicKeyMessage(
        version=3,
        signature_type=SignatureType.ED25519,
        key_signature_type=SignatureType.ED25519,
        managed_key_id=2,
        key_mode=KeyMode.TEMPORARY,
        expiry=9_999_999_999,
        public_key=ed25519_pubkey,
        time=1_000_000,
        user_id=5,
        key_identifier=0,
        signature_hex=None,
    )

    msg.sign(ed25519_keypair)

    assert msg.verify_signature(ed25519_pubkey)


def test_to_bytes_caches_result(
    dummy_signature_hex: str, dummy_public_key_secp256k1: bytes
) -> None:
    msg = _make_permanent(dummy_signature_hex, dummy_public_key_secp256k1)
    assert msg.to_bytes() is msg.to_bytes()


def test_v1_raises() -> None:
    with pytest.raises(MessageValidationError):
        AddPublicKeyMessage(
            version=1,
            signature_type=SignatureType.SECP256K1,
            key_signature_type=SignatureType.SECP256K1,
            managed_key_id=1,
            key_mode=KeyMode.PERMANENT,
            expiry=None,
            public_key=bytes(33),
            time=1,
            user_id=1,
            key_identifier=0,
        )
