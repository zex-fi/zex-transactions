import pytest
from coincurve import PrivateKey
from solders.keypair import Keypair
from zex.transactions import LoginMessage
from zex.transactions.exceptions import MessageValidationError
from zex.utils.zex_types import SignatureType, TransactionType


def _make_secp_login(private_key: PrivateKey) -> LoginMessage:
    msg = LoginMessage(
        version=1,
        signature_type=SignatureType.SECP256K1,
        public_key=private_key.public_key.format(compressed=True),
        timestamp=1_700_000_000,
        hmac=b"\xab" * 32,
    )
    msg.sign(private_key)
    return msg


def _make_ed_login(keypair: Keypair) -> LoginMessage:
    msg = LoginMessage(
        version=1,
        signature_type=SignatureType.ED25519,
        public_key=bytes(keypair.pubkey()),
        timestamp=1_700_000_000,
        hmac=b"\xcd" * 32,
    )
    msg.sign(keypair)
    return msg


def test_login_op_type_enum_value() -> None:
    assert TransactionType.LOGIN.value == ord("l")
    assert LoginMessage.TRANSACTION_TYPE is TransactionType.LOGIN


def test_secp256k1_sign_verify_roundtrip(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    assert msg.verify_signature(private_key.public_key.format(compressed=True))


def test_ed25519_sign_verify_roundtrip(ed25519_keypair: Keypair) -> None:
    msg = _make_ed_login(ed25519_keypair)
    assert msg.verify_signature(bytes(ed25519_keypair.pubkey()))


def test_to_bytes_from_bytes_roundtrip(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    restored = LoginMessage.from_bytes(msg.to_bytes())
    assert restored.version == msg.version
    assert restored.signature_type == msg.signature_type
    assert restored.public_key == msg.public_key
    assert restored.timestamp == msg.timestamp
    assert restored.hmac == msg.hmac
    assert restored.signature_hex == msg.signature_hex


def test_mutating_timestamp_invalidates_signature(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    msg.timestamp += 1
    assert not msg.verify_signature(private_key.public_key.format(compressed=True))


def test_mutating_hmac_invalidates_signature(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    msg.hmac = b"\x00" * 32
    assert not msg.verify_signature(private_key.public_key.format(compressed=True))


def test_mutating_public_key_invalidates_signature(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    other = PrivateKey().public_key.format(compressed=True)
    msg.public_key = other
    assert not msg.verify_signature(private_key.public_key.format(compressed=True))


def test_mutating_op_type_via_version_invalidates_signature(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    msg.version += 1
    assert not msg.verify_signature(private_key.public_key.format(compressed=True))


def test_different_keypair_fails_verification(private_key: PrivateKey) -> None:
    msg = _make_secp_login(private_key)
    other = PrivateKey().public_key.format(compressed=True)
    assert not msg.verify_signature(other)


def test_wrong_public_key_length_secp256k1_raises() -> None:
    with pytest.raises(MessageValidationError):
        LoginMessage(
            version=1,
            signature_type=SignatureType.SECP256K1,
            public_key=b"\x02" * 32,  # ed25519 length under secp
            timestamp=1,
            hmac=b"\x00" * 32,
        )


def test_wrong_public_key_length_ed25519_raises() -> None:
    with pytest.raises(MessageValidationError):
        LoginMessage(
            version=1,
            signature_type=SignatureType.ED25519,
            public_key=b"\x02" * 33,  # secp length under ed25519
            timestamp=1,
            hmac=b"\x00" * 32,
        )


def test_wrong_hmac_length_raises() -> None:
    with pytest.raises(MessageValidationError):
        LoginMessage(
            version=1,
            signature_type=SignatureType.ED25519,
            public_key=b"\x02" * 32,
            timestamp=1,
            hmac=b"\x00" * 16,
        )
