import pytest
from coincurve import PrivateKey, PublicKey
from solders.keypair import Keypair


@pytest.fixture
def dummy_public_key_secp256k1() -> bytes:
    return b"\x01\x23\x45\x67\x89\xab\xcd\xef\x10\x32\x54\x76\x98\xba\xdc\xfe\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x7f"


@pytest.fixture
def private_key() -> PrivateKey:
    return PrivateKey()


@pytest.fixture
def public_key(private_key: PrivateKey) -> PublicKey:
    return private_key.public_key


@pytest.fixture
def ed25519_keypair() -> Keypair:
    return Keypair()


@pytest.fixture
def dummy_signature_hex() -> str:
    return (
        "f1182b8a9ae8add78d385c9801c266da2daddd4fd61c7b0bc0dcf3ceb6e95721"
        "e4db89f141386f98cc9f9c9eb7c2f2eef835f7316c75a12ea6b3812eb1c2dea7"
    )
