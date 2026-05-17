from enum import Enum
from struct import calcsize, pack, unpack
from struct import error as struct_error

from pydantic import BaseModel

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import SignatureType, TransactionType


class KeyMode(Enum):
    NAMED = 0
    UNNAMED = 1


class AddPublicKeySchema(BaseModel):
    sig_type: SignatureType
    key_signature_type: SignatureType
    key_identifier: str
    key_mode: KeyMode
    expiry: int
    public_key: bytes
    nonce: int
    time: int
    user_id: int
    signature: str

    def to_message(self) -> "AddPublicKeyMessage":
        return AddPublicKeyMessage(
            version=1,
            signature_type=self.sig_type,
            key_signature_type=self.key_signature_type,
            key_identifier=self.key_identifier,
            key_mode=self.key_mode,
            expiry=self.expiry,
            public_key=self.public_key,
            nonce=self.nonce,
            time=self.time,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class AddPublicKeyMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.ADD_PUBLIC_KEY
    HEADER_LENGTH = 5

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        key_signature_type: SignatureType,
        key_identifier: str,
        key_mode: KeyMode,
        expiry: int,
        public_key: bytes,
        nonce: int,
        time: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.version = version
        self.signature_type = signature_type
        self.key_signature_type = key_signature_type
        self.key_identifier = key_identifier
        self.key_mode = key_mode
        self.expiry = expiry
        self.public_key = public_key
        self.nonce = nonce
        self.time = time
        self.user_id = user_id
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBBB"

    @classmethod
    def get_body_format(cls, key_identifier_length: int, public_key_length: int) -> str:
        return (
            f">{key_identifier_length}s {public_key_length}s"
            f" B I I I Q {cls.SIGNATURE_LENGTH}s"
        )

    @classmethod
    def get_format(cls, key_identifier_length: int, public_key_length: int) -> str:
        return (
            cls.get_header_format()
            + cls.get_body_format(key_identifier_length, public_key_length)[1:]
        )

    def __str__(self) -> str:
        return (
            f"v: {self.version}\n"
            "name: add_public_key\n"
            f"user_id: {self.user_id}\n"
            f"key_identifier: {self.key_identifier}\n"
            f"key_mode: {self.key_mode.name.lower()}\n"
            f"expiry: {self.expiry}\n"
            f"nonce: {self.nonce}\n"
            f"time: {self.time}\n"
            f"public_key: {self.public_key.hex()}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            AddPublicKeyMessage.get_format(
                key_identifier_length=len(self.key_identifier),
                public_key_length=len(self.public_key),
            ),
            self.version,
            AddPublicKeyMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            self.key_signature_type.value,
            len(self.key_identifier),
            self.key_identifier.encode("ascii"),
            self.public_key,
            self.key_mode.value,
            self.expiry,
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "AddPublicKeyMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            version, command, signature_type, key_signature_type, key_identifier_length = unpack(
                header_format, header_bytes
            )
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        sig_type = SignatureType.from_int(signature_type)
        key_sig_type = SignatureType.from_int(key_signature_type)
        if key_sig_type == SignatureType.SECP256K1:
            public_key_length = 33
        elif key_sig_type == SignatureType.ED25519:
            public_key_length = 32
        else:
            raise ValueError("Unknown key signature type.")

        body_format = cls.get_body_format(key_identifier_length, public_key_length)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            (
                key_identifier,
                public_key,
                key_mode_value,
                expiry,
                time,
                nonce,
                user_id,
                signature_bytes,
            ) = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        message = cls(
            version=version,
            signature_type=sig_type,
            key_signature_type=key_sig_type,
            key_identifier=key_identifier.decode("ascii"),
            key_mode=KeyMode(key_mode_value),
            expiry=expiry,
            public_key=public_key,
            nonce=nonce,
            time=time,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        message._transaction_bytes = transaction_bytes
        return message
