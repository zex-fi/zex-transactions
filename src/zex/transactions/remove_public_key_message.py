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


class RemovePublicKeySchema(BaseModel):
    sig_type: SignatureType
    key_identifier: str
    nonce: int
    time: int
    user_id: int
    signature: str

    def to_message(self) -> "RemovePublicKeyMessage":
        return RemovePublicKeyMessage(
            version=1,
            signature_type=self.sig_type,
            key_identifier=self.key_identifier,
            nonce=self.nonce,
            time=self.time,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class RemovePublicKeyMessage(BaseMessage):
    """Remove a secondary public key from a user account.

    Identifies the key to remove by its key_identifier. This message must be
    signed by the account's master key.

    Wire format
    -----------
    Header (4 bytes):  version | command='k' | signature_type | key_identifier_length
    Body:              key_identifier | time | nonce | user_id | signature
    """

    TRANSACTION_TYPE = TransactionType.REMOVE_PUBLIC_KEY
    HEADER_LENGTH = 4

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        key_identifier: str,
        nonce: int,
        time: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.version = version
        self.signature_type = signature_type
        self.key_identifier = key_identifier
        self.nonce = nonce
        self.time = time
        self.user_id = user_id
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBB"

    @classmethod
    def get_body_format(cls, key_identifier_length: int) -> str:
        return f">{key_identifier_length}s I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, key_identifier_length: int) -> str:
        return cls.get_header_format() + cls.get_body_format(key_identifier_length)[1:]

    def __str__(self) -> str:
        return (
            f"v: {self.version}\n"
            "name: remove_public_key\n"
            f"user_id: {self.user_id}\n"
            f"key_identifier: {self.key_identifier}\n"
            f"nonce: {self.nonce}\n"
            f"time: {self.time}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            RemovePublicKeyMessage.get_format(
                key_identifier_length=len(self.key_identifier),
            ),
            self.version,
            RemovePublicKeyMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            len(self.key_identifier),
            self.key_identifier.encode("ascii"),
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "RemovePublicKeyMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            version, command, signature_type, key_identifier_length = unpack(
                header_format, header_bytes
            )
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        body_format = cls.get_body_format(key_identifier_length)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            (
                key_identifier,
                time,
                nonce,
                user_id,
                signature_bytes,
            ) = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        message = cls(
            version=version,
            signature_type=SignatureType.from_int(signature_type),
            key_identifier=key_identifier.decode("ascii"),
            nonce=nonce,
            time=time,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        message._transaction_bytes = transaction_bytes
        return message
