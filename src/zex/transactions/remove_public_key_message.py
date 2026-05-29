from struct import calcsize, pack, unpack
from struct import error as struct_error

from pydantic import BaseModel

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import SignatureType, TransactionType


class RemovePublicKeySchema(BaseModel):
    sig_type: SignatureType
    managed_key_id: int
    time: int
    user_id: int
    key_identifier: int
    signature: str

    def to_message(self) -> "RemovePublicKeyMessage":
        return RemovePublicKeyMessage(
            version=2,
            signature_type=self.sig_type,
            managed_key_id=self.managed_key_id,
            time=self.time,
            user_id=self.user_id,
            key_identifier=self.key_identifier,
            signature_hex=self.signature,
        )


class RemovePublicKeyMessage(BaseMessage):
    """Remove a secondary public key from a user account.

    Identifies the key to remove by its ``managed_key_id``.  The signing key
    is identified by ``key_identifier``.

    Wire format (v2 only)
    ---------------------
    Header (3 bytes):  version=2 | command='k' | signature_type
    Body:              managed_key_id | time | key_identifier | user_id | signature
    """

    TRANSACTION_TYPE = TransactionType.REMOVE_PUBLIC_KEY
    HEADER_LENGTH = 3

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        managed_key_id: int,
        time: int,
        user_id: int,
        key_identifier: int,
        signature_hex: str | None = None,
    ) -> None:
        if version != 2:
            raise MessageValidationError("Unsupported version.")

        self.version = version
        self.signature_type = signature_type
        self.managed_key_id = managed_key_id
        self.time = time
        self.user_id = user_id
        self.key_identifier = key_identifier

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls) -> str:
        # managed_key_id | time | key_identifier | user_id | sig
        return f">I I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls) -> str:
        return cls.get_header_format() + cls.get_body_format()[1:]

    def __str__(self) -> str:
        return (
            f"v: {self.version}\n"
            "name: remove_public_key\n"
            f"user_id: {self.user_id}\n"
            f"managed_key_id: {self.managed_key_id}\n"
            f"key_identifier: {self.key_identifier}\n"
            f"time: {self.time}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            RemovePublicKeyMessage.get_format(),
            self.version,
            RemovePublicKeyMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            self.managed_key_id,
            self.time,
            self.key_identifier,
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
        try:
            version, command, signature_type = unpack(cls.get_header_format(), header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if version != 2:
            raise MessageFormatError("Unsupported version.")

        body_format = cls.get_body_format()
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            managed_key_id, time, key_identifier, user_id, signature_bytes = unpack(
                body_format, body_bytes
            )
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        message = cls(
            version=version,
            signature_type=SignatureType.from_int(signature_type),
            managed_key_id=managed_key_id,
            time=time,
            user_id=user_id,
            key_identifier=key_identifier,
            signature_hex=signature_bytes.hex(),
        )
        message._transaction_bytes = transaction_bytes
        return message
