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


class CancelSchema(BaseModel):
    sig_type: SignatureType
    order_nonce: int
    user_id: int
    signature: str

    def to_message(self) -> "CancelMessage":
        return CancelMessage(
            version=1,
            signature_type=self.sig_type,
            order_nonce=self.order_nonce,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class CancelMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.CANCEL
    HEADER_LENGTH = 3

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        order_nonce: int,
        user_id: int,
        signature_hex: str | None = None,
        key_identifier: int | None = None,
    ) -> None:
        self.signature_type = signature_type
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self.version = version
        self.order_nonce = order_nonce
        self.user_id = user_id
        self._key_identifier = key_identifier

        if version == 2 and key_identifier is None:
            raise MessageValidationError("key_identifier is required for v2 messages.")

        self._transaction_bytes: bytes | None = None

    @property
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v1 messages.")
        return self._key_identifier

    @classmethod
    def get_header_format(cls, version: int = 1) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls, version: int = 1) -> str:
        if version == 2:
            return f">QQI {cls.SIGNATURE_LENGTH}s"
        return f">QQ {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, version: int = 1) -> str:
        return cls.get_header_format(version) + cls.get_body_format(version)[1:]

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "CancelMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")

        header_format = cls.get_header_format()
        header_length = calcsize(header_format)
        header_bytes = transaction_bytes[:header_length]

        try:
            version, command, signature_type = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e

        if version not in (1, 2):
            raise MessageFormatError(f"Unsupported message version: {version}")
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        body_format = cls.get_body_format(version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - header_length < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[header_length : header_length + body_size]

        if version == 1:
            try:
                user_id, order_nonce, signature_bytes = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            key_identifier = None
        else:  # v2
            try:
                user_id, order_nonce, key_identifier, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e

        cancel_message = cls(
            version=version,
            signature_type=SignatureType.from_int(signature_type),
            order_nonce=order_nonce,
            user_id=user_id,
            key_identifier=key_identifier,
            signature_hex=signature_bytes.hex(),
        )
        cancel_message._transaction_bytes = transaction_bytes
        return cancel_message

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: cancel",
            f"user_id: {self.user_id}",
            f"order_nonce: {self.order_nonce}",
        ]
        if self.version == 2:
            parts.append(f"key_identifier: {self._key_identifier}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 1:
            transaction_bytes = pack(
                CancelMessage.get_format(version=1),
                self.version,
                CancelMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.user_id,
                self.order_nonce,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                CancelMessage.get_format(version=2),
                self.version,
                CancelMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.user_id,
                self.order_nonce,
                self._key_identifier,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
