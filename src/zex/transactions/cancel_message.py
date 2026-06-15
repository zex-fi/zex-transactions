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
            version=2,
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
        order_nonce: int | None,
        user_id: int,
        order_timestamp: int | None = None,
        key_identifier: int | None = None,
        signature_hex: str | None = None,
    ) -> None:
        if version not in (2, 3):
            raise MessageValidationError("Unsupported version.")

        self.signature_type = signature_type
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self.version = version
        self._order_nonce = order_nonce
        self._order_timestamp = order_timestamp
        self.user_id = user_id
        self._key_identifier = key_identifier

        if version == 2 and order_nonce is None:
            raise MessageValidationError("order_nonce is required for v2 messages.")
        if version == 3 and order_timestamp is None:
            raise MessageValidationError("order_timestamp is required for v3 messages.")
        if version == 3 and key_identifier is None:
            raise MessageValidationError("key_identifier is required for v3 messages.")

        self._transaction_bytes: bytes | None = None

    @property
    def order_nonce(self) -> int:
        if self._order_nonce is None:
            raise AttributeError("order_nonce is not available in v3 messages.")
        return self._order_nonce

    @property
    def order_timestamp(self) -> int:
        if self._order_timestamp is None:
            raise AttributeError("order_timestamp is not available in v2 messages.")
        return self._order_timestamp

    @property
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v1/v2 messages.")
        return self._key_identifier

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls, version: int = 2) -> str:
        # v2: user_id(Q) | order_nonce(Q) | sig
        # v3: user_id(Q) | order_timestamp(Q) | key_identifier(Q) | sig
        if version == 3:
            return f">QQQ {cls.SIGNATURE_LENGTH}s"
        return f">QQ {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, version: int = 2) -> str:
        return cls.get_header_format() + cls.get_body_format(version)[1:]

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

        if version not in (2, 3):
            raise MessageFormatError("Unsupported version.")
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        body_format = cls.get_body_format(version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - header_length < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[header_length : header_length + body_size]

        if version == 3:
            try:
                user_id, order_timestamp, key_identifier, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            order_nonce = None
        else:  # version 2
            try:
                user_id, order_nonce, signature_bytes = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            order_timestamp = None
            key_identifier = None

        try:
            sig_type = SignatureType.from_int(signature_type)
        except ValueError as e:
            raise MessageFormatError(f"Invalid signature type: {e}") from e

        cancel_message = cls(
            version=version,
            signature_type=sig_type,
            order_nonce=order_nonce,
            user_id=user_id,
            order_timestamp=order_timestamp,
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
        ]
        if self.version == 2:
            parts.append(f"order_nonce: {self._order_nonce}")
        else:
            parts.append(f"order_timestamp: {self._order_timestamp}")
            parts.append(f"key_identifier: {self._key_identifier}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 3:
            transaction_bytes = pack(
                CancelMessage.get_format(self.version),
                self.version,
                CancelMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.user_id,
                self._order_timestamp,
                self._key_identifier,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                CancelMessage.get_format(self.version),
                self.version,
                CancelMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.user_id,
                self._order_nonce,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
