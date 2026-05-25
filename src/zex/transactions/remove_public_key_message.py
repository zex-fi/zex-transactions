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
    nonce: int
    time: int
    user_id: int
    signature: str

    def to_message(self) -> "RemovePublicKeyMessage":
        return RemovePublicKeyMessage(
            version=1,
            signature_type=self.sig_type,
            managed_key_id=self.managed_key_id,
            nonce=self.nonce,
            time=self.time,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class RemovePublicKeyMessage(BaseMessage):
    """Remove a secondary public key from a user account.

    Identifies the key to remove by its ``managed_key_id``.  In v2, the
    signing key is identified by ``key_identifier``.

    Wire format (v1)
    ----------------
    Header (3 bytes):  version | command='k' | signature_type
    Body:              managed_key_id | time | nonce | user_id | signature

    Wire format (v2)
    ----------------
    Header (3 bytes):  version | command='k' | signature_type
    Body:              managed_key_id | time | key_identifier | user_id | signature
                       (nonce omitted; time serves as replay protection)
    """

    TRANSACTION_TYPE = TransactionType.REMOVE_PUBLIC_KEY
    HEADER_LENGTH = 3

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        managed_key_id: int,
        nonce: int | None,
        time: int,
        user_id: int,
        signature_hex: str | None = None,
        key_identifier: int | None = None,
    ) -> None:
        if version not in (1, 2):
            raise MessageValidationError("Unsupported version.")

        self.version = version
        self.signature_type = signature_type
        self.managed_key_id = managed_key_id
        self._nonce = nonce
        self.time = time
        self.user_id = user_id
        self._key_identifier = key_identifier

        if version == 1 and nonce is None:
            raise MessageValidationError("nonce is required for v1 messages.")
        if version == 2 and key_identifier is None:
            raise MessageValidationError("key_identifier is required for v2 messages.")

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @property
    def nonce(self) -> int:
        if self._nonce is None:
            raise AttributeError("nonce is not available in v2 messages; use time instead.")
        return self._nonce

    @property
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v1 messages.")
        return self._key_identifier

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls, version: int = 1) -> str:
        # v1: managed_key_id | time | nonce | user_id | sig
        # v2: managed_key_id | time | key_identifier | user_id | sig
        return f">I I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, version: int = 1) -> str:
        return cls.get_header_format() + cls.get_body_format(version)[1:]

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: remove_public_key",
            f"user_id: {self.user_id}",
            f"managed_key_id: {self.managed_key_id}",
        ]
        if self.version == 1:
            parts.append(f"nonce: {self._nonce}")
        else:
            parts.append(f"key_identifier: {self._key_identifier}")
        parts.append(f"time: {self.time}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 1:
            transaction_bytes = pack(
                RemovePublicKeyMessage.get_format(version=1),
                self.version,
                RemovePublicKeyMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.managed_key_id,
                self.time,
                self._nonce,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                RemovePublicKeyMessage.get_format(version=2),
                self.version,
                RemovePublicKeyMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.managed_key_id,
                self.time,
                self._key_identifier,
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
            version, command, signature_type = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        body_format = cls.get_body_format(version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        if version == 1:
            try:
                managed_key_id, time, nonce, user_id, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            key_identifier = None
        else:  # v2
            try:
                managed_key_id, time, key_identifier, user_id, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            nonce = None

        message = cls(
            version=version,
            signature_type=SignatureType.from_int(signature_type),
            managed_key_id=managed_key_id,
            nonce=nonce,
            time=time,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
            key_identifier=key_identifier,
        )
        message._transaction_bytes = transaction_bytes
        return message
