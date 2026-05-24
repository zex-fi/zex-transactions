from enum import Enum
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


class KeyMode(Enum):
    NAMED = 0
    UNNAMED = 1


class AddPublicKeySchema(BaseModel):
    sig_type: SignatureType
    key_signature_type: SignatureType
    key_identifier: int
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
    """Add a secondary public key to an existing user account.

    Named keys (KeyMode.NAMED) are permanent until explicitly removed.
    Unnamed keys (KeyMode.UNNAMED) expire at the given Unix timestamp (expiry).
    The key_identifier labels the key so users can reference it when signing
    transactions with the secondary key.

    This message must be signed by the account's master key.

    Wire format (v1)
    ----------------
    Header (4 bytes):  version | command='a' | signature_type | key_signature_type
    Body:              key_identifier | public_key | key_mode | expiry | time | nonce | user_id |
                       signature

    Wire format (v2)
    ----------------
    Header (4 bytes):  version | command='a' | signature_type | key_signature_type
    Body:              key_identifier | public_key | key_mode | expiry | time | user_id | signature
                       (nonce omitted; time serves as replay protection)
    """

    TRANSACTION_TYPE = TransactionType.ADD_PUBLIC_KEY
    HEADER_LENGTH = 4

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        key_signature_type: SignatureType,
        key_identifier: int,
        key_mode: KeyMode,
        expiry: int,
        public_key: bytes,
        nonce: int | None,
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
        self._nonce = nonce
        self.time = time
        self.user_id = user_id

        if version == 1 and nonce is None:
            raise MessageValidationError("nonce is required for v1 messages.")

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @property
    def nonce(self) -> int:
        if self._nonce is None:
            raise AttributeError("nonce is not available in v2 messages; use time instead.")
        return self._nonce

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBB"

    @classmethod
    def get_body_format(cls, public_key_length: int, version: int = 1) -> str:
        if version == 2:
            return f">I {public_key_length}s B I I Q {cls.SIGNATURE_LENGTH}s"
        return f">I {public_key_length}s B I I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, public_key_length: int, version: int = 1) -> str:
        return cls.get_header_format() + cls.get_body_format(public_key_length, version)[1:]

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: add_public_key",
            f"user_id: {self.user_id}",
            f"key_identifier: {self.key_identifier}",
            f"key_mode: {self.key_mode.name.lower()}",
            f"expiry: {self.expiry}",
        ]
        if self.version == 1:
            parts.append(f"nonce: {self._nonce}")
        parts += [
            f"time: {self.time}",
            f"public_key: {self.public_key.hex()}",
        ]
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 1:
            transaction_bytes = pack(
                AddPublicKeyMessage.get_format(
                    public_key_length=len(self.public_key),
                    version=1,
                ),
                self.version,
                AddPublicKeyMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.key_signature_type.value,
                self.key_identifier,
                self.public_key,
                self.key_mode.value,
                self.expiry,
                self.time,
                self._nonce,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                AddPublicKeyMessage.get_format(
                    public_key_length=len(self.public_key),
                    version=2,
                ),
                self.version,
                AddPublicKeyMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.key_signature_type.value,
                self.key_identifier,
                self.public_key,
                self.key_mode.value,
                self.expiry,
                self.time,
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
            version, command, signature_type, key_signature_type = unpack(
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

        body_format = cls.get_body_format(public_key_length, version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        if version == 1:
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
        else:  # v2
            try:
                (
                    key_identifier,
                    public_key,
                    key_mode_value,
                    expiry,
                    time,
                    user_id,
                    signature_bytes,
                ) = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            nonce = None

        message = cls(
            version=version,
            signature_type=sig_type,
            key_signature_type=key_sig_type,
            key_identifier=key_identifier,
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
