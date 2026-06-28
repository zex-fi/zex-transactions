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
    PERMANENT = 0
    TEMPORARY = 1


class AddPublicKeySchema(BaseModel):
    sig_type: SignatureType
    key_signature_type: SignatureType
    managed_key_id: int
    key_mode: KeyMode
    expiry: int | None
    public_key: bytes
    time: int
    user_id: int
    key_identifier: int
    signature: str

    def to_message(self) -> "AddPublicKeyMessage":
        return AddPublicKeyMessage(
            version=3,
            signature_type=self.sig_type,
            key_signature_type=self.key_signature_type,
            managed_key_id=self.managed_key_id,
            key_mode=self.key_mode,
            expiry=self.expiry,
            public_key=self.public_key,
            time=self.time,
            user_id=self.user_id,
            key_identifier=self.key_identifier,
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
        managed_key_id: int,
        key_mode: KeyMode,
        expiry: int | None,
        public_key: bytes,
        time: int,
        user_id: int,
        key_identifier: int,
        signature_hex: str | None = None,
    ) -> None:
        if version != 3:
            raise MessageValidationError("Unsupported version.")

        self.version = version
        self.signature_type = signature_type
        self.key_signature_type = key_signature_type
        self.managed_key_id = managed_key_id
        self.key_mode = key_mode
        self._expiry = expiry
        self.public_key = public_key
        self.time = time
        self.user_id = user_id
        self._key_identifier = key_identifier

        if key_mode == KeyMode.TEMPORARY and expiry is None:
            raise MessageValidationError("expiry is required for temporary keys.")
        if key_mode == KeyMode.PERMANENT and expiry is not None:
            raise MessageValidationError("expiry must not be set for permanent keys.")

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @property
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v2 messages.")
        return self._key_identifier

    @property
    def expiry(self) -> int | None:
        return self._expiry

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBBB"

    @classmethod
    def get_body_format(cls, public_key_length: int, key_mode: KeyMode) -> str:
        prefix = f">I {public_key_length}s"
        if key_mode == KeyMode.TEMPORARY:
            # expiry(Q), time(Q), key_identifier(Q), user_id(Q), sig
            suffix = f"Q Q Q Q {cls.SIGNATURE_LENGTH}s"
        else:
            # time(Q), key_identifier(Q), user_id(Q), sig
            suffix = f"Q Q Q {cls.SIGNATURE_LENGTH}s"
        return f"{prefix} {suffix}"

    @classmethod
    def get_format(cls, public_key_length: int, key_mode: KeyMode) -> str:
        body = cls.get_body_format(public_key_length, key_mode)
        return cls.get_header_format() + body[1:]

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: add_public_key",
            f"user_id: {self.user_id}",
            f"managed_key_id: {self.managed_key_id}",
            f"key_mode: {self.key_mode.name.lower()}",
        ]
        if self.key_mode == KeyMode.TEMPORARY:
            parts.append(f"expiry: {self.expiry}")
        parts += [
            f"time: {self.time}",
            f"key_identifier: {self._key_identifier}",
            f"public_key: {self.public_key.hex()}",
        ]
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None

        fmt = AddPublicKeyMessage.get_format(len(self.public_key), self.key_mode)

        args: list[object] = [
            self.version,
            AddPublicKeyMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            self.key_signature_type.value,
            self.key_mode.value,
            self.managed_key_id,
            self.public_key,
        ]
        if self.key_mode == KeyMode.TEMPORARY:
            args.append(self.expiry)
        args.extend(
            [self.time, self._key_identifier, self.user_id, bytes.fromhex(self.signature_hex)]
        )

        self._transaction_bytes = pack(fmt, *args)
        return self._transaction_bytes

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "AddPublicKeyMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        try:
            version, command, signature_type, key_signature_type, key_mode_byte = unpack(
                cls.get_header_format(), header_bytes
            )
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if version != 3:
            raise MessageFormatError("Unsupported version.")

        sig_type = SignatureType.from_int(signature_type)
        key_sig_type = SignatureType.from_int(key_signature_type)
        if key_sig_type == SignatureType.SECP256K1:
            public_key_length = 33
        elif key_sig_type == SignatureType.ED25519:
            public_key_length = 32
        else:
            raise ValueError("Unknown key signature type.")

        key_mode = KeyMode(key_mode_byte)

        body_format = cls.get_body_format(public_key_length, key_mode)
        body_start = cls.HEADER_LENGTH
        body_size = calcsize(body_format)
        if len(transaction_bytes) - body_start < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[body_start : body_start + body_size]

        try:
            if key_mode == KeyMode.TEMPORARY:
                managed_key_id, pub_key, expiry, time, key_identifier, user_id, sig_bytes = unpack(
                    body_format, body_bytes
                )
            else:  # PERMANENT
                managed_key_id, pub_key, time, key_identifier, user_id, sig_bytes = unpack(
                    body_format, body_bytes
                )
                expiry = None
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        message = cls(
            version=version,
            signature_type=sig_type,
            key_signature_type=key_sig_type,
            managed_key_id=managed_key_id,
            key_mode=key_mode,
            expiry=expiry,
            public_key=pub_key,
            time=time,
            user_id=user_id,
            key_identifier=key_identifier,
            signature_hex=sig_bytes.hex(),
        )
        message._transaction_bytes = transaction_bytes
        return message
