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

_PUBLIC_KEY_LENGTHS = {
    SignatureType.SECP256K1: 33,
    SignatureType.ED25519: 32,
}


class LoginSchema(BaseModel):
    sig_type: SignatureType
    public_key: bytes
    timestamp: int
    hmac: bytes
    signature: str

    def to_message(self) -> "LoginMessage":
        return LoginMessage(
            version=1,
            signature_type=self.sig_type,
            public_key=self.public_key,
            timestamp=self.timestamp,
            hmac=self.hmac,
            signature_hex=self.signature,
        )


class LoginMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.LOGIN
    HEADER_LENGTH = 3
    HMAC_LENGTH = 32

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        public_key: bytes,
        timestamp: int,
        hmac: bytes,
        signature_hex: str | None = None,
        key_identifier: int | None = None,
    ) -> None:
        if version not in (1, 2):
            raise MessageValidationError("Unsupported version.")

        self.user_id = -1

        self.version = version
        self.signature_type = signature_type

        expected_pk_length = _PUBLIC_KEY_LENGTHS.get(signature_type)
        if expected_pk_length is None:
            raise MessageValidationError("Unknown signature type.")
        if len(public_key) != expected_pk_length:
            raise MessageValidationError(
                f"public_key must be {expected_pk_length} bytes for "
                f"{signature_type.name}, got {len(public_key)}."
            )
        self.public_key = public_key

        if not 0 <= timestamp < 2**64:
            raise MessageValidationError("timestamp must fit in a u64.")
        self.timestamp = timestamp

        if len(hmac) != LoginMessage.HMAC_LENGTH:
            raise MessageValidationError(
                f"hmac must be {LoginMessage.HMAC_LENGTH} bytes, got {len(hmac)}."
            )
        self.hmac = hmac

        self._key_identifier = key_identifier

        if version == 2 and key_identifier is None:
            raise MessageValidationError("key_identifier is required for v2 messages.")

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self._transaction_bytes: bytes | None = None

    @property
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v1 messages.")
        return self._key_identifier

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "LoginMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        try:
            version, command, signature_type = unpack(cls.get_header_format(), header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if version not in (1, 2):
            raise MessageFormatError("Unsupported version.")

        try:
            sig_type = SignatureType.from_int(signature_type)
        except ValueError as e:
            raise MessageFormatError(f"Invalid signature type: {e}") from e
        public_key_length = _PUBLIC_KEY_LENGTHS.get(sig_type)
        if public_key_length is None:
            raise MessageFormatError(f"Unsupported signature type: {sig_type}.")

        body_format = cls.get_body_format(public_key_length, version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        if version == 1:
            try:
                public_key, timestamp, hmac, signature_bytes = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            key_identifier = None
        else:  # v2
            try:
                public_key, timestamp, hmac, key_identifier, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e

        login_message = cls(
            version=version,
            signature_type=sig_type,
            public_key=public_key,
            timestamp=timestamp,
            hmac=hmac,
            signature_hex=signature_bytes.hex(),
            key_identifier=key_identifier,
        )
        login_message._transaction_bytes = transaction_bytes
        return login_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls, public_key_length: int, version: int = 1) -> str:
        base = f">{public_key_length}s Q {cls.HMAC_LENGTH}s"
        if version == 2:
            return base + f" I {cls.SIGNATURE_LENGTH}s"
        return base + f" {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, public_key_length: int, version: int = 1) -> str:
        return cls.get_header_format() + cls.get_body_format(public_key_length, version)[1:]

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: login",
            f"public_key: {self.public_key.hex()}",
            f"t: {self.timestamp}",
            f"hmac: {self.hmac.hex()}",
        ]
        if self.version == 2:
            parts.append(f"key_identifier: {self._key_identifier}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        fmt = LoginMessage.get_format(public_key_length=len(self.public_key), version=self.version)
        if self.version == 1:
            transaction_bytes = pack(
                fmt,
                self.version,
                LoginMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.public_key,
                self.timestamp,
                self.hmac,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                fmt,
                self.version,
                LoginMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.public_key,
                self.timestamp,
                self.hmac,
                self._key_identifier,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
