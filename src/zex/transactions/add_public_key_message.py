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
    key_identifier: int
    key_mode: KeyMode
    expiry: int | None
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

    Permanent keys (KeyMode.PERMANENT) are valid until explicitly removed;
    no expiry is stored on the wire.  Temporary keys (KeyMode.TEMPORARY)
    expire at the given Unix timestamp and carry an expiry field in the
    message body.

    This message must be signed by the account's master key.

    Wire format (v1)
    ----------------
    Header (4 bytes):  version | command='a' | signature_type | key_signature_type
    Body (PERMANENT):  key_identifier | public_key | key_mode | time | nonce | user_id | signature
    Body (TEMPORARY):  key_identifier | public_key | key_mode | expiry | time | nonce |
                       user_id | signature

    Wire format (v2)
    ----------------
    Header (4 bytes):  version | command='a' | signature_type | key_signature_type
    Body (PERMANENT):  key_identifier | public_key | key_mode | time | user_id | signature
    Body (TEMPORARY):  key_identifier | public_key | key_mode | expiry | time | user_id | signature
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
        expiry: int | None,
        public_key: bytes,
        nonce: int | None,
        time: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        if version not in (1, 2):
            raise MessageValidationError("Unsupported version.")

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
        if key_mode == KeyMode.TEMPORARY and expiry is None:
            raise MessageValidationError("expiry is required for temporary keys.")
        if key_mode == KeyMode.PERMANENT and expiry is not None:
            raise MessageValidationError("expiry must not be set for permanent keys.")

        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self._transaction_bytes: bytes | None = None

    @property
    def nonce(self) -> int:
        if self.version == 2 or self._nonce is None:
            raise AttributeError("nonce is not available in v2 messages; use time instead.")
        return self._nonce

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBB"

    @classmethod
    def get_body_format(cls, public_key_length: int, version: int, key_mode: KeyMode) -> str:
        """Return the struct format string for the message body.

        The format depends on both version (v1 includes nonce, v2 does not)
        and key_mode (TEMPORARY includes expiry, PERMANENT does not).
        """
        prefix = f">I {public_key_length}s B"
        has_expiry = key_mode == KeyMode.TEMPORARY
        if version == 1:
            if has_expiry:
                suffix = f"I I I Q {cls.SIGNATURE_LENGTH}s"  # expiry, time, nonce, user_id, sig
            else:
                suffix = f"I I Q {cls.SIGNATURE_LENGTH}s"  # time, nonce, user_id, sig
        else:  # v2
            if has_expiry:
                suffix = f"I I Q {cls.SIGNATURE_LENGTH}s"  # expiry, time, user_id, sig
            else:
                suffix = f"I Q {cls.SIGNATURE_LENGTH}s"  # time, user_id, sig
        return f"{prefix} {suffix}"

    @classmethod
    def get_format(cls, public_key_length: int, version: int, key_mode: KeyMode) -> str:
        body = cls.get_body_format(public_key_length, version, key_mode)
        return cls.get_header_format() + body[1:]

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: add_public_key",
            f"user_id: {self.user_id}",
            f"key_identifier: {self.key_identifier}",
            f"key_mode: {self.key_mode.name.lower()}",
        ]
        if self.key_mode == KeyMode.TEMPORARY:
            parts.append(f"expiry: {self.expiry}")
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

        fmt = AddPublicKeyMessage.get_format(len(self.public_key), self.version, self.key_mode)

        # Build args: header + body prefix (key_id, pubkey, key_mode)
        args: list[object] = [
            self.version,
            AddPublicKeyMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            self.key_signature_type.value,
            self.key_identifier,
            self.public_key,
            self.key_mode.value,
        ]
        if self.key_mode == KeyMode.TEMPORARY:
            args.append(self.expiry)
        args.append(self.time)
        if self.version == 1:
            args.append(self._nonce)
        args.extend([self.user_id, bytes.fromhex(self.signature_hex)])

        self._transaction_bytes = pack(fmt, *args)
        return self._transaction_bytes

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "AddPublicKeyMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        try:
            version, command, signature_type, key_signature_type = unpack(
                cls.get_header_format(), header_bytes
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

        # Peek at key_mode (it comes after key_identifier + public_key in the body).
        peek_format = f">I {public_key_length}s B"
        peek_size = calcsize(peek_format)
        body_start = cls.HEADER_LENGTH
        if len(transaction_bytes) - body_start < peek_size:
            raise MessageFormatError("Transaction body is too short.")
        _, _, key_mode_byte = unpack(
            peek_format, transaction_bytes[body_start : body_start + peek_size]
        )
        key_mode = KeyMode(key_mode_byte)

        # Full body parse now that we know key_mode.
        body_format = cls.get_body_format(public_key_length, version, key_mode)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - body_start < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[body_start : body_start + body_size]

        try:
            if version == 1 and key_mode == KeyMode.TEMPORARY:
                key_id, pub_key, km, expiry, time, nonce, user_id, sig_bytes = unpack(
                    body_format, body_bytes
                )
            elif version == 1:  # PERMANENT
                key_id, pub_key, km, time, nonce, user_id, sig_bytes = unpack(
                    body_format, body_bytes
                )
                expiry = None
            elif key_mode == KeyMode.TEMPORARY:  # v2, TEMPORARY
                key_id, pub_key, km, expiry, time, user_id, sig_bytes = unpack(
                    body_format, body_bytes
                )
                nonce = None
            else:  # v2, PERMANENT
                key_id, pub_key, km, time, user_id, sig_bytes = unpack(body_format, body_bytes)
                expiry = None
                nonce = None
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        message = cls(
            version=version,
            signature_type=sig_type,
            key_signature_type=key_sig_type,
            key_identifier=key_id,
            key_mode=KeyMode(km),
            expiry=expiry,
            public_key=pub_key,
            nonce=nonce,
            time=time,
            user_id=user_id,
            signature_hex=sig_bytes.hex(),
        )
        message._transaction_bytes = transaction_bytes
        return message
