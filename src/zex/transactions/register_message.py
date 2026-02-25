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


class RegisterSchema(BaseModel):
    sig_type: SignatureType
    referral_code: str
    public_key: bytes
    signature: str

    def to_message(self) -> "RegisterMessage":
        return RegisterMessage(
            version=1,
            signature_type=self.sig_type,
            referral_code=self.referral_code,
            public_key=self.public_key,
            signature_hex=self.signature,
        )


class RegisterMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.REGISTER
    HEADER_LENGTH = 4

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        referral_code: str,
        public_key: bytes,
        signature_hex: str | None = None,
    ) -> None:
        self.user_id = -1

        self.referral_code = referral_code
        self.public_key = public_key
        self.signature_type = signature_type
        self.version = version
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self._transaction_bytes: bytes | None = None

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "RegisterMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            version, command, signature_type, referral_code_length = unpack(
                header_format, header_bytes
            )
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        sig_type = SignatureType.from_int(signature_type)
        if sig_type == SignatureType.SECP256K1:
            public_key_length = 33
        elif sig_type == SignatureType.ED25519:
            public_key_length = 32
        else:
            raise ValueError("Unknown signature type.")
        body_format = cls.get_body_format(referral_code_length, public_key_length)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            (
                referral_code,
                public_key,
                signature_bytes,
            ) = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        register_message = cls(
            version=version,
            signature_type=sig_type,
            referral_code=referral_code.decode("ascii"),
            public_key=public_key,
            signature_hex=signature_bytes.hex(),
        )
        register_message._transaction_bytes = transaction_bytes
        return register_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBB"

    @classmethod
    def get_body_format(cls, referral_code_length: int, public_key_length: int) -> str:
        return f">{referral_code_length}s {public_key_length}s {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, referral_code_length: int, public_key_length: int) -> str:
        return (
            cls.get_header_format()
            + cls.get_body_format(referral_code_length, public_key_length)[1:]
        )

    def __str__(self) -> str:
        if self.referral_code:
            return f"Welcome to ZEX.\nReferral code: {self.referral_code}"
        return "Welcome to ZEX."

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            RegisterMessage.get_format(
                referral_code_length=len(self.referral_code),
                public_key_length=len(self.public_key),
            ),
            #
            self.version,
            RegisterMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            len(self.referral_code),
            self.referral_code.encode("ascii"),
            self.public_key,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
