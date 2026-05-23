from decimal import Decimal
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
from zex.utils.numbers import format_decimal, to_scientific
from zex.utils.zex_types import ChainName, SignatureType, TransactionType


class TransferStatus(Enum):
    NEW = 0
    CONFIRMED = 1
    FAILED = 2


class TransferSchema(BaseModel):
    sig_type: SignatureType
    token_name: str
    amount: str
    recipient_id: int
    t: int
    nonce: int
    user_id: int
    signature: str

    def to_message(self) -> "TransferMessage":
        mantissa, exponent = to_scientific(Decimal(self.amount))
        return TransferMessage(
            version=1,
            signature_type=self.sig_type,
            token_name=self.token_name,
            amount_mantissa=mantissa,
            amount_exponent=exponent,
            recipient_id=self.recipient_id,
            time=self.t,
            nonce=self.nonce,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class TransferMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.TRANSFER
    HEADER_LENGTH = 4

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        token_name: str,
        amount_mantissa: int,
        amount_exponent: int,
        recipient_id: int,
        time: int,
        nonce: int | None,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.version = version
        self.signature_type = signature_type
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self.token_name = token_name
        self.amount_mantissa = amount_mantissa
        self.amount_exponent = amount_exponent
        self.recipient_id = recipient_id
        self.time = time
        self._nonce = nonce
        self.user_id = user_id

        if version == 1 and nonce is None:
            raise MessageValidationError("nonce is required for v1 messages.")

        self.chain = ChainName.Internal
        self._transaction_bytes: bytes | None = None
        self.status = TransferStatus.NEW

        min_exponent = -TransferMessage.ADDITIONAL_EXPONENT
        if amount_exponent < min_exponent:
            raise MessageValidationError(
                f"amount_exponent {amount_exponent} is too small (minimum: {min_exponent})"
            )

    @property
    def nonce(self) -> int:
        if self._nonce is None:
            raise AttributeError("nonce is not available in v2 messages; use time instead.")
        return self._nonce

    @property
    def amount(self) -> int:
        return self.amount_mantissa * 10 ** (
            self.amount_exponent + TransferMessage.ADDITIONAL_EXPONENT
        )

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "TransferMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            version, command, signature_type, token_length = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if token_length == 0:
            raise MessageFormatError("Invalid token length.")

        body_format = cls.get_body_format(token_length, version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        if version == 1:
            try:
                (
                    token_name_bytes,
                    amount_mantissa,
                    amount_exponent,
                    recipient_id,
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
                    token_name_bytes,
                    amount_mantissa,
                    amount_exponent,
                    recipient_id,
                    time,
                    user_id,
                    signature_bytes,
                ) = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            nonce = None

        transfer_message = cls(
            version=version,
            signature_type=SignatureType.from_int(signature_type),
            token_name=token_name_bytes.decode("ascii"),
            amount_mantissa=amount_mantissa,
            amount_exponent=amount_exponent,
            recipient_id=recipient_id,
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        transfer_message._transaction_bytes = transaction_bytes
        return transfer_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBB"

    @classmethod
    def get_body_format(cls, token_length: int, version: int = 1) -> str:
        if version == 2:
            return f">{token_length}s Q b Q I Q {cls.SIGNATURE_LENGTH}s"
        return f">{token_length}s Q b Q I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, token_length: int, version: int = 1) -> str:
        return cls.get_header_format() + cls.get_body_format(token_length, version)[1:]

    def __str__(self) -> str:
        amount = format_decimal(Decimal(self.amount_mantissa) * 10 ** Decimal(self.amount_exponent))
        parts = [
            f"v: {self.version}",
            f"token_name: {self.token_name}",
            f"amount: {amount}",
            f"recipient_id: {self.recipient_id}",
            f"t: {self.time}",
        ]
        if self.version == 1:
            parts.append(f"nonce: {self._nonce}")
        parts.append(f"user_id: {self.user_id}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 1:
            transaction_bytes = pack(
                TransferMessage.get_format(token_length=len(self.token_name), version=1),
                self.version,
                TransferMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                len(self.token_name),
                self.token_name.encode("ascii"),
                self.amount_mantissa,
                self.amount_exponent,
                self.recipient_id,
                self.time,
                self._nonce,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                TransferMessage.get_format(token_length=len(self.token_name), version=2),
                self.version,
                TransferMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                len(self.token_name),
                self.token_name.encode("ascii"),
                self.amount_mantissa,
                self.amount_exponent,
                self.recipient_id,
                self.time,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    def confirm(self) -> None:
        self.status = TransferStatus.CONFIRMED

    def fail(self) -> None:
        self.status = TransferStatus.FAILED
