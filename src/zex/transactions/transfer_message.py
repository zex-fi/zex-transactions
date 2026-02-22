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
from zex.utils.zex_types import ChainName, SignatureType, TransactionType, UserId


class Recipient:
    def __init__(self, recipient_id: UserId, amount_mantissa: int, amount_exponent: int) -> None:
        self.recipient_id = recipient_id
        self.amount_mantissa = amount_mantissa
        self.amount_exponent = amount_exponent

    @property
    def amount(self) -> int:
        # NOTE The way the amount is stored in withdraw, deposit, and user balance
        # makes us add the additional exponent. This logic is spreaded throughout
        # the code and should be refactored.
        return self.amount_mantissa * 10 ** (
            self.amount_exponent + TransferMessage.ADDITIONAL_EXPONENT
        )

    @property
    def amount_str(self) -> str:
        return format_decimal(Decimal(self.amount_mantissa) * 10 ** Decimal(self.amount_exponent))

    def __str__(self) -> str:
        return f"recipient_id: {self.recipient_id}, amount: {self.amount_str}"


class TransferStatus(Enum):
    NEW = 0
    CONFIRMED = 1
    FAILED = 2


class TransferSchema(BaseModel):
    sig_type: int
    token_name: str
    recipients: list[tuple[UserId, str]]
    t: int
    nonce: int
    user_id: int
    signature: str

    def to_message(self) -> "TransferMessage":
        # preallocate memory
        recipients: list[Recipient] = [None] * len(self.recipients)  # pyright: ignore[reportAssignmentType]

        for i, (recipient_id, amount) in enumerate(self.recipients):
            mantissa, exponent = to_scientific(Decimal(amount))
            recipients[i] = Recipient(recipient_id, mantissa, exponent)

        return TransferMessage(
            version=1,
            signature_type_value=self.sig_type,
            token_name=self.token_name,
            recipients=recipients,
            time=self.t,
            nonce=self.nonce,
            user_id=self.user_id,
            signature_hex=self.signature,
        )


class TransferMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.TRANSFER
    HEADER_LENGTH = 5

    def __init__(
        self,
        version: int,
        signature_type_value: int,
        token_name: str,
        recipients: list[Recipient],
        time: int,
        nonce: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.version = version
        self.signature_type = SignatureType.from_int(signature_type_value)
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self.token_name = token_name
        self.recipients = recipients
        self.time = time
        self.nonce = nonce
        self.user_id = user_id

        self.chain = ChainName.Internal
        self._transaction_bytes: bytes | None = None
        self.status = TransferStatus.NEW

        min_exponent = -TransferMessage.ADDITIONAL_EXPONENT
        if any(r.amount_exponent < min_exponent for r in self.recipients):
            raise MessageValidationError(
                f"amount_exponent is too small for one the recipients (minimum: {min_exponent})"
            )

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "TransferMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            (
                version,
                command,
                signature_type,
                token_length,
                recipients_count,
            ) = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if token_length == 0:
            raise MessageFormatError("Invalid token length.")

        body_format = cls.get_body_format(token_length, recipients_count)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            unpacked_data = unpack(body_format, body_bytes)
            data_iter = iter(unpacked_data)

            token_name_bytes = next(data_iter)

            # preallocate memory
            recipients: list[Recipient] = [None] * recipients_count  # pyright: ignore[reportAssignmentType]

            for i in range(recipients_count):
                mantissa = next(data_iter)
                exponent = next(data_iter)
                recipient_id = next(data_iter)
                recipients[i] = Recipient(recipient_id, mantissa, exponent)
            time = next(data_iter)
            nonce = next(data_iter)
            user_id = next(data_iter)
            signature_bytes = next(data_iter)
        except (struct_error, StopIteration) as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        token_name = token_name_bytes.decode("ascii")
        signature = signature_bytes.hex()

        transfer_message = cls(
            version=version,
            signature_type_value=signature_type,
            token_name=token_name,
            recipients=recipients,
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature,
        )
        transfer_message._transaction_bytes = transaction_bytes
        return transfer_message

    @classmethod
    def get_header_format(cls) -> str:
        # version, command, signature type, token name length, recipients count
        return ">BBBBB"

    @classmethod
    def get_body_format(cls, token_length: int, recipients_count: int) -> str:
        # Pattern for one recipient: Mantissa (Q), Exponent (b), RecipientID (Q)
        recipient_pattern = "QbQ" * recipients_count
        return f">{token_length}s {recipient_pattern} I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, token_length: int, recipients_count: int) -> str:
        return cls.get_header_format() + cls.get_body_format(token_length, recipients_count)[1:]

    def __str__(self) -> str:
        return (
            f"v: {self.version}\n"
            f"token_name: {self.token_name}\n"
            f"recipients: {self.recipients}\n"
            f"t: {self.time}\n"
            f"nonce: {self.nonce}\n"
            f"user_id: {self.user_id}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None

        # Interleave recipient data: [m1, e1, id1, m2, e2, id2...]
        recipients_data = []
        for r in self.recipients:
            recipients_data.extend([r.amount_mantissa, r.amount_exponent, r.recipient_id])

        transaction_bytes = pack(
            TransferMessage.get_format(
                token_length=len(self.token_name),
                recipients_count=len(self.recipients),
            ),
            #
            self.version,
            TransferMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            len(self.token_name),
            len(self.recipients),
            self.token_name.encode("ascii"),
            *recipients_data,
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    def confirm(self) -> None:
        self.status = TransferStatus.CONFIRMED

    def fail(self) -> None:
        self.status = TransferStatus.FAILED
