from decimal import Decimal
from struct import calcsize, pack, unpack
from struct import error as struct_error

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)
from zex.utils.numbers import format_decimal
from zex.utils.zex_types import SignatureType, TransactionType


class OrderMessage(BaseMessage):
    HEADER_LENGTH = 5

    def __init__(
        self,
        version: int,
        signature_type_value: int,
        base_token: str,
        quote_token: str,
        amount_mantissa: int,
        amount_exponent: int,
        price_mantissa: int,
        price_exponent: int,
        time: int,
        nonce: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.version = version
        self.signature_type = SignatureType.from_int(signature_type_value)
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self.base_token = base_token
        self.quote_token = quote_token
        self.amount_mantissa = amount_mantissa
        self.amount_exponent = amount_exponent
        self.price_mantissa = price_mantissa
        self.price_exponent = price_exponent
        self.time = time
        self.nonce = nonce
        self.user_id = user_id

        self._transaction_bytes: bytes | None = None

        min_exponent = -OrderMessage.ADDITIONAL_EXPONENT
        if amount_exponent < min_exponent:
            raise MessageValidationError(
                f"amount_exponent {amount_exponent} is too small (minimum: {min_exponent})"
            )
        if price_exponent < min_exponent:
            raise MessageValidationError(
                f"price_exponent {price_exponent} is too small (minimum: {min_exponent})"
            )

    @property
    def amount(self) -> int:
        # NOTE The way the amount is stored in withdraw, deposit, and user balance
        # makes us add the additional exponent. This logic is spreaded throughout
        # the code and should be refactored.
        return self.amount_mantissa * 10 ** (
            self.amount_exponent + OrderMessage.ADDITIONAL_EXPONENT
        )

    @property
    def price(self) -> int:
        # NOTE The way the amount is stored in withdraw, deposit, and user balance
        # makes us add the additional exponent. This logic is spreaded throughout
        # the code and should be refactored.
        return self.price_mantissa * 10 ** (self.price_exponent + OrderMessage.ADDITIONAL_EXPONENT)

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "OrderMessage":
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            (
                version,
                command,
                signature_type,
                base_token_length,
                quote_token_length,
            ) = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if base_token_length == 0:
            raise MessageFormatError("Invalid base token length.")
        if quote_token_length == 0:
            raise MessageFormatError("Invalid quote token length.")

        body_format = cls.get_body_format(base_token_length, quote_token_length)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            (
                base_token_bytes,
                quote_token_bytes,
                amount_mantissa,
                amount_exponent,
                price_mantissa,
                price_exponent,
                time,
                nonce,
                user_id,
                signature_bytes,
            ) = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        base_token = base_token_bytes.decode("ascii")
        quote_token = quote_token_bytes.decode("ascii")
        signature = signature_bytes.hex()

        order_message = cls(
            version=version,
            signature_type_value=signature_type,
            base_token=base_token,
            quote_token=quote_token,
            amount_mantissa=amount_mantissa,
            amount_exponent=amount_exponent,
            price_mantissa=price_mantissa,
            price_exponent=price_exponent,
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature,
        )
        order_message._transaction_bytes = transaction_bytes
        return order_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBBB"

    @classmethod
    def get_body_format(cls, base_token_length: int, quote_token_length: int) -> str:
        return f">{base_token_length}s {quote_token_length}s Q b Q b I Q Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, base_token_length: int, quote_token_length: int) -> str:
        return (
            cls.get_header_format() + cls.get_body_format(base_token_length, quote_token_length)[1:]
        )

    def __str__(self) -> str:
        amount = format_decimal(Decimal(self.amount_mantissa) * 10 ** Decimal(self.amount_exponent))
        price = format_decimal(Decimal(self.price_mantissa) * 10 ** Decimal(self.price_exponent))
        return (
            f"v: {self.version}\n"
            f"name: {'buy' if self.TRANSACTION_TYPE == TransactionType.BUY else 'sell'}\n"
            f"base token: {self.base_token}\n"
            f"quote token: {self.quote_token}\n"
            f"amount: {amount}\n"
            f"price: {price}\n"
            f"t: {self.time}\n"
            f"nonce: {self.nonce}\n"
            f"user_id: {self.user_id}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            OrderMessage.get_format(
                base_token_length=len(self.base_token),
                quote_token_length=len(self.quote_token),
            ),
            #
            self.version,
            self.TRANSACTION_TYPE.value,
            self.signature_type.value,
            len(self.base_token),
            len(self.quote_token),
            self.base_token.encode("ascii"),
            self.quote_token.encode("ascii"),
            self.amount_mantissa,
            self.amount_exponent,
            self.price_mantissa,
            self.price_exponent,
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
