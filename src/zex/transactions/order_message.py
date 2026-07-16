from decimal import Decimal
from functools import lru_cache
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
    _HEADER_FORMAT: str = ">BBBBB"
    _HEADER_FORMAT_SIZE: int = calcsize(">BBBBB")

    # NOTE: If you add new attributes here, you MUST also set them in from_bytes().
    # from_bytes() bypasses __init__ for performance and sets attributes directly.
    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        base_token: str,
        quote_token: str,
        amount_mantissa: int,
        amount_exponent: int,
        price_mantissa: int,
        price_exponent: int,
        time: int,
        user_id: int,
        key_identifier: int | None = None,
        signature_hex: str | None = None,
    ) -> None:
        if version not in (2, 3):
            raise MessageValidationError("Unsupported version.")

        self.version = version
        self.signature_type = signature_type
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self.base_token = base_token
        self.quote_token = quote_token
        self.amount_mantissa = amount_mantissa
        self.amount_exponent = amount_exponent
        self.price_mantissa = price_mantissa
        self.price_exponent = price_exponent
        self.time = time
        self._key_identifier = key_identifier
        self.user_id = user_id

        if version == 3 and key_identifier is None:
            raise MessageValidationError("key_identifier is required for v3 messages.")

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
    def key_identifier(self) -> int:
        if self._key_identifier is None:
            raise AttributeError("key_identifier is not available in v2 messages.")
        return self._key_identifier

    @property
    def amount(self) -> int:
        return self.amount_mantissa * 10 ** (
            self.amount_exponent + OrderMessage.ADDITIONAL_EXPONENT
        )

    @property
    def price(self) -> int:
        return self.price_mantissa * 10 ** (self.price_exponent + OrderMessage.ADDITIONAL_EXPONENT)

    @classmethod
    def get_header_format(cls) -> str:
        return cls._HEADER_FORMAT

    @classmethod
    @lru_cache(maxsize=32)
    def get_body_format(  # pyright: ignore[reportIncompatibleMethodOverride]
        cls,
        base_token_length: int,
        quote_token_length: int,
        version: int = 2,
    ) -> str:
        base = f">{base_token_length}s {quote_token_length}s Q b Q b"
        # v2: time(Q) | user_id(Q) | sig
        # v3: time(Q) | key_identifier(Q) | user_id(Q) | sig
        if version == 3:
            return base + f" Q Q Q {cls.SIGNATURE_LENGTH}s"
        return base + f" Q Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(
        cls,
        base_token_length: int,
        quote_token_length: int,
        version: int = 2,
    ) -> str:
        return (
            cls._HEADER_FORMAT
            + cls.get_body_format(base_token_length, quote_token_length, version)[1:]
        )

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> "OrderMessage":
        header_length = cls._HEADER_FORMAT_SIZE
        if len(transaction_bytes) < header_length:
            raise HeaderFormatError("Transaction is too short for header.")

        try:
            version, command, signature_type, base_token_length, quote_token_length = unpack(
                cls._HEADER_FORMAT, transaction_bytes[:header_length]
            )
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e

        if version not in (2, 3):
            raise MessageFormatError("Unsupported version.")

        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if base_token_length == 0:
            raise MessageFormatError("Invalid base token length.")
        if quote_token_length == 0:
            raise MessageFormatError("Invalid quote token length.")

        body_format = cls.get_body_format(base_token_length, quote_token_length, version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - header_length < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[header_length : header_length + body_size]

        if version == 2:
            try:
                (
                    base_token_bytes,
                    quote_token_bytes,
                    amount_mantissa,
                    amount_exponent,
                    price_mantissa,
                    price_exponent,
                    time,
                    user_id,
                    signature_bytes,
                ) = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
            key_identifier = None
        else:  # v3
            try:
                (
                    base_token_bytes,
                    quote_token_bytes,
                    amount_mantissa,
                    amount_exponent,
                    price_mantissa,
                    price_exponent,
                    time,
                    key_identifier,
                    user_id,
                    signature_bytes,
                ) = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e

        try:
            sig_type = SignatureType.from_int(signature_type)
        except ValueError as e:
            raise MessageFormatError(f"Invalid signature type: {e}") from e

        # Performance: bypass __init__ to skip redundant validation (version check,
        # signature hex round-trip, exponent range check) — all already verified above
        # or guaranteed by struct.unpack. If you add attributes to __init__, add them here too.
        order_message = object.__new__(cls)
        order_message.version = version
        order_message.signature_type = sig_type
        order_message.signature_hex = signature_bytes.hex()
        order_message.base_token = base_token_bytes.decode("ascii")
        order_message.quote_token = quote_token_bytes.decode("ascii")
        order_message.amount_mantissa = amount_mantissa
        order_message.amount_exponent = amount_exponent
        order_message.price_mantissa = price_mantissa
        order_message.price_exponent = price_exponent
        order_message.time = time
        order_message._key_identifier = key_identifier
        order_message.user_id = user_id
        order_message._transaction_bytes = transaction_bytes
        return order_message

    def __str__(self) -> str:
        amount = format_decimal(Decimal(self.amount_mantissa) * 10 ** Decimal(self.amount_exponent))
        price = format_decimal(Decimal(self.price_mantissa) * 10 ** Decimal(self.price_exponent))
        name = "buy" if self.TRANSACTION_TYPE == TransactionType.BUY else "sell"
        parts = [
            f"v: {self.version}",
            f"name: {name}",
            f"base token: {self.base_token}",
            f"quote token: {self.quote_token}",
            f"amount: {amount}",
            f"price: {price}",
            f"t: {self.time}",
        ]
        if self.version == 3:
            parts.append(f"key_identifier: {self._key_identifier}")
        parts.append(f"user_id: {self.user_id}")
        return "\n".join(parts) + "\n"

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        if self.version == 2:
            transaction_bytes = pack(
                OrderMessage.get_format(
                    base_token_length=len(self.base_token),
                    quote_token_length=len(self.quote_token),
                    version=2,
                ),
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
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 3
            transaction_bytes = pack(
                OrderMessage.get_format(
                    base_token_length=len(self.base_token),
                    quote_token_length=len(self.quote_token),
                    version=3,
                ),
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
                self._key_identifier,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
