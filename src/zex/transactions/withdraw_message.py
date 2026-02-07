from decimal import Decimal
from struct import calcsize, pack, unpack
from struct import error as struct_error
from typing import Self

from pydantic import BaseModel

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)
from zex.transactions.utils import format_decimal, to_scientific
from zex.transactions.zex_types import ChainName, SignatureType, TransactionType


class WithdrawMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.WITHDRAW
    HEADER_LENGTH = 8

    def __init__(
        self,
        version: int,
        signature_type_value: int,
        token_name: str,
        chain_name: ChainName,
        amount_mantissa: int,
        amount_exponent: int,
        destination_wallet: bytes,
        time: int,
        nonce: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.destination_wallet = destination_wallet
        self.signature_type = SignatureType.from_int(signature_type_value)
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex

        self.chain = chain_name
        self.amount_mantissa = amount_mantissa
        self.amount_exponent = amount_exponent
        self.version = version
        self.token_name = token_name
        self.time = time
        self.nonce = nonce
        self.user_id = user_id

        self._transaction_bytes: bytes | None = None

        min_exponent = -WithdrawMessage.ADDITIONAL_EXPONENT
        if amount_exponent < min_exponent:
            raise MessageValidationError(
                f"amount_exponent {amount_exponent} is too small (minimum: {min_exponent})"
            )

    @property
    def amount(self) -> int:
        # NOTE The way the amount is stored in withdraw, deposit, and user balance
        # makes us add the additional exponent. This logic is spreaded throughout
        # the code and should be refactored.
        return self.amount_mantissa * 10 ** (
            self.amount_exponent + WithdrawMessage.ADDITIONAL_EXPONENT
        )

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> Self:
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
                destination_wallet_length,
            ) = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if token_length == 0:
            raise MessageFormatError("Invalid token length.")
        if destination_wallet_length == 0:
            raise MessageFormatError("Invalid destination address length.")

        body_format = cls.get_body_format(token_length, destination_wallet_length)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            (
                token_chain_bytes,
                token_name_bytes,
                amount_mantissa,
                amount_exponent,
                destination_wallet,
                time,
                nonce,
                user_id,
                signature_bytes,
            ) = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e

        chain_name = ChainName.from_string(token_chain_bytes.decode("ascii"))
        token_name = token_name_bytes.decode("ascii")

        withdraw_message = cls(
            version=version,
            signature_type_value=signature_type,
            token_name=token_name,
            chain_name=chain_name,
            amount_mantissa=amount_mantissa,
            amount_exponent=amount_exponent,
            destination_wallet=destination_wallet,
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        withdraw_message._transaction_bytes = transaction_bytes
        return withdraw_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBBBI"

    @classmethod
    def get_body_format(cls, token_length: int, destination_wallet_length: int) -> str:
        # Token chain's length is hard-coded as 3.
        return f">3s {token_length}s Q b {destination_wallet_length}s I I Q {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, token_length: int, destination_wallet_length: int) -> str:
        return (
            cls.get_header_format()
            + cls.get_body_format(token_length, destination_wallet_length)[1:]
        )

    def __str__(self) -> str:
        amount = format_decimal(Decimal(self.amount_mantissa) * 10 ** Decimal(self.amount_exponent))
        destination_str, ok = self.chain.destination_to_str(self.destination_wallet)
        if not ok:
            raise MessageFormatError("destination_wallet is not valid")
        return (
            f"v: {self.version}\n"
            "name: withdraw\n"
            f"token chain: {self.chain.abbreviation}\n"
            f"token name: {self.token_name}\n"
            f"amount: {amount}\n"
            f"to: {destination_str}\n"
            f"t: {self.time}\n"
            f"nonce: {self.nonce}\n"
            f"user_id: {self.user_id}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            WithdrawMessage.get_format(
                token_length=len(self.token_name),
                destination_wallet_length=len(self.destination_wallet),
            ),
            #
            self.version,
            WithdrawMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            len(self.token_name),
            len(self.destination_wallet),
            self.chain.abbreviation.encode("ascii"),
            self.token_name.encode("ascii"),
            self.amount_mantissa,
            self.amount_exponent,
            self.destination_wallet,
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes


class WithdrawSchema(BaseModel):
    sig_type: int
    token_chain: str
    token_name: str
    amount: str
    destination: str
    t: int
    nonce: int
    user_id: int
    signature: str

    def to_message(self) -> WithdrawMessage:
        mantissa, exponent = to_scientific(Decimal(self.amount))
        chain = ChainName.from_string(self.token_chain)
        destination_wallet, ok = chain.destination_to_bytes(self.destination)
        if not ok:
            raise ValueError("Invalid destination address.")

        return WithdrawMessage(
            version=1,
            signature_type_value=self.sig_type,
            token_name=self.token_name,
            chain_name=chain,
            amount_mantissa=mantissa,
            amount_exponent=exponent,
            destination_wallet=destination_wallet,
            time=self.t,
            nonce=self.nonce,
            user_id=self.user_id,
            signature_hex=self.signature,
        )
