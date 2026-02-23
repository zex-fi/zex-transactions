from __future__ import annotations

from struct import calcsize, pack, unpack
from struct import error as struct_error

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import SignatureType, TransactionType


class PauseWithdrawMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.PAUSE
    HEADER_LENGTH = 3

    def __init__(
        self,
        version: int,
        signature_type_value: int,
        is_set: bool,
        time: int,
        nonce: int,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        self.signature_type = SignatureType.from_int(signature_type_value)
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self.version = version
        self.time = time
        self.is_set = is_set
        self.nonce = nonce
        self.user_id = user_id

        self._transaction_bytes: bytes | None = None

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls) -> str:
        return f">BIIQ {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls) -> str:
        return cls.get_header_format() + cls.get_body_format()[1:]

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> PauseWithdrawMessage:
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            version, command, signature_type = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        body_format = cls.get_body_format()
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        try:
            is_set, time, nonce, user_id, signature_bytes = unpack(body_format, body_bytes)
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack body: {e}") from e
        if is_set not in (0, 1):
            raise MessageFormatError("Incorrect value for is_set argument.")

        pause_withdraw_message = cls(
            version=version,
            signature_type_value=signature_type,
            is_set=bool(is_set),
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        pause_withdraw_message._transaction_bytes = transaction_bytes
        return pause_withdraw_message

    def __str__(self) -> str:
        return (
            f"v: {self.version}\n"
            "name: pause withdraw\n"
            f"is set: {self.is_set}\n"
            f"t: {self.time}\n"
            f"nonce: {self.nonce}\n"
            f"user_id: {self.user_id}\n"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        assert self.signature_hex is not None
        transaction_bytes = pack(
            PauseWithdrawMessage.get_format(),
            #
            self.version,
            PauseWithdrawMessage.TRANSACTION_TYPE.value,
            self.signature_type.value,
            self.is_set,
            self.time,
            self.nonce,
            self.user_id,
            bytes.fromhex(self.signature_hex),
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
