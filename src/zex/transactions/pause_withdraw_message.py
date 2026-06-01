from __future__ import annotations

from struct import calcsize, pack, unpack
from struct import error as struct_error

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import SignatureType, TransactionType


class PauseWithdrawMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.PAUSE
    HEADER_LENGTH = 3

    def __init__(
        self,
        version: int,
        signature_type: SignatureType,
        is_set: bool,
        time: int,
        nonce: int | None,
        user_id: int,
        signature_hex: str | None = None,
    ) -> None:
        if version not in (1, 2):
            raise MessageValidationError("Unsupported version.")

        self.signature_type = signature_type
        self.validate_signature(signature_hex)
        self.signature_hex = signature_hex
        self.version = version
        self.time = time
        self.is_set = is_set
        self._nonce = nonce
        self.user_id = user_id

        if nonce is None:
            raise MessageValidationError("nonce is required.")

        self._transaction_bytes: bytes | None = None

    @property
    def nonce(self) -> int:
        assert self._nonce is not None
        return self._nonce

    @classmethod
    def get_header_format(cls) -> str:
        return ">BBB"

    @classmethod
    def get_body_format(cls, version: int = 1) -> str:
        # v1: is_set | time(I) | nonce | user_id | sig
        # v2: is_set | time(Q) | key_identifier | user_id | sig
        if version == 2:
            return f">BQIQ {cls.SIGNATURE_LENGTH}s"
        return f">BIIQ {cls.SIGNATURE_LENGTH}s"

    @classmethod
    def get_format(cls, version: int = 1) -> str:
        return cls.get_header_format() + cls.get_body_format(version)[1:]

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
        if version not in (1, 2):
            raise MessageFormatError("Unsupported version.")

        body_format = cls.get_body_format(version)
        body_size = calcsize(body_format)
        if len(transaction_bytes) - cls.HEADER_LENGTH < body_size:
            raise MessageFormatError("Transaction body is too short.")
        body_bytes = transaction_bytes[cls.HEADER_LENGTH : cls.HEADER_LENGTH + body_size]

        if version == 1:
            try:
                is_set, time, nonce, user_id, signature_bytes = unpack(body_format, body_bytes)
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e
        else:  # v2
            try:
                is_set, time, nonce, user_id, signature_bytes = unpack(
                    body_format, body_bytes
                )
            except struct_error as e:
                raise MessageFormatError(f"Failed to unpack body: {e}") from e

        if is_set not in (0, 1):
            raise MessageFormatError("Incorrect value for is_set argument.")

        try:
            sig_type = SignatureType.from_int(signature_type)
        except ValueError as e:
            raise MessageFormatError(f"Invalid signature type: {e}") from e

        pause_withdraw_message = cls(
            version=version,
            signature_type=sig_type,
            is_set=bool(is_set),
            time=time,
            nonce=nonce,
            user_id=user_id,
            signature_hex=signature_bytes.hex(),
        )
        pause_withdraw_message._transaction_bytes = transaction_bytes
        return pause_withdraw_message

    def __str__(self) -> str:
        parts = [
            f"v: {self.version}",
            "name: pause withdraw",
            f"is set: {self.is_set}",
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
                PauseWithdrawMessage.get_format(version=1),
                self.version,
                PauseWithdrawMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.is_set,
                self.time,
                self._nonce,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        else:  # version == 2
            transaction_bytes = pack(
                PauseWithdrawMessage.get_format(version=2),
                self.version,
                PauseWithdrawMessage.TRANSACTION_TYPE.value,
                self.signature_type.value,
                self.is_set,
                self.time,
                self._nonce,
                self.user_id,
                bytes.fromhex(self.signature_hex),
            )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes
