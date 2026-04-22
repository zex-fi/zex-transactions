from enum import Enum
from struct import calcsize, pack, unpack
from struct import error as struct_error
from typing import Any, ClassVar, Self

from coincurve import PrivateKey
from eth_account import Account
from eth_account.messages import encode_defunct
from frost_lib.custom_types import KeyPair
from pydantic import BaseModel
from zexfrost.utils import get_curve

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import ChainName, TransactionType

curve = get_curve(curve="secp256k1")


class UpdateWithdrawMessageStatus(Enum):
    REJECTED = ord("r")
    SUCCESSFUL = ord("s")


class UpdatedWithdrawal(BaseModel):
    BYTES_FORMAT: ClassVar[str] = "> Q {transaction_hash_length}s"

    id: int
    tx_hash: bytes

    def to_bytes(self: Self) -> bytes:
        try:
            return pack(
                self.BYTES_FORMAT.format(transaction_hash_length=len(self.tx_hash)),
                self.id,
                self.tx_hash,
            )
        except struct_error as e:
            raise MessageFormatError(f"Failed to pack withdraw: {e}") from e

    @classmethod
    def from_bytes(cls, data: bytes, transaction_hash_length: int) -> tuple[Self, int]:
        try:
            fmt = cls.BYTES_FORMAT.format(transaction_hash_length=transaction_hash_length)
            size = calcsize(fmt)
            id, tx_hash = unpack(fmt, data[:size])
            return cls(id=id, tx_hash=tx_hash), size
        except struct_error as e:
            raise MessageFormatError(f"Failed to unpack withdraw: {e}") from e


class UpdateWithdrawMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.UPDATE_WITHDRAW
    HEADER_LENGTH = 9
    FROST_SIGNATURE_LENGTH = 65
    ECDSA_SIGNATURE_LENGTH = 65
    SIGNATURE_LENGTH = FROST_SIGNATURE_LENGTH + ECDSA_SIGNATURE_LENGTH

    def __init__(
        self,
        version: int,
        chain: ChainName,
        status: UpdateWithdrawMessageStatus,
        transaction_hash_length: int,
        withdraws: list[UpdatedWithdrawal],
        frost_signature: bytes | None = None,
        ecdsa_signature: bytes | None = None,
    ) -> None:
        self.version = version
        self.chain = chain
        self.status = status

        if frost_signature is not None and len(frost_signature) != self.FROST_SIGNATURE_LENGTH:
            raise ValueError("The length of given frost signature does not match.")
        self.frost_signature = frost_signature

        if ecdsa_signature is not None and len(ecdsa_signature) != self.ECDSA_SIGNATURE_LENGTH:
            raise ValueError("The length of given ecdsa signature does not match.")
        self.ecdsa_signature = ecdsa_signature
        if any(len(w.tx_hash) != transaction_hash_length for w in withdraws):
            raise ValueError("All withdraw tx_hash lengths must match transaction_hash_length.")
        self.transaction_hash_length = transaction_hash_length
        if not withdraws:
            raise ValueError("withdraws must not be empty.")

        self.withdraws = withdraws

        self._transaction_bytes: bytes | None = None

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
                chain_bytes,
                status_int,
                transaction_hash_length,
                withdraws_count,
            ) = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")
        if withdraws_count == 0:
            raise MessageFormatError("Invalid withdraw count.")

        body_format = cls.get_body_format(transaction_hash_length)
        body_size = calcsize(body_format)
        total_body_size = body_size * withdraws_count
        if len(transaction_bytes) - cls.HEADER_LENGTH - cls.SIGNATURE_LENGTH != total_body_size:
            raise MessageFormatError(
                "Transaction length does not match the specified withdraw count."
            )
        withdraws = []
        for i in range(withdraws_count):
            index = i * body_size
            withdraw_bytes = transaction_bytes[
                cls.HEADER_LENGTH + index : cls.HEADER_LENGTH + index + body_size
            ]
            withdraw, _ = UpdatedWithdrawal.from_bytes(withdraw_bytes, transaction_hash_length)
            withdraws.append(withdraw)

        frost_signature, ecdsa_signature = unpack(
            cls.get_signature_format(),
            transaction_bytes[-cls.SIGNATURE_LENGTH :],
        )

        try:
            status = UpdateWithdrawMessageStatus(status_int)
        except ValueError as e:
            raise MessageFormatError(f"Invalid withdraw status: {status_int}") from e

        withdraw_message = cls(
            version=version,
            chain=ChainName.from_string(chain_bytes.decode("utf-8")),
            status=status,
            transaction_hash_length=transaction_hash_length,
            withdraws=withdraws,
            frost_signature=frost_signature,
            ecdsa_signature=ecdsa_signature,
        )
        withdraw_message._transaction_bytes = transaction_bytes
        return withdraw_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">B B 3s B B H"

    @classmethod
    def get_body_format(cls, transaction_hash_length: int) -> str:
        return UpdatedWithdrawal.BYTES_FORMAT.format(
            transaction_hash_length=transaction_hash_length
        )

    @classmethod
    def get_signature_format(cls) -> str:
        return f">{cls.FROST_SIGNATURE_LENGTH}s {cls.ECDSA_SIGNATURE_LENGTH}s"

    @classmethod
    def get_message_format(
        cls,
        transaction_hash_length: int,
    ) -> str:
        return cls.get_header_format() + cls.get_body_format(transaction_hash_length)[1:]

    @classmethod
    def get_format(cls, transaction_hash_length: int) -> str:
        return (
            cls.get_message_format(
                transaction_hash_length,
            )
            + cls.get_signature_format()[1:]
        )

    def __str__(self) -> str:
        return (
            f"version: {self.version},\n"
            f"chain: {self.chain.abbreviation},\n"
            f"status: {self.status},\n"
            f"transaction_hash_length: {self.transaction_hash_length},\n"
            f"withdraws: {self.withdraws},\n"
            f"frost_signature: {self.frost_signature},\n"
            f"ecdsa_signature: {self.ecdsa_signature}"
        )

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        if self.frost_signature is None or self.ecdsa_signature is None:
            raise ValueError("Cannot serialize message without both signatures")
        transaction_bytes = self.create_message() + pack(
            self.get_signature_format(),
            self.frost_signature,
            self.ecdsa_signature,
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    def create_message(self) -> bytes:
        body = b""
        for withdraw in self.withdraws:
            body += withdraw.to_bytes()

        return (
            pack(
                self.get_header_format(),
                *self._get_header_arguments(),
            )
            + body
        )

    def _get_header_arguments(self) -> list[Any]:
        return [
            self.version,
            self.TRANSACTION_TYPE.value,
            self.chain.abbreviation.encode("utf-8"),
            self.status.value,
            self.transaction_hash_length,
            len(self.withdraws),
        ]

    def verify_signature(
        self,
        public_key_bytes: bytes,
        frost_public_key: str,
        shield_address: str,
    ) -> bool:

        frost_verified = self._verify_frost_signature(frost_public_key)
        ecdsa_verified = self._verify_ecdsa_signature(shield_address)

        return frost_verified and ecdsa_verified

    def _verify_frost_signature(self, frost_public_key: str) -> bool:
        assert self.frost_signature is not None

        transaction_bytes = self._transaction_bytes or self.to_bytes()
        message = transaction_bytes[: -self.SIGNATURE_LENGTH]

        frost_verified = curve.single_verify(
            self.frost_signature.hex(),
            message,
            frost_public_key,
        )
        return frost_verified

    def _verify_ecdsa_signature(self, shield_address: str) -> bool:
        assert self.ecdsa_signature is not None

        transaction_bytes = self._transaction_bytes or self.to_bytes()
        message = transaction_bytes[: -self.SIGNATURE_LENGTH]

        eth_signed_message = encode_defunct(message)
        recovered_address = Account.recover_message(
            eth_signed_message, signature=self.ecdsa_signature
        )
        ecdsa_verified = recovered_address == shield_address
        return ecdsa_verified

    def sign(
        self,
        private_key: PrivateKey,
        frost_keypair: KeyPair,
        ecdsa_account: Account,
    ) -> bytes:
        message = self.create_message()
        return message + pack(
            self.get_signature_format(),
            self._create_frost_signature(message, frost_keypair),
            self._create_ecdsa_signature(message, ecdsa_account),
        )

    def _create_frost_signature(self, message: bytes, frost_keypair: KeyPair) -> bytes:
        if self.frost_signature is not None:
            return self.frost_signature
        frost_signature = bytes.fromhex(curve.single_sign(frost_keypair.signing_key, message))
        assert len(frost_signature) == self.FROST_SIGNATURE_LENGTH
        self.frost_signature = frost_signature
        return frost_signature

    def _create_ecdsa_signature(self, message: bytes, ecdsa_account: Account) -> bytes:
        if self.ecdsa_signature is not None:
            return self.ecdsa_signature
        eth_signed_message = encode_defunct(message)
        signed_message = ecdsa_account.sign_message(eth_signed_message)
        ecdsa_signature = signed_message.signature
        assert len(ecdsa_signature) == self.ECDSA_SIGNATURE_LENGTH
        self.ecdsa_signature = ecdsa_signature
        return ecdsa_signature
