from __future__ import annotations

from struct import calcsize, pack, unpack
from struct import error as struct_error
from typing import Any

from coincurve import PrivateKey
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import BaseModel
from web3 import Web3
from zexfrost.utils import get_curve

from zex.transactions.base_message import BaseMessage
from zex.transactions.exceptions import (
    HeaderFormatError,
    UnexpectedCommandError,
)
from zex.utils.zex_types import ChainName, TransactionType

w3 = Web3()

curve = get_curve(curve="secp256k1")


class Deposit(BaseModel):
    transaction_hash: bytes
    token_contract: bytes
    amount: int
    decimal: int
    time: int
    salt_length: int
    vout: int
    salt: int


class DepositMessage(BaseMessage):
    TRANSACTION_TYPE = TransactionType.DEPOSIT
    HEADER_LENGTH = 9
    SIGNATURE_LENGTH = 130
    FROST_SIGNATURE_LENGTH = 65
    ECDSA_SIGNATURE_LENGTH = 65
    AMOUNT_BYTES_LENGTH = 32

    def __init__(
        self,
        version: int,
        chain: ChainName,
        transaction_hash_length: int,
        token_contract_length: int,
        deposits: list[Deposit],
        frost_signature: bytes | None = None,
        ecdsa_signature: bytes | None = None,
    ) -> None:
        self.version = version
        self.chain = chain
        self.transaction_hash_length = transaction_hash_length
        self.token_contract_length = token_contract_length
        self.deposits = deposits

        if (
            frost_signature is not None
            and len(frost_signature) != DepositMessage.FROST_SIGNATURE_LENGTH
        ):
            raise ValueError("The length of given frost signature does not match.")
        self.frost_signature = frost_signature

        if (
            ecdsa_signature is not None
            and len(ecdsa_signature) != DepositMessage.ECDSA_SIGNATURE_LENGTH
        ):
            raise ValueError("The length of given ecdsa signature does not match.")
        self.ecdsa_signature = ecdsa_signature

        self._transaction_bytes: bytes | None = None
        self.user_id = self.deposits[0].salt

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> DepositMessage:
        if len(transaction_bytes) < cls.HEADER_LENGTH:
            raise HeaderFormatError("Transaction is too short for header.")
        header_bytes = transaction_bytes[: cls.HEADER_LENGTH]
        header_format = cls.get_header_format()
        try:
            (
                version,
                command,
                chain_bytes,
                transaction_hash_length,
                token_contract_length,
                count,
            ) = unpack(header_format, header_bytes)
        except struct_error as e:
            raise HeaderFormatError(f"Failed to unpack header: {e}") from e
        if command != cls.TRANSACTION_TYPE.value:
            raise UnexpectedCommandError("Unexpected command.")

        single_deposit_part1_format = cls.get_body_format_part1(
            transaction_hash_length, token_contract_length
        )
        single_deposit_part1_length = calcsize(single_deposit_part1_format)

        deposits: list[Deposit] = []
        index = cls.HEADER_LENGTH
        for _ in range(count):
            (
                transaction_hash,
                token_contract,
                amount_bytes,
                decimal,
                time,
                salt_length,
            ) = unpack(
                single_deposit_part1_format,
                transaction_bytes[index : index + single_deposit_part1_length],
            )

            single_deposit_part2_format = cls.get_body_format_part2(salt_length)
            single_deposit_part2_length = calcsize(single_deposit_part2_format)
            salt_bytes, vout = unpack(
                single_deposit_part2_format,
                transaction_bytes[
                    index + single_deposit_part1_length : index
                    + single_deposit_part1_length
                    + single_deposit_part2_length
                ],
            )

            amount = int.from_bytes(amount_bytes, byteorder="big")
            assert decimal <= 18
            amount *= 10 ** (18 - decimal)

            deposits.append(
                Deposit(
                    transaction_hash=transaction_hash,
                    token_contract=token_contract,
                    amount=amount,
                    decimal=decimal,
                    time=time,
                    salt_length=salt_length,
                    vout=vout,
                    salt=int.from_bytes(salt_bytes, "big"),
                )
            )
            index += single_deposit_part1_length + single_deposit_part2_length

        frost_signature, ecdsa_signature = unpack(
            cls.get_signature_format(),
            transaction_bytes[-cls.SIGNATURE_LENGTH :],
        )
        deposit_message = DepositMessage(
            version=version,
            chain=ChainName.from_string(chain_bytes.decode("ascii")),
            transaction_hash_length=transaction_hash_length,
            token_contract_length=token_contract_length,
            deposits=deposits,
            frost_signature=frost_signature,
            ecdsa_signature=ecdsa_signature,
        )
        deposit_message._transaction_bytes = transaction_bytes
        return deposit_message

    @classmethod
    def get_header_format(cls) -> str:
        return ">B B 3s B B H"

    @classmethod
    def get_body_format(
        cls,
        transaction_hash_length: int,
        token_contrant_length: int,
        salt_lengths: list[int],
    ) -> str:
        result = ">"
        body_format_part1 = cls.get_body_format_part1(
            transaction_hash_length=transaction_hash_length,
            token_contract_length=token_contrant_length,
        )
        for salt_length in salt_lengths:
            body_format_part2 = cls.get_body_format_part2(salt_length)
            result += body_format_part1[1:] + body_format_part2[1:]
        return result

    @classmethod
    def get_body_format_part1(
        cls,
        transaction_hash_length: int,
        token_contract_length: int,
    ) -> str:
        return (
            f">{transaction_hash_length}s {token_contract_length}s{cls.AMOUNT_BYTES_LENGTH}s B I B"
        )

    @classmethod
    def get_body_format_part2(cls, salt_length: int) -> str:
        return f">{salt_length}s B"

    @classmethod
    def get_signature_format(cls) -> str:
        return f">{cls.FROST_SIGNATURE_LENGTH}s {cls.ECDSA_SIGNATURE_LENGTH}s"

    @classmethod
    def get_message_format(
        cls, transaction_hash_length: int, token_contranct_length: int, salt_lengths: list[int]
    ) -> str:
        return (
            cls.get_header_format()
            + cls.get_body_format(
                transaction_hash_length,
                token_contranct_length,
                salt_lengths,
            )[1:]
        )

    @classmethod
    def get_format(
        cls, transaction_hash_length: int, token_contranct_length: int, salt_lengths: list[int]
    ) -> str:
        return (
            cls.get_message_format(
                transaction_hash_length,
                token_contranct_length,
                salt_lengths,
            )
            + cls.get_signature_format()[1:]
        )

    def __str__(self) -> str:
        return ""

    def to_bytes(self) -> bytes:
        if self._transaction_bytes is not None:
            return self._transaction_bytes
        transaction_bytes = self.create_message() + pack(
            DepositMessage.get_signature_format(),
            self.frost_signature,
            self.ecdsa_signature,
        )
        self._transaction_bytes = transaction_bytes
        return transaction_bytes

    def create_message(self) -> bytes:
        return pack(
            DepositMessage.get_message_format(
                self.transaction_hash_length,
                self.token_contract_length,
                salt_lengths=[deposit.salt_length for deposit in self.deposits],
            ),
            *self._get_message_arguments(),
        )

    def sign(
        self,
        private_key: PrivateKey,
        frost_keypair: Any,
        ecdsa_account: Account,
    ) -> bytes:
        message = self.create_message()
        return message + pack(
            DepositMessage.get_signature_format(),
            self._create_frost_signature(message, frost_keypair),
            self._create_ecdsa_signature(message, ecdsa_account),
        )

    def verify_signature(
        self,
        public_key_bytes: bytes,
        deposit_frost_public_key: str,
        deposit_shield_address: str,
    ) -> bool:
        transaction_bytes = self._transaction_bytes or self.to_bytes()
        message = transaction_bytes[: -DepositMessage.SIGNATURE_LENGTH]

        # Verify FROST signature
        assert self.frost_signature is not None
        assert self.ecdsa_signature is not None
        frost_verified = curve.single_verify(
            self.frost_signature.hex(),
            message,
            deposit_frost_public_key,
        )

        # Verify ECDSA signature
        eth_signed_message = encode_defunct(message)
        recovered_address = w3.eth.account.recover_message(
            eth_signed_message, signature=self.ecdsa_signature
        )
        deposit_shield_address = deposit_shield_address
        ecdsa_verified = recovered_address == deposit_shield_address

        return frost_verified and ecdsa_verified

    def _get_message_arguments(self) -> list[Any]:
        header_arguments = [
            self.version,
            DepositMessage.TRANSACTION_TYPE.value,
            self.chain.abbreviation.encode("ascii"),
            self.transaction_hash_length,
            self.token_contract_length,
            len(self.deposits),
        ]
        body_arguments = []
        for deposit in self.deposits:
            # NOTE The order of arguments is important.
            body_arguments.extend(
                [
                    deposit.transaction_hash,
                    deposit.token_contract,
                    self._calculate_amount_bytes(deposit.amount, deposit.decimal),
                    deposit.decimal,
                    deposit.time,
                    deposit.salt_length,
                    deposit.salt.to_bytes(deposit.salt_length, byteorder="big"),
                    deposit.vout,
                ]
            )
        return [*header_arguments, *body_arguments]

    def _create_frost_signature(self, message: bytes, frost_keypair: Any) -> bytes:
        if self.frost_signature is not None:
            return self.frost_signature
        frost_signature = bytes.fromhex(curve.single_sign(frost_keypair.signing_key, message))
        assert len(frost_signature) == DepositMessage.FROST_SIGNATURE_LENGTH
        self.frost_signature = frost_signature
        return frost_signature

    def _create_ecdsa_signature(self, message: bytes, ecdsa_account: Account) -> bytes:
        if self.ecdsa_signature is not None:
            return self.ecdsa_signature
        eth_signed_message = encode_defunct(message)
        signed_message = ecdsa_account.sign_message(eth_signed_message)
        ecdsa_signature = signed_message.signature
        assert len(ecdsa_signature) == DepositMessage.ECDSA_SIGNATURE_LENGTH
        self.ecdsa_signature = ecdsa_signature
        return ecdsa_signature

    def _calculate_amount_bytes(self, amount: int, decimal: int) -> bytes:
        if decimal > 18:
            raise ValueError("Decimal cannot be bigger than 18.")
        scale_factor: int = 10 ** (18 - decimal)

        original_amount = amount // scale_factor
        return original_amount.to_bytes(DepositMessage.AMOUNT_BYTES_LENGTH, byteorder="big")
