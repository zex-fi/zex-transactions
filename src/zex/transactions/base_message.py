from __future__ import annotations

from abc import ABC, abstractmethod
from struct import calcsize, unpack
from struct import error as struct_error
from typing import Any, ClassVar

from coincurve import PrivateKey, PublicKey, ecdsa
from eth_hash.auto import keccak
from solders.pubkey import Pubkey
from solders.signature import Signature

from zex.transactions.exceptions import MessageFormatError, MessageValidationError
from zex.utils.zex_types import SignatureType, TransactionType


class BaseMessage(ABC):
    TRANSACTION_TYPE: ClassVar[TransactionType]
    HEADER_LENGTH: ClassVar[int]
    ADDITIONAL_EXPONENT: ClassVar[int] = 18
    SIGNATURE_LENGTH: ClassVar[int] = 64
    TRANSACTION_TYPE_FORMAT = ">xB"
    _TRANSACTION_TYPE_MAP: ClassVar[dict[int, type["BaseMessage"]] | None] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.version = 1
        self.user_id = -1
        self.signature_type: SignatureType
        self.signature_hex: str | None
        self._transaction_bytes: bytes | None

    @classmethod
    @abstractmethod
    def get_header_format(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def get_body_format(cls, *args: Any, **kwargs: Any) -> str:
        pass

    @classmethod
    @abstractmethod
    def get_format(cls, *args: Any, **kwargs: Any) -> str:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def to_bytes(self) -> bytes:
        pass

    @classmethod
    def get_leaf_subclasses(cls: type) -> set[type[BaseMessage]]:
        leaves = set()

        def _resolve_leaves(current_cls):
            subs = current_cls.__subclasses__()
            if not subs:
                leaves.add(current_cls)
            else:
                for sub in subs:
                    _resolve_leaves(sub)

        for child in cls.__subclasses__():
            _resolve_leaves(child)

        return leaves

    @classmethod
    def from_bytes(cls, transaction_bytes: bytes) -> BaseMessage:
        try:
            (transaction_type_value,) = unpack(
                cls.TRANSACTION_TYPE_FORMAT,
                transaction_bytes[: calcsize(cls.TRANSACTION_TYPE_FORMAT)],
            )
        except struct_error as e:
            raise MessageFormatError(
                f"Failed to unpack transaction type from transaction bytes: {e}"
            ) from e

        # Lazy initialization
        if cls._TRANSACTION_TYPE_MAP is None:
            cls._TRANSACTION_TYPE_MAP = cls._build_transaction_type_map()

        concrete_message = cls._TRANSACTION_TYPE_MAP.get(transaction_type_value)

        if concrete_message is None:
            raise ValueError(
                f"No message class registered for transaction type {transaction_type_value}"
            )

        return concrete_message.from_bytes(transaction_bytes)

    @classmethod
    def _build_transaction_type_map(cls) -> dict[int, type["BaseMessage"]]:
        mapping: dict[int, type[BaseMessage]] = {}

        for leaf in cls.get_leaf_subclasses():
            tx_type = leaf.TRANSACTION_TYPE.value
            if tx_type in mapping:
                raise RuntimeError(
                    f"Duplicate TRANSACTION_TYPE value {tx_type} for "
                    f"{leaf.__name__} and {mapping[tx_type].__name__}"
                )
            mapping[tx_type] = leaf

        return mapping

    def create_message(self) -> bytes:
        if self.signature_type == SignatureType.SECP256K1:
            message = "".join(("\x19Ethereum Signed Message:\n", str(len(str(self))), str(self)))
        elif self.signature_type == SignatureType.ED25519:
            message = str(self)
        else:
            raise ValueError("The message type is invalid.")
        return message.encode("ascii")

    def sign(self, private_key: PrivateKey, *args, **kwargs) -> bytes:
        if self.signature_type == SignatureType.SECP256K1:
            signature = private_key.sign_recoverable(keccak(self.create_message()), hasher=None)
            signature = signature[:64]  # Compact format
            self.signature_hex = signature.hex()
            return signature
        elif self.signature_type == SignatureType.ED25519:
            raise NotImplementedError()
        else:
            raise ValueError("The signature type of this message is not valid.")

    def validate_signature(self, signature_hex: str | None) -> None:
        if signature_hex is None:
            return
        try:
            if len(bytes.fromhex(signature_hex)) != self.SIGNATURE_LENGTH:
                raise MessageValidationError("The length of the provided signature is not valid.")
        except ValueError as e:
            raise MessageFormatError(
                "The provided signature is not a valid hexadecimal number."
            ) from e

    def verify_signature(self, public_key_bytes: bytes, *args, **kwargs) -> bool:
        assert self.signature_hex is not None
        if self.signature_type == SignatureType.SECP256K1:
            public_key_secp256k1 = PublicKey(public_key_bytes)
            signature = ecdsa.cdata_to_der(
                ecdsa.deserialize_compact(bytes.fromhex(self.signature_hex))
            )
            message_hash = keccak(self.create_message())
            return public_key_secp256k1.verify(signature, message_hash, hasher=None)
        elif self.signature_type == SignatureType.ED25519:
            public_key_ed25519 = Pubkey.from_bytes(public_key_bytes)
            signature = Signature.from_bytes(bytes.fromhex(self.signature_hex))
            msg = self.create_message()
            return signature.verify(public_key_ed25519, msg)
        else:
            raise ValueError("The signature type of this message is not valid.")
