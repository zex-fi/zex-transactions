from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Literal

import base58
from bitcoinutils.keys import (
    P2pkhAddress,
    P2shAddress,
    P2trAddress,
    P2wpkhAddress,
)
from bitcoinutils.setup import setup as _btc_setup
from eth_utils.address import to_checksum_address

type UserPublic = bytes
type UserId = int
type OrderId = int
type TradeId = int
type DepositId = int
type WithdrawId = int

type OrderNonce = int

# type ChainName = str
type CurveName = str
type TokenName = str
type MarketName = str
type Address = str


class SecurityError(Exception):
    pass


class Side(StrEnum):
    BUY = "buy"
    SELL = "sell"


class TransactionType(Enum):
    REGISTER = ord("r")
    DEPOSIT = ord("d")
    WITHDRAW = ord("w")
    BUY = ord("b")
    SELL = ord("s")
    CANCEL = ord("c")
    TRANSFER = ord("t")
    PAUSE = ord("p")
    UPDATE_WITHDRAW = ord("u")


class SignatureType(Enum):
    SECP256K1 = 1
    ED25519 = 2

    @classmethod
    def from_int(cls, value: int) -> "SignatureType":
        if value == 1:
            return SignatureType.SECP256K1
        elif value == 2:
            return SignatureType.ED25519
        else:
            raise ValueError("Invalid value for signature type.")


class ExecutionType(StrEnum):
    NEW = "NEW"
    CANCELED = "CANCELED"
    REJECTED = "REJECTED"
    TRADE = "TRADE"
    EXPIRED = "EXPIRED"


class EncodingType(StrEnum):
    B58 = "b58"
    HEX = "hex"
    UTF8 = "utf-8"


@dataclass(frozen=True)
class ChainInfo:
    id: int
    abbreviation: str
    tx_hash_type: EncodingType
    address_type: EncodingType
    tx_hash_prefix: str


class ChainNameInvalidValueError(Exception):
    "raise if inputs are not valid for converting types"


type BtcNetwork = Literal["mainnet", "testnet", "testnet4", "signet", "regtest"]


def setup_btc_network(network: BtcNetwork = "testnet4") -> None:
    """Configure the Bitcoin network used for address validation.

    Must be called before any BTC address is validated. Defaults to testnet4.
    """
    _btc_setup(network)


def _validate_btc_address(address: str) -> None:
    """Validate a BTC address against all supported script types.

    Requires ``setup_btc_network()`` to have been called first; otherwise
    validation silently uses testnet (the bitcoinutils default).
    """

    # P2wshAddress is excluded: its __init__ hardcodes address=None, so it never
    # accepts an address string. All valid segwit v0 addresses (P2WPKH and P2WSH)
    # pass P2wpkhAddress validation instead.
    for cls in (P2pkhAddress, P2shAddress, P2wpkhAddress, P2trAddress):
        try:
            cls(address)
            return  # valid — stop as soon as one class accepts it
        except (ValueError, TypeError):
            pass
    raise ChainNameInvalidValueError(f"Invalid BTC address: {address}")


class ChainName(Enum):
    Bitcoin = ChainInfo(
        id=0,
        abbreviation="BTC",
        tx_hash_type=EncodingType.HEX,
        address_type=EncodingType.UTF8,
        tx_hash_prefix="",
    )
    Solana = ChainInfo(
        id=1,
        abbreviation="SOL",
        tx_hash_type=EncodingType.B58,
        address_type=EncodingType.B58,
        tx_hash_prefix="",
    )
    Ethereum = ChainInfo(
        id=2,
        abbreviation="ETH",
        tx_hash_type=EncodingType.HEX,
        address_type=EncodingType.HEX,
        tx_hash_prefix="0x",
    )
    Tron = ChainInfo(
        id=3,
        abbreviation="TRN",
        tx_hash_type=EncodingType.HEX,
        address_type=EncodingType.B58,
        tx_hash_prefix="",
    )
    Sepolia = ChainInfo(
        id=4,
        abbreviation="SEP",
        tx_hash_type=EncodingType.HEX,
        address_type=EncodingType.HEX,
        tx_hash_prefix="0x",
    )
    Internal = ChainInfo(
        id=5,
        abbreviation="INT",
        tx_hash_type=EncodingType.HEX,
        address_type=EncodingType.HEX,
        tx_hash_prefix="",
    )

    @property
    def id(self) -> int:
        return self.value.id

    @property
    def abbreviation(self) -> str:
        return self.value.abbreviation

    @property
    def tx_hash_type(self) -> EncodingType:
        return self.value.tx_hash_type

    @property
    def address_type(self) -> EncodingType:
        return self.value.address_type

    @property
    def tx_hash_prefix(self) -> str:
        return self.value.tx_hash_prefix

    @classmethod
    def from_string(cls, s: str) -> "ChainName":
        """
        Gets a ChainName member from a string (case-insensitive).
        Supports both full name and abbreviation.
        """
        s_lower = s.lower()
        for member in cls:
            # 4. Access values by name instead of index
            if member.name.lower() == s_lower or member.abbreviation.lower() == s_lower:
                return member
        raise ValueError(f"'{s}' is not a valid chain name or abbreviation.")

    def contract_to_bytes(self, contract_address: str) -> bytes:
        if ChainName.Bitcoin == self:
            return b""

        try:
            match self.address_type:
                case EncodingType.HEX:
                    return bytes.fromhex(contract_address.removeprefix("0x"))
                case EncodingType.B58:
                    return base58.b58decode(contract_address)
                case _:
                    raise NotImplementedError(f"chain {self} is not supported")
        except ValueError as e:
            raise ChainNameInvalidValueError(
                f"contract_address: {contract_address} for chain: {self.name} is not valid"
            ) from e

    def contract_to_str(self, contract_address: bytes) -> str:
        if ChainName.Bitcoin == self:
            if len(contract_address) != 0:
                raise ChainNameInvalidValueError(
                    f"contract_address: {contract_address} for chain: {self.name} is not valid"
                )
            return ""

        try:
            match self.address_type:
                case EncodingType.HEX:
                    return to_checksum_address(contract_address)
                case EncodingType.B58:
                    return base58.b58encode(contract_address).decode("utf-8")
                case _:
                    raise NotImplementedError(f"chain {self} is not supported")
        except (ValueError, TypeError) as e:
            raise ChainNameInvalidValueError(
                f"contract_address: {contract_address} for chain: {self.name} is not valid"
            ) from e

    def address_to_str(self, address: bytes) -> str:
        try:
            match self.address_type:
                case EncodingType.HEX:
                    return to_checksum_address(address)
                case EncodingType.B58:
                    return base58.b58encode(address).decode("utf-8")
                case EncodingType.UTF8:
                    str_address = address.decode("utf-8")
                    if ChainName.Bitcoin == self:
                        _validate_btc_address(str_address)
                    return str_address
                case _:
                    raise NotImplementedError(f"chain {self} is not supported")
        except (ValueError, TypeError, AttributeError) as e:
            raise ChainNameInvalidValueError(
                f"address: {address} for chain: {self.name} is not valid"
            ) from e

    def _value_to_bytes(self, value: str, encoding_type: EncodingType) -> bytes:
        try:
            match encoding_type:
                case EncodingType.HEX:
                    return bytes.fromhex(value.removeprefix("0x"))
                case EncodingType.B58:
                    return base58.b58decode(value)
                case EncodingType.UTF8:
                    return value.encode("utf-8")
                case _:
                    raise NotImplementedError(f"chain {self} is not supported")
        except (ValueError, TypeError, AttributeError) as e:
            raise ChainNameInvalidValueError(
                f"value: {value} for chain: {self.name} is not valid"
            ) from e

    def address_to_bytes(self, address: str) -> bytes:
        if self == ChainName.Bitcoin:
            _validate_btc_address(address)
        return self._value_to_bytes(address, self.address_type)

    def tx_hash_to_str(self, tx_hash: bytes) -> str:
        match self.tx_hash_type:
            case EncodingType.HEX:
                return self.tx_hash_prefix + tx_hash.hex()
            case EncodingType.B58:
                try:
                    return base58.b58encode(tx_hash).decode("utf-8")
                except (TypeError, ValueError) as e:
                    raise ChainNameInvalidValueError(
                        f"tx_hash: {tx_hash} for chain: {self.name} is not valid"
                    ) from e
            case _:
                raise NotImplementedError(f"chain {self} is not supported")

    def tx_hash_to_bytes(self, tx_hash: str) -> bytes:
        return self._value_to_bytes(tx_hash, self.tx_hash_type)
