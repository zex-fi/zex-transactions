from collections import namedtuple
from enum import Enum

import base58
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


class Side(Enum):
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

    @classmethod
    def from_string(cls, value: str) -> "SignatureType":
        try:
            return cls[value.upper()]
        except KeyError as e:
            raise ValueError(f"'{value}' is not a valid SignatureType.") from e


class ExecutionType(Enum):
    NEW = "NEW"
    CANCELED = "CANCELED"
    REJECTED = "REJECTED"
    TRADE = "TRADE"
    EXPIRED = "EXPIRED"


ChainInfo = namedtuple("ChainInfo", ["id", "abbreviation"])


class ChainName(Enum):
    # 2. Use the namedtuple to define the value for each member
    Bitcoin = ChainInfo(id=0, abbreviation="BTC")
    Solana = ChainInfo(id=1, abbreviation="SOL")
    Ethereum = ChainInfo(id=2, abbreviation="ETH")
    Tron = ChainInfo(id=3, abbreviation="TRN")
    Sepolia = ChainInfo(id=4, abbreviation="SEP")
    Internal = ChainInfo(id=5, abbreviation="INT")

    # 3. (Optional but recommended) Add properties for cleaner access
    @property
    def id(self) -> int:
        return self.value.id

    @property
    def abbreviation(self) -> str:
        return self.value.abbreviation

    @classmethod
    def from_string(cls, s: str):
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

    def contract_to_bytes(self, contract_address: str) -> tuple[bytes, bool]:
        match self:
            case ChainName.Bitcoin:
                return b"", True
            case ChainName.Solana | ChainName.Tron:
                try:
                    return base58.b58decode(contract_address), True
                except ValueError:
                    return b"", False
            case ChainName.Ethereum | ChainName.Sepolia:
                try:
                    return bytes.fromhex(contract_address[2:]), True
                except ValueError:
                    return b"", False
            case _:
                raise NotImplementedError(f"chain {self} is not supported")

    def contract_to_str(self, contract_address: bytes) -> tuple[str, bool]:
        match self:
            case ChainName.Bitcoin:
                if len(contract_address) != 0:
                    return "", False
                return "", True
            case ChainName.Solana | ChainName.Tron:
                try:
                    return base58.b58encode(contract_address).decode("ascii"), True
                except UnicodeDecodeError:
                    return "", False
            case ChainName.Ethereum | ChainName.Sepolia:
                address_str = "0x" + contract_address.hex()
                try:
                    return to_checksum_address(address_str), True
                except (ValueError, TypeError):
                    return "", False
            case _:
                raise NotImplementedError(f"chain {self} is not supported")

    def destination_to_str(self, destination: bytes) -> tuple[str, bool]:
        match self:
            case ChainName.Bitcoin | ChainName.Solana | ChainName.Tron:
                try:
                    return destination.decode("ascii"), True
                except UnicodeDecodeError:
                    return "", False

            case ChainName.Ethereum | ChainName.Sepolia:  # EVM family
                try:
                    return to_checksum_address("0x" + destination.hex()), True
                except (ValueError, TypeError):
                    return "", False
            case _:
                raise NotImplementedError(f"chain {self} is not supported")

    def destination_to_bytes(self, destination: str) -> tuple[bytes, bool]:
        match self:
            case ChainName.Bitcoin | ChainName.Solana | ChainName.Tron:
                try:
                    return destination.encode("ascii"), True
                except UnicodeEncodeError:
                    return b"", False

            case ChainName.Ethereum | ChainName.Sepolia:  # EVM family
                try:
                    return bytes.fromhex(destination[2:]), True
                except (ValueError, TypeError):
                    return b"", False
            case _:
                raise NotImplementedError(f"chain {self} is not supported")

    def tx_hash_to_str(self, tx_hash: bytes):
        match self:
            case ChainName.Bitcoin | ChainName.Tron:
                return tx_hash.hex()
            case ChainName.Solana:
                return base58.b58encode(tx_hash).decode("ascii")
            case ChainName.Ethereum | ChainName.Sepolia:
                return "0x" + tx_hash.hex()
            case _:
                raise NotImplementedError(f"chain {self.abbreviation} is not supported")
