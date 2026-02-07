from __future__ import annotations

from collections import namedtuple
from enum import Enum

from eth_utils.address import to_checksum_address


class SignatureType(Enum):
    SECP256K1 = 1
    ED25519 = 2

    @classmethod
    def from_int(cls, value: int) -> SignatureType:
        if value == 1:
            return SignatureType.SECP256K1
        elif value == 2:
            return SignatureType.ED25519
        else:
            raise ValueError("Invalid value for signature type.")


class TransactionType(Enum):
    REGISTER = ord("r")
    DEPOSIT = ord("d")
    WITHDRAW = ord("w")
    BUY = ord("b")
    SELL = ord("s")
    CANCEL = ord("c")
    TRANSFER = ord("t")
    PAUSE = ord("p")


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
