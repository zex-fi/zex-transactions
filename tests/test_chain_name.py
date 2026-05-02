import pytest
import base58


from zex.utils.zex_types import ChainName, ChainNameInvalidValueError, EncodingType


class TestChainNameProperties:
    def test_bitcoin_properties(self):
        chain = ChainName.Bitcoin
        assert chain.id == 0
        assert chain.abbreviation == "BTC"
        assert chain.tx_hash_type == EncodingType.HEX
        assert chain.address_type == EncodingType.UTF8
        assert chain.tx_hash_prefix == ""

    def test_solana_properties(self):
        chain = ChainName.Solana
        assert chain.id == 1
        assert chain.abbreviation == "SOL"
        assert chain.tx_hash_type == EncodingType.B58
        assert chain.address_type == EncodingType.B58
        assert chain.tx_hash_prefix == ""

    def test_ethereum_properties(self):
        chain = ChainName.Ethereum
        assert chain.id == 2
        assert chain.abbreviation == "ETH"
        assert chain.tx_hash_type == EncodingType.HEX
        assert chain.address_type == EncodingType.HEX
        assert chain.tx_hash_prefix == "0x"

    def test_tron_properties(self):
        chain = ChainName.Tron
        assert chain.id == 3
        assert chain.abbreviation == "TRN"
        assert chain.tx_hash_type == EncodingType.HEX
        assert chain.address_type == EncodingType.B58
        assert chain.tx_hash_prefix == ""

    def test_sepolia_properties(self):
        chain = ChainName.Sepolia
        assert chain.id == 4
        assert chain.abbreviation == "SEP"
        assert chain.tx_hash_type == EncodingType.HEX
        assert chain.address_type == EncodingType.HEX
        assert chain.tx_hash_prefix == "0x"

    def test_internal_properties(self):
        chain = ChainName.Internal
        assert chain.id == 5
        assert chain.abbreviation == "INT"
        assert chain.tx_hash_type == EncodingType.HEX
        assert chain.address_type == EncodingType.HEX
        assert chain.tx_hash_prefix == ""


class TestFromString:
    @pytest.mark.parametrize(
        "s, expected",
        [
            ("Bitcoin", ChainName.Bitcoin),
            ("bitcoin", ChainName.Bitcoin),
            ("BITCOIN", ChainName.Bitcoin),
            ("BTC", ChainName.Bitcoin),
            ("btc", ChainName.Bitcoin),
            ("Solana", ChainName.Solana),
            ("SOL", ChainName.Solana),
            ("sol", ChainName.Solana),
            ("Ethereum", ChainName.Ethereum),
            ("ETH", ChainName.Ethereum),
            ("eth", ChainName.Ethereum),
            ("Tron", ChainName.Tron),
            ("TRN", ChainName.Tron),
            ("trn", ChainName.Tron),
            ("Sepolia", ChainName.Sepolia),
            ("SEP", ChainName.Sepolia),
            ("sep", ChainName.Sepolia),
            ("Internal", ChainName.Internal),
            ("INT", ChainName.Internal),
            ("int", ChainName.Internal),
        ],
    )
    def test_valid_strings(self, s, expected):
        assert ChainName.from_string(s) == expected

    @pytest.mark.parametrize("s", ["invalid", "", "BIT", "ETHER", "sol1"])
    def test_invalid_string_raises(self, s):
        with pytest.raises(ValueError):
            ChainName.from_string(s)


class TestContractToBytes:
    def test_bitcoin_returns_empty_bytes(self):
        assert ChainName.Bitcoin.contract_to_bytes("") == b""

    def test_ethereum_hex_address(self):
        addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        result = ChainName.Ethereum.contract_to_bytes(addr)
        assert result == bytes.fromhex(addr)

    def test_ethereum_hex_address_with_prefix(self):
        addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        result = ChainName.Ethereum.contract_to_bytes("0x" + addr)
        assert result == bytes.fromhex(addr)

    def test_solana_b58_address(self):
        addr = "So11111111111111111111111111111111111111112"
        result = ChainName.Solana.contract_to_bytes(addr)
        assert result == base58.b58decode(addr)

    def test_ethereum_invalid_address_raises(self):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Ethereum.contract_to_bytes("not_hex!")


class TestContractToStr:
    def test_bitcoin_empty_bytes_returns_empty_string(self):
        assert ChainName.Bitcoin.contract_to_str(b"") == ""

    def test_bitcoin_non_empty_bytes_raises(self):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Bitcoin.contract_to_str(b"\x01")

    def test_ethereum_bytes_returns_checksum_address(self):
        raw = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        result = ChainName.Ethereum.contract_to_str(raw)
        assert result == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

    def test_solana_bytes_returns_b58_string(self):
        addr = "So11111111111111111111111111111111111111112"
        raw = base58.b58decode(addr)
        result = ChainName.Solana.contract_to_str(raw)
        assert result == addr


class TestAddressToBytes:
    def test_ethereum_hex_address(self):
        addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        assert ChainName.Ethereum.address_to_bytes(addr) == bytes.fromhex(addr)

    def test_ethereum_hex_address_with_prefix(self):
        addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        assert ChainName.Ethereum.address_to_bytes("0x" + addr) == bytes.fromhex(addr)

    def test_solana_b58_address(self):
        addr = "So11111111111111111111111111111111111111112"
        assert ChainName.Solana.address_to_bytes(addr) == base58.b58decode(addr)

    def test_bitcoin_b58_address(self):
        # Using a valid segwit address (P2WPKH)
        addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert ChainName.Bitcoin.address_to_bytes(addr) == addr.encode()

    def test_invalid_hex_raises(self):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Ethereum.address_to_bytes("not_hex!")


class TestAddressToStr:
    def test_ethereum_returns_checksum_address(self):
        raw = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        result = ChainName.Ethereum.address_to_str(raw)
        assert result == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

    def test_solana_returns_b58_string(self):
        addr = "So11111111111111111111111111111111111111112"
        raw = base58.b58decode(addr)
        assert ChainName.Solana.address_to_str(raw) == addr

    def test_bitcoin_returns_b58_string(self):
        # Using a valid segwit address (P2WPKH)
        addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        raw = addr.encode()
        assert ChainName.Bitcoin.address_to_str(raw) == addr


class TestTxHashToBytes:
    def test_ethereum_hex_tx_hash(self):
        tx = "0x" + "ab" * 32
        assert ChainName.Ethereum.tx_hash_to_bytes(tx) == bytes.fromhex("ab" * 32)

    def test_bitcoin_hex_tx_hash_no_prefix(self):
        tx = "ab" * 32
        assert ChainName.Bitcoin.tx_hash_to_bytes(tx) == bytes.fromhex("ab" * 32)

    def test_solana_b58_tx_hash(self):
        tx_bytes = b"\x01" * 32
        tx = base58.b58encode(tx_bytes).decode()
        assert ChainName.Solana.tx_hash_to_bytes(tx) == tx_bytes

    def test_invalid_hex_raises(self):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Ethereum.tx_hash_to_bytes("not_hex!")


class TestTxHashToStr:
    def test_ethereum_adds_prefix(self):
        tx_bytes = bytes.fromhex("ab" * 32)
        assert ChainName.Ethereum.tx_hash_to_str(tx_bytes) == "0x" + "ab" * 32

    def test_bitcoin_no_prefix(self):
        tx_bytes = bytes.fromhex("ab" * 32)
        assert ChainName.Bitcoin.tx_hash_to_str(tx_bytes) == "ab" * 32

    def test_solana_returns_b58(self):
        tx_bytes = b"\x01" * 32
        assert ChainName.Solana.tx_hash_to_str(tx_bytes) == base58.b58encode(tx_bytes).decode()


class TestBitcoinAddressValidation:
    """Test Bitcoin address validation for all supported script types."""

    @pytest.mark.parametrize(
        "addr",
        [
            # P2PKH — legacy, starts with 1
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "1ADMYXTkuBE8EcdiWvCBvnxX4xsjFX9FSF",
            # P2SH — starts with 3
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "3Ai1JZ8pdJb2ksieUV8FsxSNVJCpoPi8W6",
            # P2WPKH / P2WSH — both start with bc1q; P2wshAddress cannot validate
            # address strings (library limitation), so P2wpkhAddress covers both.
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            # P2TR — taproot, starts with bc1p
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        ],
    )
    def test_valid_address_accepted(self, addr):
        result = ChainName.Bitcoin.address_to_bytes(addr)
        assert result == addr.encode()

    @pytest.mark.parametrize(
        "addr",
        [
            "not_a_valid_address",
            "bc1qinvalidchecksum",
            "1InvalidAddress",
            "",
            "0x1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
        ],
    )
    def test_invalid_address_raises(self, addr):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Bitcoin.address_to_bytes(addr)

    @pytest.mark.parametrize(
        "addr",
        [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        ],
    )
    def test_address_to_str_valid(self, addr):
        assert ChainName.Bitcoin.address_to_str(addr.encode()) == addr

    @pytest.mark.parametrize(
        "addr",
        [
            "invalid_bitcoin_address",
            "bc1qinvalidchecksum",
        ],
    )
    def test_address_to_str_invalid_raises(self, addr):
        with pytest.raises(ChainNameInvalidValueError):
            ChainName.Bitcoin.address_to_str(addr.encode())
