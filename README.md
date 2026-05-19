## Installation

This package builds C extensions against a few system libraries. Install them before installing the Python package.

### 1. System Prerequisites

#### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    pkg-config \
    libsecp256k1-dev \
    build-essential \
    libgmp-dev \
    python3-dev
```

> `libgmp-dev` is required because the `fastecdsa` dependency compiles a C extension that links against GMP for its bignum arithmetic.

### 2. Install the Package

You can install `zex-transactions` directly from GitHub using `pip`. This will automatically handle the Python dependencies (including `zexfrost` and `frost-lib`).

**Option A: Install the latest stable release (Recommended)**

```bash
pip install "zex-transactions @ git+https://github.com/zex-fi/zex-transactions.git@v0.1.0"
```

**Option B: Install the latest development version**

```bash
pip install "zex-transactions @ git+https://github.com/zex-fi/zex-transactions.git@main"
```

#### Using UV

```bash
uv add "zex-transactions @ git+https://github.com/zex-fi/zex-transactions.git@main"
```

### Verification

To verify the installation was successful and the shared libraries are correctly linked:

```bash
python3 -c "import zex; print('Successfully imported zex-transactions!')"
```

### Bitcoin Network Configuration

Before validating any BTC addresses, call `setup_btc_network` once at startup (defaults to testnet4):

```python
from zex.utils.zex_types import setup_btc_network

setup_btc_network("testnet4")  # or "mainnet", "testnet", "signet", "regtest"
```

---

## Getting Started

`zex-transactions` handles encoding, signing, and decoding of ZEX exchange transactions as compact binary messages. Each transaction type maps to a message class with `to_bytes()` / `from_bytes()` for serialization and `sign()` / `verify_signature()` for cryptographic operations.

### Core Concepts

**Signature types** — every message requires one:

- `SignatureType.SECP256K1` — Ethereum/Bitcoin-style keys (33-byte compressed public key)
- `SignatureType.ED25519` — Solana-style keys (32-byte public key)

**Amount encoding** — amounts use scientific notation: `amount = mantissa × 10^exponent`. Use `to_scientific()` to convert a `Decimal`:

This package relies on the decimal module. If you are working with high-precision values, ensure the precision is configured (e.g., via decimal.getcontext().prec or decimal.setcontext()) to avoid truncation during calculations.

```python
from decimal import Decimal
from zex.utils.numbers import to_scientific

mantissa, exponent = to_scientific(Decimal("0.005"))  # → (5, -3)
```

**Supported chains** — `ChainName.Bitcoin`, `ChainName.Ethereum`, `ChainName.Solana`, `ChainName.Tron`, `ChainName.Sepolia`

---

### Register a User

```python
from coincurve import PrivateKey
from zex.transactions import RegisterMessage
from zex.utils.zex_types import SignatureType

private_key = PrivateKey()
public_key_bytes = private_key.public_key.format(compressed=True)  # 33 bytes

msg = RegisterMessage(
    version=1,
    signature_type=SignatureType.SECP256K1,
    referral_code="REF123",
    public_key=public_key_bytes,
    signature_hex=None,
)
msg.sign(private_key)

transaction_bytes = msg.to_bytes()
transaction_hex = msg.signature_hex
```

For ED25519 (Solana):

```python
from solders.keypair import Keypair
from zex.transactions import RegisterMessage
from zex.utils.zex_types import SignatureType

keypair = Keypair()

msg = RegisterMessage(
    version=1,
    signature_type=SignatureType.ED25519,
    referral_code="",
    public_key=bytes(keypair.pubkey()),  # 32 bytes
    signature_hex=None,
)

msg.sign(keypair)
```

---

### Place a Buy / Sell Order

```python
from decimal import Decimal
from coincurve import PrivateKey
from zex.transactions import BuyMessage, SellMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import SignatureType
import time

private_key = PrivateKey()

amount_mantissa, amount_exponent = to_scientific(Decimal("1.5"))    # 1.5 BTC
price_mantissa, price_exponent   = to_scientific(Decimal("65000"))  # at $65,000

msg = BuyMessage(
    version=1,
    signature_type=SignatureType.SECP256K1,
    base_token="BTC",
    quote_token="USDT",
    amount_mantissa=amount_mantissa,
    amount_exponent=amount_exponent,
    price_mantissa=price_mantissa,
    price_exponent=price_exponent,
    time=int(time.time()),
    nonce=1,
    user_id=42,
    signature_hex=None,
)
msg.sign(private_key)
```

Replace `BuyMessage` with `SellMessage` for a sell order — the interface is identical.

---

### Cancel an Order

```python
from coincurve import PrivateKey
from zex.transactions import CancelMessage
from zex.utils.zex_types import SignatureType

private_key = PrivateKey()

msg = CancelMessage(
    version=1,
    signature_type=SignatureType.SECP256K1,
    order_nonce=1,
    user_id=42,
    signature_hex=None,
)
msg.sign(private_key)
```

---

### Withdraw

```python
from decimal import Decimal
from coincurve import PrivateKey
from zex.transactions import WithdrawMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import ChainName, SignatureType
import time

private_key = PrivateKey()
chain = ChainName.Ethereum
destination = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"  # checksummed EVM address

mantissa, exponent = to_scientific(Decimal("0.5"))

msg = WithdrawMessage(
    version=1,
    signature_type=SignatureType.SECP256K1,
    token_name="USDT",
    chain_name=chain,
    amount_mantissa=mantissa,
    amount_exponent=exponent,
    destination_wallet=chain.address_to_bytes(destination),
    time=int(time.time()),
    nonce=1,
    user_id=42,
    signature_hex=None,
)
msg.sign(private_key)
```

---

### Transfer (Internal)

```python
from decimal import Decimal
from coincurve import PrivateKey
from zex.transactions import TransferMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import SignatureType
import time

private_key = PrivateKey()
mantissa, exponent = to_scientific(Decimal("10"))

msg = TransferMessage(
    version=1,
    signature_type=SignatureType.SECP256K1,
    token_name="USDT",
    amount_mantissa=mantissa,
    amount_exponent=exponent,
    time=int(time.time()),
    nonce=1,
    user_id=42,
    recipient_id=99,
    signature_hex=None,
)
msg.sign(private_key)
```

---

### Serialize and Deserialize

Every message class supports round-trip binary encoding:

```python
from zex.transactions import BaseMessage, BuyMessage

# Encode
raw: bytes = msg.to_bytes()

# Decode as a specific known type
decoded = BuyMessage.from_bytes(raw)

# Or auto-dispatch without knowing the type in advance — BaseMessage inspects
# the transaction type byte and delegates to the correct subclass
decoded = BaseMessage.from_bytes(raw)
```

---

### Verify a Signature

**SECP256K1:**

```python
from coincurve import PrivateKey

private_key = PrivateKey()
public_key_bytes = private_key.public_key.format(compressed=True)  # 33 bytes
is_valid = msg.verify_signature(public_key_bytes)
```

**ED25519 (Solana):**

```python
from solders.keypair import Keypair

keypair = Keypair()
public_key_bytes = bytes(keypair.pubkey())  # 32 bytes
is_valid = msg.verify_signature(public_key_bytes)
```

---

Available schemas: `RegisterSchema`, `BuySchema`, `SellSchema`, `WithdrawSchema`, `TransferSchema`, `CancelSchema`

---

### Available Messages

| Message           | Purpose                                                          |
| ----------------- | ---------------------------------------------------------------- |
| `RegisterMessage` | Register a new user with a public key and optional referral code |
| `BuyMessage`      | Place a buy order on a base/quote pair                           |
| `SellMessage`     | Place a sell order on a base/quote pair                          |
| `CancelMessage`   | Cancel a previously placed order by nonce                        |
| `WithdrawMessage` | Withdraw funds to an external on-chain address                   |
| `TransferMessage` | Internal transfer between ZEX users                              |
| `OrderMessage`    | Shared base for `BuyMessage` / `SellMessage`                     |
