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

### Troubleshooting

**Error: `fatal error: Python.h: No such file or directory`**
You are missing the Python development headers required to build C extensions.

- **Ubuntu:** `sudo apt-get install python3-dev`
- **Fedora:** `sudo dnf install python3-devel`

---

## Getting Started

`zex-transactions` handles encoding, signing, and decoding of ZEX exchange transactions as compact binary messages. Each transaction type maps to a message class with `to_bytes()` / `from_bytes()` for serialization and `sign()` / `verify_signature()` for cryptographic operations.

### Core Concepts

**Signature types** — every message requires one:
- `SignatureType.SECP256K1` — Ethereum/Bitcoin-style keys (33-byte compressed public key)
- `SignatureType.ED25519` — Solana-style keys (32-byte public key)

**Amount encoding** — amounts use scientific notation: `amount = mantissa × 10^exponent`. Use `to_scientific()` to convert a `Decimal`:

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
from zex.transactions import BuyMessage, SellMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import SignatureType
import time

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
from zex.transactions import CancelMessage
from zex.utils.zex_types import SignatureType

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
from zex.transactions import WithdrawMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import ChainName, SignatureType
import time

chain = ChainName.Ethereum
destination = "0xAbCd..."  # checksummed EVM address

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
from zex.transactions import TransferMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import SignatureType
import time

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
# Encode
raw: bytes = msg.to_bytes()

# Decode — automatically detects transaction type
from zex.transactions import BuyMessage
decoded = BuyMessage.from_bytes(raw)

# Or dispatch without knowing the type in advance
from zex.transactions import BaseMessage
decoded = BaseMessage.from_bytes(raw)
```

---

### Verify a Signature

```python
public_key_bytes = private_key.public_key.format(compressed=True)
is_valid = msg.verify_signature(public_key_bytes)
```

---

### Schema Helpers (Pydantic)

Each transaction type ships a `*Schema` model for deserializing JSON payloads (e.g., from an API):

```python
from zex.transactions import BuySchema
from zex.utils.zex_types import SignatureType

schema = BuySchema(
    sig_type=SignatureType.SECP256K1,
    base_token="BTC",
    quote_token="USDT",
    amount="1.5",
    price="65000",
    t=1700000000,
    nonce=1,
    user_id=42,
    signature="deadbeef...",
)
buy_msg = schema.to_message()
```

Available schemas: `RegisterSchema`, `BuySchema`, `SellSchema`, `WithdrawSchema`, `TransferSchema`, `CancelSchema`

---

### Error Handling

```python
from zex.transactions import (
    HeaderFormatError,
    MessageFormatError,
    MessageValidationError,
    UnexpectedCommandError,
)

try:
    msg = BuyMessage.from_bytes(raw_bytes)
except HeaderFormatError:
    ...  # bad header / too short
except UnexpectedCommandError:
    ...  # wrong transaction type byte
except MessageFormatError:
    ...  # body is malformed
except MessageValidationError:
    ...  # values out of range (e.g. exponent too small)
```
