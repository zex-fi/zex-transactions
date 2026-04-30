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
* **Ubuntu:** `sudo apt-get install python3-dev`
* **Fedora:** `sudo dnf install python3-devel`
