## Installation

This package relies on high-performance cryptographic libraries (specifically `mcl` for pairing-based cryptography). You must install these system dependencies before installing the Python package.

### 1. System Prerequisites

#### Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    pkg-config \
    libsecp256k1-dev \
    build-essential \
    libgmp-dev \
    cmake \
    clang \
    python3-dev
```

### 2. Installing the MCL Library

This project relies on the [MCL library](https://github.com/herumi/mcl) (v2.14) for BLS signatures. You must build and install it manually:

```bash
# Clone and build mcl
git clone --depth 1 --branch v2.14 [https://github.com/herumi/mcl.git](https://github.com/herumi/mcl.git)
cd mcl
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ ..
make -j$(nproc)
sudo make install
sudo ldconfig  # Refresh shared library cache (Linux only)
cd ../.. && rm -rf mcl
```

### 3. Install the Package

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

---

### Troubleshooting

**Error: `libmcl.so: cannot open shared object file`**
If you see this error, your system cannot find the installed MCL library.
* **Linux:** Run `sudo ldconfig` to update your library cache.
* **Custom Path:** If you installed MCL to a custom location, add it to your path:
  ```bash
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
  ```

**Error: `fatal error: Python.h: No such file or directory`**
You are missing the Python development headers required to build C extensions.
* **Ubuntu:** `sudo apt-get install python3-dev`
* **Fedora:** `sudo dnf install python3-devel`
