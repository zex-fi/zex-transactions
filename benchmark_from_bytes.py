"""Benchmark from_bytes() parsing performance for BuyMessage, SellMessage, CancelMessage."""

import time

from zex.transactions import BaseMessage, BuyMessage, CancelMessage, SellMessage
from zex.utils.zex_types import SignatureType

DUMMY_SIG = (
    "f1182b8a9ae8add78d385c9801c266da2daddd4fd61c7b0bc0dcf3ceb6e95721"
    "e4db89f141386f98cc9f9c9eb7c2f2eef835f7316c75a12ea6b3812eb1c2dea7"
)

N = 100_000


def make_buy_bytes() -> bytes:
    return BuyMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=1,
        price_mantissa=1,
        price_exponent=5,
        time=10000,
        user_id=1,
        signature_hex=DUMMY_SIG,
    ).to_bytes()


def make_sell_bytes() -> bytes:
    return SellMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        base_token="BTC",
        quote_token="USDT",
        amount_mantissa=1,
        amount_exponent=1,
        price_mantissa=1,
        price_exponent=5,
        time=10000,
        user_id=1,
        signature_hex=DUMMY_SIG,
    ).to_bytes()


def make_cancel_bytes() -> bytes:
    return CancelMessage(
        version=2,
        signature_type=SignatureType.SECP256K1,
        order_nonce=42,
        user_id=1,
        signature_hex=DUMMY_SIG,
    ).to_bytes()


def bench_direct(name: str, cls: type, data: bytes) -> float:
    start = time.perf_counter()
    for _ in range(N):
        cls.from_bytes(data)
    elapsed = time.perf_counter() - start
    us_per = elapsed / N * 1_000_000
    print(f"  {name}.from_bytes() direct:     {us_per:.2f} us/msg  ({elapsed:.3f}s total)")
    return us_per


def bench_dispatch(name: str, data: bytes) -> float:
    start = time.perf_counter()
    for _ in range(N):
        BaseMessage.from_bytes(data)
    elapsed = time.perf_counter() - start
    us_per = elapsed / N * 1_000_000
    print(f"  {name} via BaseMessage dispatch: {us_per:.2f} us/msg  ({elapsed:.3f}s total)")
    return us_per


def main():
    buy_data = make_buy_bytes()
    sell_data = make_sell_bytes()
    cancel_data = make_cancel_bytes()

    # Warm up the type map
    BaseMessage.from_bytes(buy_data)

    print(f"Benchmarking {N:,} iterations each\n")

    cases = [
        ("BuyMessage", BuyMessage, buy_data),
        ("SellMessage", SellMessage, sell_data),
        ("CancelMessage", CancelMessage, cancel_data),
    ]

    for name, cls, data in cases:
        print(f"{name} ({len(data)} bytes):")
        bench_direct(name, cls, data)
        bench_dispatch(name, data)
        print()

    # Batch simulation: 1000 mixed messages
    batch = [buy_data] * 400 + [sell_data] * 400 + [cancel_data] * 200
    start = time.perf_counter()
    for data in batch:
        BaseMessage.from_bytes(data)
    elapsed = time.perf_counter() - start
    print(
        f"Batch of 1000 mixed messages (dispatch): "
        f"{elapsed * 1000:.2f} ms  ({elapsed / 1000 * 1_000_000:.2f} us/msg)"
    )


if __name__ == "__main__":
    main()
