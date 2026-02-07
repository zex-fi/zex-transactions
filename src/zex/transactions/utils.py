from decimal import Decimal


def int_to_bytes(value: int) -> bytes:
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, byteorder="big", signed=False)


def to_scientific(n: Decimal) -> tuple[int, int]:
    "Convert a Decimal value to a mantissa and an exponent (base 10)"

    sign, digits, exponent = n.normalize().as_tuple()
    if not isinstance(exponent, int):
        raise Exception(f"Cannot convert value to scientific form: {n}")

    mantissa = 0
    for i, d in enumerate(reversed(digits)):
        mantissa += d * 10**i
    mantissa *= -1 if sign != 0 else 1

    if exponent < -128 or exponent > 127:
        raise Exception(f"Cannot convert value to scientific form: {n}")

    return mantissa, exponent


def format_decimal(d: Decimal):
    """format the given decimal number, making sure scientific notation
    is _not_ used and that there's always a traling .0 if there's no
    fractional part.
    """
    s = format(d, "f")
    if "." not in s:
        s += ".0"
    return s
