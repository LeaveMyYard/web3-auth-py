import random
import string
import re

SYMBOLS = string.hexdigits


def generate_salt(size: int) -> str:
    return "".join(random.choices(SYMBOLS, k=size))


def check_address_valid(address: str) -> bool:
    return bool(re.match(r"^(0x[a-fA-F0-9]{40})$", address))
