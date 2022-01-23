import random
import re
import string

SYMBOLS = string.hexdigits


def generate_salt(size: int) -> str:
    return "0x" + "".join(random.choices(SYMBOLS, k=size * 2)).lower()


def check_address_valid(address: str) -> bool:
    return bool(re.match(r"^(0x[a-fA-F0-9]{40})$", address))
