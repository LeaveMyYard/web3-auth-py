import string
import random


def generate_address() -> str:
    return "0x" + "".join(random.choices(string.hexdigits, k=40))
