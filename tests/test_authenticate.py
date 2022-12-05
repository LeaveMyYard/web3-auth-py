import pytest
import web3auth as w3a
from typing import Optional
from eth_utils.curried import keccak
from web3.auto import w3
import random

# NOTE do not use this key anywhere in production
# b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
PRIVATE_KEY = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
PUBLIC_KEY = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"

random.seed(0)


@pytest.mark.parametrize(
    "salt", [None, w3a.utils.generate_salt(32), w3a.utils.generate_salt(32)]
)
def test_valid_signature(manager: w3a.AuthManager, salt: Optional[str]) -> None:
    message_hash = keccak(manager.generate_sign_data(PUBLIC_KEY, salt, type="hash"))
    signature = w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature
    noonce = manager.get_noonce(PUBLIC_KEY)

    assert PUBLIC_KEY == manager.authenticate(PUBLIC_KEY, noonce, salt, signature).user


@pytest.mark.parametrize(
    "salt", [None, w3a.utils.generate_salt(32), w3a.utils.generate_salt(32)]
)
def test_valid_signature_other_address(
    manager: w3a.AuthManager, salt: Optional[str]
) -> None:
    public_key = PUBLIC_KEY.replace("1", "2")
    message_hash = keccak(manager.generate_sign_data(public_key, salt, type="hash"))
    signature = w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature
    noonce = manager.get_noonce(PUBLIC_KEY)

    with pytest.raises(w3a.AuthError):
        manager.authenticate(PUBLIC_KEY, noonce, salt, signature)


@pytest.mark.parametrize(
    "salt", [None, w3a.utils.generate_salt(32), w3a.utils.generate_salt(32)]
)
def test_invalid_signature(manager: w3a.AuthManager, salt: Optional[str]) -> None:
    message_hash = keccak(manager.generate_sign_data(PUBLIC_KEY, salt, type="hash"))
    signature = (
        w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature[:-4] + b"1234"
    )
    noonce = manager.get_noonce(PUBLIC_KEY)

    with pytest.raises(w3a.AuthError):
        manager.authenticate(PUBLIC_KEY, noonce, salt, signature)


@pytest.mark.parametrize(
    "salt", [None, w3a.utils.generate_salt(32), w3a.utils.generate_salt(32)]
)
def test_invalid_noonce(manager: w3a.AuthManager, salt: Optional[str]) -> None:
    message_hash = keccak(manager.generate_sign_data(PUBLIC_KEY, salt, type="hash"))
    signature = w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature
    noonce = manager.get_noonce(PUBLIC_KEY)

    with pytest.raises(w3a.AuthError):
        manager.authenticate(PUBLIC_KEY, noonce + 1, salt, signature)


@pytest.mark.parametrize(
    "salt", [None, w3a.utils.generate_salt(32), w3a.utils.generate_salt(32)]
)
def test_invalid_twice(manager: w3a.AuthManager, salt: Optional[str]) -> None:
    message_hash = keccak(manager.generate_sign_data(PUBLIC_KEY, salt, type="hash"))
    signature = w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature
    noonce = manager.get_noonce(PUBLIC_KEY)

    manager.authenticate(PUBLIC_KEY, noonce, salt, signature)

    with pytest.raises(w3a.AuthError):
        manager.authenticate(PUBLIC_KEY, noonce, salt, signature)
