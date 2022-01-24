import secrets
from datetime import timedelta

import pytest
import web3auth as w3a
from eth_utils.curried import keccak
from web3.auto import w3

# NOTE do not use this key anywhere in production
# b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
PRIVATE_KEY = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
PUBLIC_KEY = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"


def test_token(manager: w3a.AuthManager) -> None:
    salt = w3a.utils.generate_salt(32)
    auth_message = manager.make_auth_message(PUBLIC_KEY)
    message_hash = keccak(manager.generate_sign_data(PUBLIC_KEY, salt, type="hash"))
    signature = w3.eth.account._sign_hash(message_hash, PRIVATE_KEY).signature

    token_manager = manager.authenticate(
        PUBLIC_KEY, auth_message.noonce, salt, signature
    )

    secret_key = secrets.token_urlsafe(16)

    token = token_manager.create_access_token(timedelta(1), secret_key=secret_key)
    payload = w3a.validate_token(token, secret_key)

    assert payload.sub == PUBLIC_KEY


def test_token_invalid() -> None:
    secret_key = secrets.token_urlsafe(16)
    with pytest.raises(w3a.AuthError):
        w3a.validate_token("johfaohfiahf0owahofaihohfw", secret_key)
