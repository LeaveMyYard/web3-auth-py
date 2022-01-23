import secrets
from datetime import timedelta

import pytest
import web3auth as w3a
from web3.auto import w3


def test_token(manager: w3a.AuthManager) -> None:
    address = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
    data = manager.generate_sign_data(address)
    # NOTE do not use this key anywhere in production
    # b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
    private_key = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
    signed_message = w3.eth.account.sign_message(data.encode(), private_key=private_key)

    token_manager = manager.authenticate_data(data, signed_message.signature)

    secret_key = secrets.token_urlsafe(16)

    token = token_manager.create_access_token(timedelta(1), secret_key=secret_key)
    payload = w3a.validate_token(token, secret_key)

    assert payload.sub == address


def test_token_invalid() -> None:
    secret_key = secrets.token_urlsafe(16)
    with pytest.raises(w3a.AuthError):
        w3a.validate_token("johfaohfiahf0owahofaihohfw", secret_key)
