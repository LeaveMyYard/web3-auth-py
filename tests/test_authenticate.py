import pytest
import web3auth
from web3.auto import w3


def test_valid_signature(manager: web3auth.AuthManager) -> None:
    address = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
    data = manager.generate_sign_data(address)
    # NOTE do not use this key anywhere in production
    # b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
    private_key = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
    signed_message = w3.eth.account.sign_message(data.encode(), private_key=private_key)

    assert address == manager.authenticate_data(data, signed_message.signature).user
    assert address == manager.authenticate(data.message, signed_message.signature, data.domain.salt).user

    assert (
        address == manager.authenticate_data(data, signed_message.signature.hex()).user
    )
    assert (
        address
        == manager.authenticate(data.message, signed_message.signature.hex(), data.domain.salt).user
    )


def test_valid_signature_other_address(manager: web3auth.AuthManager) -> None:
    address = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB13E"
    data = manager.generate_sign_data(address)
    # NOTE do not use this key anywhere in production
    # b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
    private_key = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
    signed_message = w3.eth.account.sign_message(data.encode(), private_key=private_key)

    with pytest.raises(web3auth.AuthError):
        manager.authenticate_data(data, signed_message.signature)

    with pytest.raises(web3auth.AuthError):
        manager.authenticate(data.message, signed_message.signature, data.domain.salt)


def test_invalid_signature(manager: web3auth.AuthManager) -> None:
    address = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
    data = manager.generate_sign_data(address)
    # NOTE do not use this key anywhere in production
    # b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364
    private_key = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
    signed_message = w3.eth.account.sign_message(data.encode(), private_key=private_key)

    with pytest.raises(web3auth.AuthError):
        manager.authenticate_data(data, signed_message.signature.hex()[:-4] + "1234")

    with pytest.raises(web3auth.AuthError):
        manager.authenticate(data.message, signed_message.signature.hex()[:-4] + "1234", data.domain.salt)
