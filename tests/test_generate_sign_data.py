import pytest
import random
import web3auth

import utils

random.seed(0)


@pytest.mark.parametrize(
    "address",
    [utils.generate_address() for _ in range(10)],
)
def test_random_address(address: str, manager: web3auth.AuthManager):
    data = manager.generate_sign_data(address)
    assert data["message"]["address"] == address

    assert isinstance(manager.generate_sign_data(address, type="json"), str)
    assert isinstance(manager.generate_sign_data(address, type="hash"), bytes)


@pytest.mark.parametrize(
    "address",
    [
        utils.generate_address()[1:],
        utils.generate_address()[2:],
        utils.generate_address() + "183",
        utils.generate_address()[2:-2],
        utils.generate_address()[:-2] + "ik",
    ],
)
def test_invalid_address(address: str, manager: web3auth.AuthManager):
    with pytest.raises(web3auth.AuthError):
        manager.generate_sign_data(address)
