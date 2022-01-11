import pytest
import web3auth


@pytest.fixture
def domain() -> web3auth.DomainData:
    return web3auth.DomainData(
        "Test", "1.0", 5777, "0xd4039eB67CBB36429Ad9DD30187B94f6A5122215"
    )


@pytest.fixture
def manager(domain: web3auth.DomainData) -> web3auth.AuthManager:
    return web3auth.AuthManager(domain)
