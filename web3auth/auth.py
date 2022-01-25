from collections import defaultdict
from typing import Any, Dict, Literal, Optional, Type, TypeVar, overload

from eip712_structs import EIP712Struct, make_domain
from eth_account.account import Account
from eth_utils.crypto import keccak

from . import exceptions, token, types, utils

_T = TypeVar("_T", bound="AuthManager")


class AuthManager:
    def __init__(
        self,
        name: str,
        version: str,
        chain_id: int,
        verifying_contract: Optional[str] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.chain_id = chain_id
        self.verifying_contract = verifying_contract and verifying_contract.lower()

        self._noonce_data: Dict[str, int] = defaultdict(lambda: 0)

    @classmethod
    def from_domain_data(cls: Type[_T], domain: types.DomainData) -> _T:
        return cls(
            domain.name, domain.version, domain.chain_id, domain.verifying_contract
        )

    def get_noonce(self, address: str) -> int:
        return self._noonce_data[address]

    def add_noonce(self, address: str) -> None:
        self._noonce_data[address] += 1

    def verify_noonce(self, noonce: int, address: str) -> None:
        current_noonce = self.get_noonce(address)
        if current_noonce != noonce:
            raise exceptions.AuthError(
                f"Invalid noonce. Found {noonce}, expected {current_noonce}"
            )

    def make_auth_message(self, address: str) -> types.AuthMessage:
        address = address.lower()
        if not utils.check_address_valid(address):
            raise exceptions.AuthError(f"Invalid address format: {address!r}")

        return types.AuthMessage(address=address, noonce=self.get_noonce(address))

    def make_domain(self, salt: Optional[str] = None) -> EIP712Struct:
        return make_domain(
            self.name,
            self.version,
            self.chain_id,
            self.verifying_contract,
            salt or utils.generate_salt(32),
        )

    @overload
    def generate_sign_data(
        self,
        address: str,
        salt: Optional[str] = None,
        *,
        type: Literal["json"],
    ) -> str:
        ...

    @overload
    def generate_sign_data(
        self,
        address: str,
        salt: Optional[str] = None,
        *,
        type: Literal["hash"],
    ) -> bytes:
        ...

    @overload
    def generate_sign_data(
        self,
        address: str,
        salt: Optional[str] = None,
        *,
        type: Literal["dict"],
    ) -> Any:
        ...

    @overload
    def generate_sign_data(
        self,
        address: str,
        salt: Optional[str] = None,
    ) -> Any:
        ...

    def generate_sign_data(self, address, salt=None, *, type="dict"):
        """
        Returns a EIP712 data to sign.

        If type == "json", will return a json string with EIP712 data.
        If type == "hash", will return bytes object, ready to be signed.
        If type == "dict", will return python dict with full EIP712 data.

        """

        address = address.lower()
        domain = self.make_domain(salt)
        auth_message = self.make_auth_message(address)

        if type == "json":
            return auth_message.to_message_json(domain)
        if type == "hash":
            return auth_message.signable_bytes(domain)
        if type == "dict":
            return auth_message.to_message(domain)

    def authenticate(
        self, address: str, noonce: int, salt: str, signature: str
    ) -> token.UserTokenManager:
        """
        Using provided data and a signature, return a token manager, that can create JWT.

        If something is wrong - an AuthError is raised.

        If everything is correct, `self.add_noonce(address)` will be called.
        """

        address = address.lower()
        auth_message = self.make_auth_message(address)
        domain = self.make_domain(salt)

        self.verify_noonce(noonce, address)

        message_hash = keccak(auth_message.signable_bytes(domain))
        try:
            recovered_address = Account._recover_hash(message_hash, signature=signature)
        except Exception as e:
            raise exceptions.AuthError(*e.args) from e

        if recovered_address.lower() != address.lower():
            raise exceptions.AuthError(
                f"Address in data {address!r} does not "
                f"match address recovered from signature {recovered_address!r}"
            )

        token_manager = token.UserTokenManager(recovered_address)

        self.add_noonce(address)

        return token_manager
