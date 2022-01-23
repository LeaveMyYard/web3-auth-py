from dataclasses import asdict
from typing import Dict, Optional

from eth_account.account import Account

from . import exceptions, token, types, utils

EIP712Domain = [
    types.FieldDeclaration(name="name", type="string"),
    types.FieldDeclaration(name="version", type="string"),
    types.FieldDeclaration(name="chainId", type="uint256"),
    types.FieldDeclaration(name="verifyingContract", type="address"),
    types.FieldDeclaration(name="salt", type="string"),
]

EIP712_TYPES: Dict[str, types.TypeDeclaration] = {
    "EIP712Domain": EIP712Domain,
    "Auth": [
        types.FieldDeclaration(name="address", type="string"),
    ],
}

EIP712_PRIMARY_TYPE = "Auth"


class AuthManager:
    def __init__(self, domain: types.DomainData) -> None:
        self.domain = domain

    def combine_message_to_EIP712(self, message: types.AuthMessage, salt: Optional[str] = None) -> types.EIP712Data:
        domain = types.DomainDataWithSalt(
            **asdict(self.domain), salt=salt or utils.generate_salt(32)
        )
        return types.EIP712Data(EIP712_TYPES, EIP712_PRIMARY_TYPE, domain, message)

    def generate_sign_data(self, address: str) -> types.EIP712Data:
        if not utils.check_address_valid(address):
            raise exceptions.AuthError(f"Invalid address format: {address!r}")

        auth_message = types.AuthMessage(address)
        return self.combine_message_to_EIP712(auth_message)

    def authenticate(
        self, message: types.AuthMessage, signature: str, salt: str
    ) -> token.UserTokenManager:
        data = self.combine_message_to_EIP712(message, salt)
        return self.authenticate_data(data, signature)

    @staticmethod
    def authenticate_data(
        data: types.EIP712Data, signature: str
    ) -> token.UserTokenManager:
        try:
            recovered_address = Account.recover_message(
                data.encode(), signature=signature
            )
        except Exception as e:
            raise exceptions.AuthError(*e.args) from e

        if data.message.address.lower() != recovered_address.lower():
            raise exceptions.AuthError(
                f"Address in data {data.message.address!r} does not "
                f"match address recovered from signature {recovered_address}"
            )

        return token.UserTokenManager(recovered_address)
