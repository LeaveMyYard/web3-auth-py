from . import types, utils, exceptions, token
from eth_account.account import Account
from copy import deepcopy

EIP712_TYPES: types.TypeDeclaration = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
        {"name": "salt", "type": "address"},
    ]
}

EIP712_PRIMARY_TYPE = "string"


class AuthManager:
    def __init__(self, domain: types.DomainData) -> None:
        self.domain = domain

    def combine_message_to_EIP712(self, message: str) -> types.EIP712Data:
        domain = deepcopy(self.domain)
        domain.salt = utils.generate_salt(16)
        return types.EIP712Data(EIP712_TYPES, EIP712_PRIMARY_TYPE, domain, message)

    def generate_sign_data(self, address: str) -> types.EIP712Data:
        if not utils.check_address_valid(address):
            raise exceptions.AuthError(f"Invalid address format: {address!r}")

        return self.combine_message_to_EIP712(address)

    def authenticate(
        self, message: types.MessageData, signature: str
    ) -> token.UserTokenManager:
        data = self.combine_message_to_EIP712(message)
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

        if data.message.address != recovered_address:
            raise exceptions.AuthError(
                f"Address in data {data.message.address!r} does not "
                f"match address recovered from signature {recovered_address}"
            )

        return token.UserTokenManager(recovered_address)
