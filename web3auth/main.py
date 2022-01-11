from . import types, utils, exceptions
from eth_account.account import Account

EIP712_TYPES: types.TypeDeclaration = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "Auth": [
        {"name": "address", "type": "string"},
        {"name": "salt", "type": "string"},
    ],
}

EIP712_PRIMARY_TYPE = "Auth"


class AuthManager:
    def __init__(self, domain: types.DomainData) -> None:
        self.domain = domain

    def combine_message_to_EIP712(self, message: types.MessageData) -> types.EIP712Data:
        return types.EIP712Data(EIP712_TYPES, EIP712_PRIMARY_TYPE, self.domain, message)

    def authenticate(self, message: types.MessageData, signature: str) -> str:
        data = self.combine_message_to_EIP712(message)
        return self.authenticate_data(data, signature)

    def generate_sign_data(self, address: str) -> types.EIP712Data:
        if not utils.check_address_valid(address):
            raise exceptions.AuthError(f"Invalid address format: {address!r}")

        message = types.MessageData(address, utils.generate_salt(16))
        return self.combine_message_to_EIP712(message)

    @staticmethod
    def authenticate_data(data: types.EIP712Data, signature: str) -> str:
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

        return recovered_address
