from dataclasses import dataclass, asdict
from typing import Dict, List
from eth_account.messages import encode_structured_data, SignableMessage


@dataclass
class FieldDeclaration:
    name: str
    type: str


TypeDeclaration = List[FieldDeclaration]


@dataclass
class DomainData:
    name: str
    version: str
    chainId: int
    verifyingContract: str


@dataclass
class MessageData:
    address: str
    salt: str


@dataclass
class EIP712Data:
    types: Dict[str, TypeDeclaration]
    primaryType: str
    domain: DomainData
    message: MessageData

    def encode(self) -> SignableMessage:
        return encode_structured_data(asdict(self))
