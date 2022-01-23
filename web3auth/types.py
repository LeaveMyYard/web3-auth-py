from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, List, Optional

from eth_account.messages import SignableMessage, encode_structured_data

from . import utils


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
    verifyingContract: Optional[str]


@dataclass
class DomainDataWithSalt(DomainData):
    salt: str


@dataclass
class AuthMessage:
    address: str


@dataclass
class EIP712Data:
    types: Dict[str, TypeDeclaration]
    primaryType: str
    domain: DomainDataWithSalt
    message: AuthMessage

    def encode(self) -> SignableMessage:
        return encode_structured_data(asdict(self))


@dataclass
class AuthTokenPayload:
    sub: str
    exp: datetime
