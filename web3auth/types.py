from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from eth_account.messages import encode_structured_data, SignableMessage
from datetime import datetime


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
    salt: str


@dataclass
class EIP712Data:
    types: Dict[str, TypeDeclaration]
    primaryType: str
    domain: DomainData
    message: str

    def encode(self) -> SignableMessage:
        return encode_structured_data(asdict(self))


@dataclass
class AuthTokenPayload:
    sub: str
    exp: datetime
