from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from eip712_structs import EIP712Struct, String, Uint


class AuthMessage(EIP712Struct):
    address = String()
    noonce = Uint(256)


@dataclass
class AuthTokenPayload:
    sub: str
    exp: datetime


@dataclass
class DomainData:
    name: str
    version: str
    chain_id: int
    verifying_contract: Optional[str] = None
