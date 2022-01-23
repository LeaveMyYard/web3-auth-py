import dataclasses
from datetime import datetime, timedelta
from typing import List

from jose import jwt

from . import exceptions, types


class UserTokenManager:
    def __init__(self, user: str) -> None:
        self.user = user

    def create_access_token(
        self, expires_delta: timedelta, secret_key: str, *, algorithm: str = "HS256"
    ) -> str:
        expire = datetime.utcnow() + expires_delta

        to_encode = dataclasses.asdict(types.AuthTokenPayload(self.user, exp=expire))
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        return encoded_jwt

    @staticmethod
    def validate_token(
        token: str, secret_key: str, *, algorithms: List[str] = ["HS256"]
    ) -> types.AuthTokenPayload:
        try:
            payload = jwt.decode(token, secret_key, algorithms=algorithms)
            token_data = types.AuthTokenPayload(**payload)
        except (jwt.JWTError, TypeError) as error:
            raise exceptions.AuthError("Could not validate credentials") from error
        return token_data
