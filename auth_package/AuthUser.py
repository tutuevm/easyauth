from datetime import datetime

import jwt

from auth_package.AuthConfig import AuthConfig


class JWTAuth:
    def __init__(self, type, username, config : AuthConfig):
        self.type = type
        self.username = username
        self.config  = config

    def __str__(self):
        return f"{self.type} {self.username}"

    def generate_token(self):
        expire = datetime.utcnow() + self.config.lifetime_seconds
        private_key = self.config.private_key
        encode = jwt.encode(
            {
                "sub": self.email,
                "exp": expire,
            },
            private_key,
            algorithm="HS256"
        )
        print(encode)
        return encode

    def verify_token(self, encoded):
        decoded = jwt.decode(encoded, self.cofig.public_key, algorithms=["RS256"])
        return decoded