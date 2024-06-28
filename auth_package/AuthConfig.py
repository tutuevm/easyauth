from datetime import timedelta
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class AuthConfig:
    def __init__(self, type, private_key: str, public_key:str,  lifetime_seconds: int):
        self.type = type
        self.public_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
        self.private_key = private_key
        self.lifetime_seconds = timedelta(seconds= lifetime_seconds)