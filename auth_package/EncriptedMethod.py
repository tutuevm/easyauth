from abc import ABC, abstractmethod
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class EncriptedMethod(ABC):
    @abstractmethod
    def genrate_token(self):
        pass

    @abstractmethod
    def verify_token(self, token):
        pass


class RS256Strategy(EncriptedMethod):
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_token(self, payload):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return jwt.encode(payload, private_pem, algorithm='RS256')

    def verify_token(self, token):
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jwt.decode(token, public_pem, algorithms=['RS256'])

class HS256Strategy(EncriptedMethod):
    def __init__(self, secret_key):
        self.secret_key = secret_key
    def generate_token(self, payload):
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    def verify_token(self, token):
        return jwt.decode(token, self.secret_key, algorithms=['HS256'])