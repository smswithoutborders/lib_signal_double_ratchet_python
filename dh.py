#!/usr/bin/env python3
from abc import ABC, abstractmethod

# ECDH
from ecdsa import ECDH, NIST256p
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# X25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import binascii
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class DH(ABC):
    size = 64

    @abstractmethod
    def get_public_key(self):
        pass

    @abstractmethod
    def get_private_key(self):
        pass

    @abstractmethod
    def get_shared_key(self, public_key):
        pass

    @abstractmethod
    def get_derived_key(self, public_key, info=None, salt=None):
        pass

    def __get_derived_key__(self, public_key, info=None, salt=None):
        shared_key = self.get_shared_key(public_key)
        extended_derived_key = HKDF(algorithm=hashes.SHA256(),
                           length=DH.size,
                           salt=salt,
                           info=info,).derive(shared_key)
        keystore = Keystore()
        keystore.store_key(keypair=(extended_derived_key[:32], extended_derived_key[32:]))

class ecdh(DH):
    def __init__(self):
        """
        """
        self.ecdh = ECDH(curve=NIST256p)
        self.ecdh.generate_private_key()

    def get_public_key(self, pem=True):
        public_key = self.ecdh.get_public_key()
        return public_key.to_pem() if pem else public_key

    def get_private_key(self):
        pass

    def get_shared_key(self, public_key):
        self.ecdh.load_received_public_key_pem(public_key)
        b_secrets = self.ecdh.generate_sharedsecret_bytes()
        return b_secrets

    def get_derived_key(self, public_key, info=b"ecdh_key_exchange", salt=None):
        DH.__get_derived_key__(public_key, info, salt)


class x25519(DH):
    def __init__(self):
        self.keypair = X25519PrivateKey.generate()

    def get_public_key(self):
        return self.keypair.public_key()

    def get_private_key(self):
        return self.keypair.private_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PrivateFormat.PKCS8,
                                              encryption_algorithm=serialization.NoEncryption()) 

    def get_shared_key(self, public_key):
        return self.keypair.exchange(public_key)

    def get_derived_key(self, public_key, info=b"x25591_key_exchange", salt=None) -> bytes:
        DH.__get_derived_key__(public_key, info, salt)


if __name__ == "__main__":
    client1 = ecdh()
    client1_public_key = client1.get_public_key()

    client2 = ecdh()
    client2_public_key = client2.get_public_key()

    client2_secrets = client2.get_derived_key(client1_public_key)
    client1_secrets = client1.get_derived_key(client2_public_key)

    assert(client1_secrets == client2_secrets)


    client1 = x25519()
    client1_public_key = client1.get_public_key()

    client2 = x25519()
    client2_public_key = client2.get_public_key()

    client2_secrets = client2.get_derived_key(client1_public_key)
    client1_secrets = client1.get_derived_key(client2_public_key)

    assert(client1_secrets == client2_secrets)
