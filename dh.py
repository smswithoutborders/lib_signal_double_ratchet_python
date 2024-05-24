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

from keystore import Keystore

import base64
import secrets


class DH(ABC):
    size = 32

    @abstractmethod
    def get_public_key(self):
        pass

    @abstractmethod
    def get_private_key(self):
        pass

    @abstractmethod
    def __get_shared_key__(self, public_key):
        pass

    @abstractmethod
    def agree(self, public_key, keystore_path, info=None, salt=None):
        pass

    def __agree__(secret_key, keystore_path, pk, _pk, info=b"x25591_key_exchange", salt=None):
        extended_derived_key = HKDF(algorithm=hashes.SHA256(),
                           length=DH.size,
                           salt=salt,
                           info=info,).derive(secret_key)
        keystore = Keystore(keystore_path, base64.b64encode(extended_derived_key).decode())
        return keystore.store(keypair=(pk, _pk))


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


    def agree(self, public_key, keystore_path, info=b"x25591_key_exchange", salt=None) -> bytes:
        self.ecdh.load_received_public_key_pem(public_key)
        shared_key = self.ecdh.generate_sharedsecret_bytes()
        return DH.__agree__(shared_key, keystore_path, _pk, info, salt)


class x25519(DH):
    def __init__(self):
        self.keypair = X25519PrivateKey.generate()
        """
        - generate random shared keys
        - use random shared keys to encrypt content
        - return random shared keys
        """

    def get_public_key(self):
        return self.keypair.public_key()

    def get_private_key(self):
        return self.keypair.private_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PrivateFormat.PKCS8,
                                              encryption_algorithm=serialization.NoEncryption()) 

    def agree(self, public_key, keystore_path, info=b"x25591_key_exchange", salt=None) -> bytes:
        # shared_key = self.keypair.exchange(public_key)

        secret_key = secrets.token_bytes(size) # store this
        _pk = self.keypair.private_bytes(encoding=serialization.Encoding.PEM, 
                                   format=serialization.PrivateFormat.PKCS8, 
                                   encryption_algorithm=serialization.NoEncryption()) 
        return secret_key, DH.__agree__(secret_key, keystore_path, _pk, info, salt)


if __name__ == "__main__":
    client1 = ecdh()
    client1_public_key = client1.get_public_key()

    client2 = ecdh()
    client2_public_key = client2.get_public_key()

    pnt_keystore1 = client2.agree(client1_public_key, "db_keys/ecdh1.db")
    pnt_keystore2 = client1.agree(client2_public_key, "db_keys/ecdh2.db")
    assert(client1_secrets == client2_secrets)


    client1 = x25519()
    client1_public_key = client1.get_public_key()

    client2 = x25519()
    client2_public_key = client2.get_public_key()

    pnt_keystore1 = client2.agree(client1_public_key, "db_keys/x25519.1.db")
    pnt_keystore2 = client1.agree(client2_public_key, "db_keys/x25519.2.db")
    assert(client1_secrets == client2_secrets)
