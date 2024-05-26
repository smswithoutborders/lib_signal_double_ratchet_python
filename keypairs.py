#!/usr/bin/env python3
from abc import ABC, abstractmethod

# ECDH
from ecdsa import ECDH, NIST256p
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# X25519
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import binascii
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from keystore import Keystore

import base64
import secrets
import uuid

class Keypairs(ABC):
    size = 32

    @abstractmethod
    def init(self):
        pass

    @abstractmethod
    def agree(self, public_key, info, salt):
        pass

    @abstractmethod
    def get_public_key(self):
        pass

    def store(pk, _pk, keystore_path, pnt_keystore, info=b"x25591_key_exchange", salt=None):
        secret_key = secrets.token_bytes(Keypairs.size) # store this
        extended_derived_key = HKDF(algorithm=hashes.SHA256(),
                           length=Keypairs.size,
                           salt=salt,
                           info=info,).derive(secret_key)
        secret_key = base64.b64encode(extended_derived_key).decode()

        keystore = Keystore(keystore_path, secret_key)
        keystore.store(keypair=(pk, _pk), pnt=pnt_keystore)

        return secret_key

    def fetch(pnt_keystore, secret_key, keystore_path=None):
        keystore = Keystore(keystore_path, secret_key)
        return keystore.fetch(pnt_keystore)

    def __agree__(secret_key, info=b"x25591_key_exchange", salt=None):
        return HKDF(algorithm=hashes.SHA256(), 
                    length=Keypairs.size, salt=salt, info=info,).derive(secret_key) 


class ecdh(Keypairs):
    def __init__(self, pnt_keystore=None, keystore_path=None, secret_key=None):
        self.pnt_keystore = pnt_keystore
        self.keystore_path = keystore_path

    def init(self):
        ecdh = ECDH(curve=NIST256p)
        pk = ecdh.generate_private_key()
        self.pnt_keystore = uuid.uuid4().hex

        if not self.keystore_path:
            self.keystore_path = f"db_keys/{self.pnt_keystore}.db"

        self.secret_key = Keypairs.store(pk.to_string(), 
                                         ecdh.private_key.to_string(), 
                                         self.keystore_path, 
                                         self.pnt_keystore)
        return pk.to_string()

    def get_public_key(self):
        ppk = Keypairs.fetch(self.pnt_keystore, self.secret_key, self.keystore_path )
        return ppk[0]

    def agree(self, public_key, info=b"x25591_key_exchange", salt=None) -> bytes:
        if not self.keystore_path:
            self.keystore_path = f"db_keys/{pnt_keystore}.db"
        ppk = Keypairs.fetch(self.pnt_keystore, self.secret_key, self.keystore_path )
        if ppk:
            ecdh = ECDH(curve=NIST256p)
            ecdh.load_private_key_bytes(ppk[1])
            # ecdh.load_received_public_key_pem(public_key)
            ecdh.load_received_public_key_bytes(public_key)
            shared_key = ecdh.generate_sharedsecret_bytes()
            return Keypairs.__agree__(shared_key, info, salt)


class x25519(Keypairs):
    def __init__(self, keystore_path=None):
        self.keystore_path = keystore_path

    def init(self):
        x = X25519PrivateKey.generate()
        pk = x.public_key().public_bytes_raw()

        """
        _pk = x.private_bytes(encoding=serialization.Encoding.PEM, 
                              format=serialization.PrivateFormat.PKCS8, 
                              encryption_algorithm=serialization.NoEncryption()) 
        """
        _pk = x.private_bytes_raw()
        self.pnt_keystore = uuid.uuid4().hex

        if not self.keystore_path:
            self.keystore_path = f"db_keys/{self.pnt_keystore}.db"

        self.secret_key = Keypairs.store(pk, _pk, self.keystore_path, self.pnt_keystore)
        return pk

    def get_public_key(self):
        ppk = Keypairs.fetch(self.pnt_keystore, self.secret_key, self.keystore_path )
        return ppk[0]

    def agree(self, public_key, info=b"x25591_key_exchange", salt=None) -> bytes:
        if not self.keystore_path:
            self.keystore_path = f"db_keys/{pnt_keystore}.db"
        ppk = Keypairs.fetch(self.pnt_keystore, self.secret_key, self.keystore_path )
        if ppk:
            x = X25519PrivateKey.from_private_bytes(ppk[1])
            shared_key = x.exchange(X25519PublicKey.from_public_bytes(public_key))
            return Keypairs.__agree__(shared_key, info, salt)


if __name__ == "__main__":
    client1 = ecdh()
    client1_public_key = client1.init()

    client2 = ecdh()
    client2_public_key = client2.init()

    dk = client1.agree(client2_public_key)
    dk1 = client2.agree(client1_public_key)

    assert(dk != None)
    assert(dk1 != None)
    assert(dk == dk1)


    client1 = x25519()
    client1_public_key = client1.init()

    client2 = x25519()
    client2_public_key = client2.init()

    dk = client1.agree(client2_public_key)
    dk1 = client2.agree(client1_public_key)

    assert(dk != None)
    assert(dk1 != None)
    assert(dk == dk1)