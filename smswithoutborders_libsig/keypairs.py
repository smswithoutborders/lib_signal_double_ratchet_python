#!/usr/bin/env python3
import secrets
import struct
import uuid
import hashlib
from typing import Self

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Protocol.KDF import HKDF

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from smswithoutborders_libsig.keystore import Keystore


class x25519:
    def __init__(
        self, 
        keystore_path=None, 
        pnt_keystore=None, 
        secret_key=None,
    ):
        self.keystore_path = keystore_path
        self.pnt_keystore = pnt_keystore
        self.secret_key = secret_key
        self.size = 32

    def initHE(
        self,
        eC: X25519PrivateKey = None,
        eCHK: X25519PrivateKey = None,
        eCNHK: X25519PrivateKey = None,
    ):
        if not eC:
            eC = X25519PrivateKey.generate()
        if not eCHK:
            eCHK = X25519PrivateKey.generate()
        if not eCNHK:
            eCNHK = X25519PrivateKey.generate()
        pk = eC.public_key().public_bytes_raw()
        hk_pk = eCHK.public_key().public_bytes_raw()
        nhk_pk = eCNHK.public_key().public_bytes_raw()

        self.pnt_keystore = uuid.uuid4().hex

        if not self.keystore_path:
            self.keystore_path = f"db_keys/{self.pnt_keystore}.db"

        self.secret_key = self.storeHE(
            public_key=pk, 
            private_key=eC.private_bytes_raw(), 
            header_public_key=hk_pk, 
            header_private_key=eCHK.private_bytes_raw(), 
            next_header_public_key=nhk_pk, 
            next_header_private_key=eCNHK.private_bytes_raw(), 
            keystore_path=self.keystore_path, 
            pnt_keystore=self.pnt_keystore, 
            secret_key=self.secret_key
        )
        return pk, hk_pk, nhk_pk

    def init(
        self,
        private_key: X25519PrivateKey = None
    ):
        if not private_key:
            private_key = X25519PrivateKey.generate()

        pk = private_key.public_key().public_bytes_raw()
        _pk = private_key.private_bytes_raw()
        self.pnt_keystore = uuid.uuid4().hex

        if not self.keystore_path:
            self.keystore_path = f"db_keys/{self.pnt_keystore}.db"

        self.secret_key = self.store(
            pk, _pk, self.keystore_path, self.pnt_keystore, secret_key=self.secret_key
        )
        return pk

    def serialize(self) -> bytes:
        """ """
        if (
            not hasattr(self, "pnt_keystore")
            or self.pnt_keystore == None
            or not hasattr(self, "keystore_path")
            or self.keystore_path == None
            or not hasattr(self, "secret_key")
            or self.secret_key == None
        ):
            raise Exception("keypair not initialized -- init()")

        keystore_path_len = len(self.keystore_path)
        pnt_keystore_len = len(self.pnt_keystore)
        return (
            struct.pack("<ii", keystore_path_len, pnt_keystore_len)
            + self.keystore_path.encode()
            + self.pnt_keystore.encode()
            + self.secret_key.encode()
        )

    def deserialize(self, data) -> Self:
        """ """
        x = x25519()

        keystore_path_len, pnt_keystore_len = struct.unpack("<ii", data[0:8])
        x.keystore_path = data[8 : (8 + keystore_path_len)].decode()
        x.pnt_keystore = data[
            (8 + keystore_path_len) : (8 + keystore_path_len + pnt_keystore_len)
        ].decode()
        x.secret_key = data[(8 + keystore_path_len + pnt_keystore_len) :].decode()
        return x

    def load_keystore_HE(self, pnt_keystore: str, secret_key: bytes):
        if not self.keystore_path:
            self.keystore_path = f"db_keys/{pnt_keystore}.db"
        (public_key, private_key, 
         _, header_private_key, 
         _, next_header_private_key) = self.fetchHE(pnt_keystore, secret_key, self.keystore_path)
        if public_key:
            self.pnt_keystore = pnt_keystore
            self.secret_key = secret_key

            return X25519PrivateKey.from_private_bytes(private_key), X25519PrivateKey.from_private_bytes(header_private_key), X25519PrivateKey.from_private_bytes(next_header_private_key)

    def load_keystore(self, pnt_keystore: str, secret_key: bytes):
        if not self.keystore_path:
            self.keystore_path = f"db_keys/{pnt_keystore}.db"
        ppk = self.fetch(pnt_keystore, secret_key, self.keystore_path)
        if ppk:
            self.pnt_keystore = pnt_keystore
            self.secret_key = secret_key

            return X25519PrivateKey.from_private_bytes(ppk[1])

    def get_public_key(self):
        ppk = self.fetch(self.pnt_keystore, self.secret_key, self.keystore_path)
        if ppk:
            return ppk[0]

    def agreeOnly( 
        self, 
        public_key, 
        private_key: X25519PrivateKey = None,  # Clients have this as static keypairs
    ) -> bytes:
        if private_key == None:
            private_key = self.load_keystore(self.pnt_keystore, self.secret_key)
        return private_key.exchange(X25519PublicKey.from_public_bytes(public_key))

    def agree(
        self, 
        public_key, 
        info=b"x25591_key_exchange", 
        salt=None,
        header_encrypted=False,
    ) -> bytes:
        if header_encrypted:
            x, _, _ = self.load_keystore_HE(self.pnt_keystore, self.secret_key)
        else:
            x = self.load_keystore(self.pnt_keystore, self.secret_key)
        shared_key = x.exchange(X25519PublicKey.from_public_bytes(public_key))
        return self.__agree__(shared_key, info, salt)

    def storeHE(
            self, 
            public_key, 
            private_key, 
            header_public_key, 
            header_private_key, 
            next_header_public_key, 
            next_header_private_key, 
            keystore_path, 
            pnt_keystore, 
            secret_key=None
    ) -> bytes:
        if not secret_key:
            secret_key = secrets.token_bytes(self.size).hex()

        keystore = Keystore(keystore_path, secret_key, True)
        keystore.storeHE(keypair=(
            public_key, 
            private_key,
            header_public_key,
            header_private_key,
            next_header_public_key,
            next_header_private_key), 
            pnt=pnt_keystore
        )

        return secret_key

    def store(self, pk, _pk, keystore_path, pnt_keystore, secret_key=None) -> bytes:
        if not secret_key:
            secret_key = secrets.token_bytes(self.size).hex()

        keystore = Keystore(keystore_path, secret_key)
        keystore.store(keypair=(pk, _pk), pnt=pnt_keystore)

        return secret_key

    def fetchHE(self, pnt_keystore, secret_key, keystore_path=None):
        keystore = Keystore(keystore_path, secret_key, True)
        return keystore.fetchHE(pnt_keystore)

    def fetch(self, pnt_keystore, secret_key, keystore_path=None):
        keystore = Keystore(keystore_path, secret_key)
        return keystore.fetch(pnt_keystore)

    def __agree__(self, secret_key, info=b"x25591_key_exchange", salt=None):
        return HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=salt,
            context=info,
            master=secret_key
        )

    def __agreeWithAuthAndNonce__(
        self,
        eph_private_key: X25519PrivateKey,
        auth_private_key: X25519PrivateKey,  # Clients have this as static keypairs
        auth_public_key: X25519PublicKey,
        public_key: bytes,
        nonce1: bytes,
        nonce2: bytes,
        salt: bytes = b"RelaySMS v1",
        info: bytes = b"RelaySMS C2S DR v1",
    ): 
        handshake_salt = nonce1 + nonce2

        if auth_private_key == None:
            dh1 = eph_private_key.exchange(auth_public_key)
        else:
            dh1 = auth_private_key.exchange(X25519PublicKey.from_public_bytes(public_key))
        dh2 = eph_private_key.exchange(X25519PublicKey.from_public_bytes(public_key))

        chain_key = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=salt,
            context=info,
            master=handshake_salt
        )

        chain_key = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=chain_key,
            context=info,
            master=dh1
        )

        return HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=chain_key,
            context=info,
            master=dh2
        )

    def agreeWithAuthAndNonce(
        self,
        auth_private_key: X25519PrivateKey,  # Clients have this as static keypairs
        auth_public_key: X25519PublicKey,
        public_key: bytes,
        header_public_key: bytes,
        next_header_public_key: bytes,
        nonce1: bytes,
        nonce2: bytes,
    ) -> bytes:
        header_info=b"RelaySMS C2S DRHE v1"
        eph_private_key, header_private_key, next_header_private_key = self.load_keystore_HE(self.pnt_keystore, self.secret_key)

        root_key = self.__agreeWithAuthAndNonce__(
            eph_private_key=eph_private_key,
            auth_private_key=auth_private_key,
            auth_public_key=auth_public_key,
            public_key=public_key,
            nonce1=nonce1,
            nonce2=nonce2,
        )

        header_key = self.__agreeWithAuthAndNonce__(
            eph_private_key=header_private_key,
            auth_private_key=auth_private_key,
            auth_public_key=auth_public_key,
            public_key=header_public_key,
            nonce1=nonce1,
            nonce2=nonce2,
            info = header_info
        )

        next_header_key = self.__agreeWithAuthAndNonce__(
            eph_private_key=next_header_private_key,
            auth_private_key=auth_private_key,
            auth_public_key=auth_public_key,
            public_key=next_header_public_key,
            nonce1=nonce1,
            nonce2=nonce2,
            info = header_info
        )

        return root_key, header_key, next_header_key
    
    def agreeWithNoiseIKPattern(
        self,
        client_static_private_key: X25519PrivateKey, 
        client_ephemeral_public_key: X25519PublicKey, 
        client_enc_static_public_key: bytes,
        server_static_public_key: X25519PublicKey,
        server_static_private_key: X25519PrivateKey,
    ): 
        client_ephemeral_private_key = None
        if not server_static_private_key:
            client_ephemeral_private_key = self.load_keystore(self.pnt_keystore, self.secret_key) 
            client_ephemeral_public_key = client_ephemeral_private_key.public_key()

        info = b"RelaySMS C2S DR v1"
        header_info = b"RelaySMS C2S DRHE v1"

        h = hashlib.sha256(b"Noise_IK_25519_AESGCM_SHA256").digest()

        ck = h

        if server_static_public_key:
            h = hashlib.sha256(h + server_static_public_key.public_bytes_raw()).digest()
        else:
            h = hashlib.sha256(h + server_static_private_key.public_key().public_bytes_raw()).digest()
        h = hashlib.sha256(h + client_ephemeral_public_key.public_bytes_raw()).digest()

        if client_ephemeral_private_key:
            DH_es = client_ephemeral_private_key.exchange(server_static_public_key)
        else:
            DH_es = server_static_private_key.exchange(client_ephemeral_public_key)

        ck, k = HKDF(
            hashmod=SHA256, 
            key_len=self.size,
            salt=ck,
            context=info,
            master=DH_es,
            num_keys=2
        )

        h = hashlib.sha256(h + DH_es).digest()

        if client_static_private_key: 
            cipher = AES.new(k, AES.MODE_GCM, nonce=h)
            client_enc_static_public_key = cipher.encrypt(pad(client_static_private_key.public_key().public_bytes_raw(), AES.block_size))
        else:
            cipher = AES.new(k, AES.MODE_GCM, nonce=h) 
            CI_pk = unpad(cipher.decrypt(client_enc_static_public_key), AES.block_size)

        h = hashlib.sha256(h + client_enc_static_public_key).digest()

        if client_static_private_key:
            DH_ss = client_static_private_key.exchange(server_static_public_key)
        else:
            DH_ss = server_static_private_key.exchange(X25519PublicKey.from_public_bytes(CI_pk))

        ck, k = HKDF(
            key_len=self.size,
            salt=ck,
            hashmod=SHA256, 
            context=info,
            master=DH_ss,
            num_keys=2
        )

        h = hashlib.sha256(h + DH_ss).digest()

        root_key, header_key, next_header_key = HKDF(
            hashmod=SHA256, 
            key_len=self.size,
            salt=k,
            context=header_info,
            num_keys=3,
            master=None
        )

        return h, client_enc_static_public_key, root_key, header_key, next_header_key
