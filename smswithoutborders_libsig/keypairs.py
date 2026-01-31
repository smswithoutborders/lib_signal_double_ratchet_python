#!/usr/bin/env python3
import secrets
import struct
import uuid
import hashlib
from typing import Self, Optional, Tuple

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
            secret_key=self.secret_key,
        )
        return pk, hk_pk, nhk_pk

    def init(self, private_key: X25519PrivateKey = None):
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
        (public_key, private_key, _, header_private_key, _, next_header_private_key) = (
            self.fetchHE(pnt_keystore, secret_key, self.keystore_path)
        )
        if public_key:
            self.pnt_keystore = pnt_keystore
            self.secret_key = secret_key

            return (
                X25519PrivateKey.from_private_bytes(private_key),
                X25519PrivateKey.from_private_bytes(header_private_key),
                X25519PrivateKey.from_private_bytes(next_header_private_key),
            )

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

    def agreeOnly(self, public_key, private_key: X25519PrivateKey = None) -> bytes:
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
        secret_key=None,
    ) -> bytes:
        if not secret_key:
            secret_key = secrets.token_bytes(self.size).hex()

        keystore = Keystore(keystore_path, secret_key, True)
        keystore.storeHE(
            keypair=(
                public_key,
                private_key,
                header_public_key,
                header_private_key,
                next_header_public_key,
                next_header_private_key,
            ),
            pnt=pnt_keystore,
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
            master=secret_key,
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
            dh1 = auth_private_key.exchange(
                X25519PublicKey.from_public_bytes(public_key)
            )
        dh2 = eph_private_key.exchange(X25519PublicKey.from_public_bytes(public_key))

        chain_key = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=salt,
            context=info,
            master=handshake_salt,
        )

        chain_key = HKDF(
            hashmod=SHA256, key_len=self.size, salt=chain_key, context=info, master=dh1
        )

        return HKDF(
            hashmod=SHA256, key_len=self.size, salt=chain_key, context=info, master=dh2
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
        header_info = b"RelaySMS C2S DRHE v1"
        eph_private_key, header_private_key, next_header_private_key = (
            self.load_keystore_HE(self.pnt_keystore, self.secret_key)
        )

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
            info=header_info,
        )

        next_header_key = self.__agreeWithAuthAndNonce__(
            eph_private_key=next_header_private_key,
            auth_private_key=auth_private_key,
            auth_public_key=auth_public_key,
            public_key=next_header_public_key,
            nonce1=nonce1,
            nonce2=nonce2,
            info=header_info,
        )

        return root_key, header_key, next_header_key

    def agreeWithNoiseIKPatternMessage1(
        self,
        client_static_private_key: Optional[X25519PrivateKey],
        client_enc_static_public_key: Optional[bytes],
        server_static_public_key: Optional[X25519PublicKey],
        server_static_private_key: Optional[X25519PrivateKey],
        client_ephemeral_public_key: Optional[X25519PublicKey] = None,
    ) -> Tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        """
        Noise IK Message 1.

        Returns: (h, enc_static_pk, rk0, hk, nhk, ck)
        """
        is_client = server_static_private_key is None

        if is_client:
            assert client_static_private_key is not None, (
                "Client must provide static private key"
            )
            assert server_static_public_key is not None, (
                "Client must provide server static public key"
            )
            assert self.pnt_keystore is not None, "Client must have keystore"
            assert self.secret_key is not None, "Client must have secret key"
        else:
            assert client_enc_static_public_key is not None, (
                "Server must provide encrypted client static public key"
            )
            assert client_ephemeral_public_key is not None, (
                "Server must provide client ephemeral public key"
            )
            assert server_static_private_key is not None, (
                "Server must provide static private key"
            )

        info = b"RelaySMS C2S DR v1"
        header_info = b"RelaySMS C2S DRHE v1"

        h = hashlib.sha256(b"Noise_IK_25519_AESGCM_SHA256").digest()
        ck = h

        if is_client:
            h = hashlib.sha256(h + server_static_public_key.public_bytes_raw()).digest()
        else:
            h = hashlib.sha256(
                h + server_static_private_key.public_key().public_bytes_raw()
            ).digest()

        if is_client:
            client_ephemeral_private_key = self.load_keystore(
                self.pnt_keystore, self.secret_key
            )
            client_ephemeral_public_key = client_ephemeral_private_key.public_key()

        h = hashlib.sha256(h + client_ephemeral_public_key.public_bytes_raw()).digest()

        if is_client:
            DH_es = client_ephemeral_private_key.exchange(server_static_public_key)
        else:
            DH_es = server_static_private_key.exchange(client_ephemeral_public_key)

        ck, k = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=ck,
            context=info,
            master=DH_es,
            num_keys=2,
        )

        if is_client:
            cipher = AES.new(k, AES.MODE_GCM, nonce=h[:12])
            cipher.update(h)
            client_enc_static_public_key = (
                cipher.encrypt(
                    client_static_private_key.public_key().public_bytes_raw()
                )
                + cipher.digest()
            )
        else:
            ciphertext = client_enc_static_public_key[:-16]
            tag = client_enc_static_public_key[-16:]
            cipher = AES.new(k, AES.MODE_GCM, nonce=h[:12])
            cipher.update(h)
            CI_pk = cipher.decrypt_and_verify(ciphertext, tag)

        h = hashlib.sha256(h + client_enc_static_public_key).digest()

        if is_client:
            DH_ss = client_static_private_key.exchange(server_static_public_key)
        else:
            DH_ss = server_static_private_key.exchange(
                X25519PublicKey.from_public_bytes(CI_pk)
            )

        ck, k = HKDF(
            key_len=self.size,
            salt=ck,
            hashmod=SHA256,
            context=info,
            master=DH_ss,
            num_keys=2,
        )

        cipher = AES.new(k, AES.MODE_GCM, nonce=h[:12])
        cipher.update(h)
        ciphertext = cipher.encrypt(b"") + cipher.digest()

        h = hashlib.sha256(h + ciphertext).digest()

        root_key, header_key, next_header_key = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=ck,
            context=header_info,
            master=DH_ss,
            num_keys=3,
        )

        return (
            h,
            client_enc_static_public_key,
            root_key,
            header_key,
            next_header_key,
            ck,
        )

    def agreeWithNoiseIKPatternMessage2(
        self,
        client_ephemeral_public_key: Optional[X25519PublicKey],
        server_ephemeral_public_key: Optional[X25519PublicKey],
        server_static_public_key: Optional[X25519PublicKey],
        server_static_private_key: Optional[X25519PrivateKey],
        h: bytes,
        ck: bytes,
    ) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        """
        Noise IK Message 2.

        Returns: (h, eS_pk, rk1, hk1, nhk1)
        """
        is_client = server_static_private_key is None

        if is_client:
            assert server_ephemeral_public_key is not None, (
                "Client must provide server ephemeral public key"
            )
            assert server_static_public_key is not None, (
                "Client must provide server static public key"
            )
            assert self.pnt_keystore is not None, (
                "Client must have keystore with eC from Message 1"
            )
            assert self.secret_key is not None, "Client must have keystore secret key"
        else:
            assert client_ephemeral_public_key is not None, (
                "Server must provide client ephemeral public key"
            )
            assert server_static_private_key is not None, (
                "Server must provide static private key"
            )
            assert self.pnt_keystore is not None, "Server must have keystore with eS"
            assert self.secret_key is not None, "Server must have keystore secret key"

        info = b"RelaySMS C2S DR v1"
        header_info = b"RelaySMS C2S DRHE v1"

        ephemeral_private_key = self.load_keystore(self.pnt_keystore, self.secret_key)

        if is_client:
            server_eph_pk_bytes = server_ephemeral_public_key.public_bytes_raw()
        else:
            server_eph_pk_bytes = ephemeral_private_key.public_key().public_bytes_raw()

        h = hashlib.sha256(h + server_eph_pk_bytes).digest()

        if is_client:
            DH_ee = ephemeral_private_key.exchange(server_ephemeral_public_key)
        else:
            DH_ee = ephemeral_private_key.exchange(client_ephemeral_public_key)

        ck, k = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=ck,
            context=info,
            master=DH_ee,
            num_keys=2,
        )

        cipher = AES.new(k, AES.MODE_GCM, nonce=h[:12])
        cipher.update(h)
        ciphertext = cipher.encrypt(b"") + cipher.digest()

        h = hashlib.sha256(h + ciphertext).digest()

        if is_client:
            DH_se = ephemeral_private_key.exchange(server_static_public_key)
        else:
            DH_se = server_static_private_key.exchange(client_ephemeral_public_key)

        ck, k = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=ck,
            context=info,
            master=DH_se,
            num_keys=2,
        )

        cipher = AES.new(k, AES.MODE_GCM, nonce=h[:12])
        cipher.update(h)
        ciphertext1 = cipher.encrypt(b"") + cipher.digest()

        h = hashlib.sha256(h + ciphertext1).digest()

        root_key1, header_key1, next_header_key1 = HKDF(
            hashmod=SHA256,
            key_len=self.size,
            salt=ck,
            context=header_info,
            master=b"",
            num_keys=3,
        )

        return h, server_eph_pk_bytes, root_key1, header_key1, next_header_key1
