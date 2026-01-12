#!/usr/bin/env python3

import base64
import json
import pickle
import struct
import warnings

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

import smswithoutborders_libsig.helpers as helpers
from smswithoutborders_libsig.keypairs import x25519


class States:
    DHs: x25519 = None
    DHr: bytes = None

    RK: bytes = None
    CKs: bytes = None
    CKr: bytes = None

    Ns = 0
    Nr = 0

    PN = 0

    MKSKIPPED = {}

    DHRs: x25519 = None
    DHRr: bytes = None
    HKs: bytes = None
    HKr: bytes = None
    NHKs: bytes = None
    NHKr: bytes = None

    @staticmethod
    def deserialize(data):
        warnings.warn(
            "deserialize() is deprecated due to pickle usage. Use deserialize_json() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        state = States()

        s_keypairs_len, dhr_len, rk_len, cks_len, ckr_len = struct.unpack(
            f"<{'i' * 5}", data[0 : 4 * 5]
        )

        data = data[4 * 5 :]

        state.DHs = x25519().deserialize(data[:s_keypairs_len])
        state.RK = data[s_keypairs_len : (s_keypairs_len + rk_len)]
        state.DHr = data[
            (s_keypairs_len + rk_len) : (s_keypairs_len + dhr_len + rk_len)
        ]
        state.CKs = data[
            (s_keypairs_len + dhr_len + rk_len) : (
                s_keypairs_len + dhr_len + rk_len + cks_len
            )
        ]
        if state.CKs == b"":
            state.CKs = None
        state.CKr = data[
            (s_keypairs_len + dhr_len + rk_len + cks_len) : (
                s_keypairs_len + dhr_len + rk_len + cks_len + ckr_len
            )
        ]
        if state.CKr == b"":
            state.CKr = None
        state.Ns, state.Nr, state.PN = struct.unpack(
            "<iii",
            data[
                (s_keypairs_len + dhr_len + rk_len + cks_len + ckr_len) : (
                    s_keypairs_len + dhr_len + rk_len + cks_len + ckr_len + 3 * 4
                )
            ],
        )
        state.MKSKIPPED = pickle.loads(
            data[(s_keypairs_len + dhr_len + rk_len + cks_len + ckr_len + 3 * 4) :]
        )

        return state

    def serialize_json(self) -> bytes:
        """
        Serialize state to JSON format
        Returns bytes containing JSON-encoded state.
        """

        if (
            (self.DHs is None and self.DHRs is None)
            or self.RK is None
        ):
            raise Exception(
                "State cannot be serialized: reason DHs == None or RK == None"
            )

        mkskipped_encoded = {}
        for (dh_key, n), mk_value in self.MKSKIPPED.items():
            key_str = f"{base64.b64encode(dh_key).decode('ascii')}:{n}"
            mkskipped_encoded[key_str] = base64.b64encode(mk_value).decode("ascii")

        state_dict = {
            "version": 1,
            "DHs": base64.b64encode(self.DHs.serialize()).decode("ascii") if self.DHs else None,
            "DHr": base64.b64encode(self.DHr).decode("ascii") if self.DHr else None,
            "RK": base64.b64encode(self.RK).decode("ascii"),
            "CKs": base64.b64encode(self.CKs).decode("ascii") if self.CKs else None,
            "CKr": base64.b64encode(self.CKr).decode("ascii") if self.CKr else None,
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "HKs": base64.b64encode(self.HKs).decode("ascii") if self.HKs else None,
            "HKr": base64.b64encode(self.HKr).decode("ascii") if self.HKr else None,
            "NHKs": base64.b64encode(self.NHKs).decode("ascii") if self.NHKs else None,
            "NHKr": base64.b64encode(self.NHKr).decode("ascii") if self.NHKr else None,
            "DHRr": base64.b64encode(self.DHRr).decode("ascii") if self.DHRr else None,
            "DHRs": base64.b64encode(self.DHRs.serialize()).decode("ascii") if self.DHRs else None,
        }

        return json.dumps(state_dict).encode("utf-8")

    @staticmethod
    def deserialize_json(data: bytes):
        """
        Deserialize state from JSON format.
        """
        state = States()
        state_dict = json.loads(data.decode("utf-8"))

        if state_dict.get("version") != 1:
            raise ValueError(f"Unsupported state version: {state_dict.get('version')}")

        state.DHs = x25519().deserialize(base64.b64decode(state_dict["DHs"])) if state_dict["DHs"] else None
        state.RK = base64.b64decode(state_dict["RK"])
        state.DHr = base64.b64decode(state_dict["DHr"]) if state_dict["DHr"] else None
        state.CKs = base64.b64decode(state_dict["CKs"]) if state_dict["CKs"] else None
        state.CKr = base64.b64decode(state_dict["CKr"]) if state_dict["CKr"] else None
        state.Ns = state_dict["Ns"]
        state.Nr = state_dict["Nr"]
        state.PN = state_dict["PN"]


        state.DHRs = x25519().deserialize(base64.b64decode(state_dict["DHRs"])) if state_dict["DHRs"] else None
        state.DHRr = base64.b64decode(state_dict["DHRr"]) if state_dict["DHRr"] else None
        state.HKr = base64.b64decode(state_dict["HKr"]) if state_dict["HKr"] else None
        state.HKs = base64.b64decode(state_dict["HKs"]) if state_dict["HKs"] else None
        state.NHKs = base64.b64decode(state_dict["NHKs"]) if state_dict["NHKs"] else None
        state.NHKr = base64.b64decode(state_dict["NHKr"]) if state_dict["NHKr"] else None

        state.MKSKIPPED = {}
        for key_str, mk_value_encoded in state_dict["MKSKIPPED"].items():
            dh_b64, n_str = key_str.rsplit(":", 1)
            dh_key = base64.b64decode(dh_b64)
            n = int(n_str)
            mk_value = base64.b64decode(mk_value_encoded)
            state.MKSKIPPED[(dh_key, n)] = mk_value

        return state


class HEADERS:
    dh: bytes  # public key bytes
    pn = None
    n = None

    LEN = None

    def __init__(self, dh_pair: bytes = None, pn=None, n=None):
        if dh_pair:
            self.dh = dh_pair.get_public_key()
        self.pn = pn
        self.n = n

    def serialize(self) -> bytes:
        return struct.pack("<ii", self.pn, self.n) + self.dh

    """
    def deserialize(self, data):
        self.pn, self.n = struct.unpack("<ii", data[0:8])
        self.dh = data[12:]
    """

    @staticmethod
    def deserialize(data):
        pn, n = struct.unpack("<ii", data[0:8])
        headers = HEADERS(pn=pn, n=n)
        headers.dh = data[8:]

        return headers


def DHRatchet(state: States, header: HEADERS):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0

    state.DHr = header.dh
    shared_secret = DH(state.DHs, state.DHr)
    state.RK, state.CKr = KDF_RK(state.RK, shared_secret)
    state.DHs = GENERATE_DH(state.DHs.keystore_path, state.DHs.secret_key)
    shared_secret = DH(state.DHs, state.DHr)
    state.RK, state.CKs = KDF_RK(state.RK, shared_secret)

def DHRatchetHE(state: States, header: HEADERS):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.HKs = state.NHKs
    state.HKr = state.NHKr
    state.DHRr = header.dh
    state.RK, state.CKr, state.NHKr = KDF_RK_HE(state.RK, DH_HE(state.DHRs, state.DHRr))
    state.DHRs = GENERATE_DH_HE(state.DHRs.keystore_path, state.DHRs.secret_key)
    state.RK, state.CKs, state.NHKs = KDF_RK_HE(state.RK, DH_HE(state.DHRs, state.DHRr))

def GENERATE_DH_HE(keystore_path: str = None, secret_key=None) -> bytes:
    x = x25519(keystore_path=keystore_path, secret_key=secret_key)
    x.initHE()
    return x


def GENERATE_DH(keystore_path: str = None, secret_key=None) -> bytes:
    x = x25519(keystore_path=keystore_path, secret_key=secret_key)
    x.init()
    return x


def DH_HE(dh_pair: x25519, dh_pub: bytes) -> bytes:
    return dh_pair.agree(
        public_key=dh_pub, 
        info = b"RelaySMS C2S DR Ratchet v1",
    )

def DH(dh_pair: x25519, dh_pub: bytes) -> bytes:
    return dh_pair.agree(dh_pub)

def KDF_RK_HE(rk, dh_out):
    length = 32
    num_keys = 3

    information = b"SMSWithoutBorders DRHE v2"

    return HKDF(
        master=dh_out,
        key_len=length,
        salt=rk,
        hashmod=SHA512,
        num_keys=num_keys,
        context=information,
    )

def KDF_RK(rk, dh_out):
    length = 32
    num_keys = 2

    # TODO: make meaninful information
    information = b"KDF_RK"

    return HKDF(
        master=dh_out,
        key_len=length,
        salt=rk,
        hashmod=SHA512,
        num_keys=num_keys,
        context=information,
    )


def KDF_CK(ck):
    d_ck = HMAC.new(ck, digestmod=SHA256)
    _ck = d_ck.update(b"\x01").digest()

    d_ck = HMAC.new(ck, digestmod=SHA256)
    mk = d_ck.update(b"\x02").digest()
    return _ck, mk

def HENCRYPT(hk, plaintext) -> bytes:
    key, auth_key, iv = helpers.get_mac_parameters(hk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plaintext, AES.block_size))
    hmac = helpers.build_verification_hash(
        auth_key=auth_key, 
        cipher_text=cipher_text,
        associated_data=None
    )
    return cipher_text + hmac.digest()


def ENCRYPT(mk, plaintext, associated_data) -> bytes:
    key, auth_key, iv = helpers.get_mac_parameters(mk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plaintext, AES.block_size))
    hmac = helpers.build_verification_hash(auth_key, associated_data, cipher_text)
    return cipher_text + hmac.digest()

def HDECRYPT(hk, ciphertext):
    # Throws an exception in case cannot verify
    cipher_text = helpers.verify_signature(hk, ciphertext, None)
    key, _, iv = helpers.get_mac_parameters(hk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text), AES.block_size)


def DECRYPT(mk, ciphertext, associated_data):
    # Throws an exception in case cannot verify
    cipher_text = helpers.verify_signature(mk, ciphertext, associated_data)
    key, _, iv = helpers.get_mac_parameters(mk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text), AES.block_size)


def CONCAT_HE(ad: bytes, header: bytes):
    # ex_len = struct.pack("<i", len(ad))
    # return ex_len + ad + header.serialize()
    return ad + header

def CONCAT(ad: bytes, header: HEADERS):
    # ex_len = struct.pack("<i", len(ad))
    # return ex_len + ad + header.serialize()
    return ad + header.serialize()
