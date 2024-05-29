from smswithoutborders_libsig.keypairs import Keypairs, x25519

from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import logging
import struct
import smswithoutborders_libsig.helpers as helpers

class States:
    DHs: Keypairs = None
    DHr: bytes = None

    RK: bytes = None
    CKs: bytes = None
    CKr: bytes = None

    Ns = 0
    Nr = 0

    PN = 0

    MKSKIPPED = {}


class HEADERS:
    dh: bytes # public key bytes
    pn = None
    n = None
    
    LEN = None
    
    def __init__(self, dh: Keypairs=None, pn=None, n=None):
        self.dh = dh.get_public_key()
        self.pn = pn
        self.n = n

    def serialize(self) -> bytes:
        return struct.pack("<ii", self.pn, self.n) + self.dh

    def deserialize(self, data):
        self.pn, self.n = struct.unpack("<ii", data[0:8])
        self.dh = data[12:]


class DHRatchet:
    def __init__(self, state: States, header: HEADERS):
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0

        state.DHr = header.dh
        shared_secret = DH(state.DHs, state.DHr)
        state.RK, state.CKr = KDF_RK(state.RK, shared_secret)
        state.DHs = GENERATE_DH(state.DHs.keystore_path)
        shared_secret = DH(state.DHs, state.DHr)
        state.RK, state.CKs = KDF_RK(state.RK, shared_secret)


def GENERATE_DH(keystore_path: str=None) -> bytes:
    x = x25519(keystore_path=keystore_path)
    x.init()
    return x

def DH(dh_pair: Keypairs, dh_pub: bytes) -> bytes:
    return dh_pair.agree(dh_pub)

def KDF_RK(rk, dh_out): 
    length=32
    num_keys=2

    # TODO: make meaninful information
    information=b'KDF_RK'

    return HKDF(master=dh_out, 
                 key_len=length, 
                 salt=rk, 
                 hashmod=SHA512, 
                 num_keys=num_keys, context=information)

def KDF_CK(ck):
    d_ck = HMAC.new(ck, digestmod=SHA256)
    ck = d_ck.update(b'\x01').digest()

    d_ck = HMAC.new(ck, digestmod=SHA256)
    mk = d_ck.update(b'\x02').digest()
    return ck, mk

def ENCRYPT(mk, plaintext, associated_data) -> bytes:
    key, auth_key, iv = helpers.get_mac_parameters(mk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = iv + cipher.encrypt(pad(plaintext,  AES.block_size))
    hmac = helpers.build_verification_hash(auth_key, associated_data, cipher_text)
    return cipher_text + hmac.digest()

def DECRYPT(mk, ciphertext, associated_data):
    # Throws an exception in case cannot verify
    cipher_text = helpers.verify_signature(mk, ciphertext, associated_data)
    key, _, _ = helpers.get_mac_parameters(mk)
    iv = cipher_text[:AES.block_size]
    data = cipher_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def CONCAT(ad: bytes, header: HEADERS):
    ex_len = struct.pack("<i", len(ad))
    return ex_len + ad + header.serialize()
