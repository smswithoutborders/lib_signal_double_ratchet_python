from keypairs import Keypairs, x25519

from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import logging
import struct
import helpers

class States:
    DHs: Keypairs
    DHr: bytes

    RK: bytes
    CKs: bytes
    CKr: bytes

    Ns = 0
    Nr = 0

    PN = 0

    MKSKIPPED = {}

    public_key: bytes
    pnt_keystore: str
    enc_key: bytes


class HEADERS:
    dh: bytes # public key bytes
    pn = None
    n = None
    
    LEN = None
    
    def __init__(self, dh=None, pn=None, n=None):
        self.dh = dh
        self.pn = pn
        self.n = n

    def serialize(self) -> bytes:
        return struct.pack("<ii", self.pn, self.n) + self.dh

    def deserialize(self, data):
        self.pn, self.n = struct.unpack("<ii", data[0:8])
        self.dh = data[12:]


class DHRatchet:
    def __init__(self, state: States, header: HEADERS, keystore_path: str=None):
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0

        state.DHr = header.dh
        state.public_key, state.pnt_keystore, state.enc_key, dk = \
            DH(state.DHs, state.DHr, keystore_path)
        state.RK, state.CKr = KDF_RK(state.RK, dk)
        state.DHs = GENERATE_DH(keystore_path)
        state.public_key, state.pnt_keystore, state.enc_key, dk = \
            DH(state.DHs, state.DHr, keystore_path)
        state.RK, state.CKs = KDF_RK(state.RK, dk)

def GENERATE_DH(keystore_path: str=None):
    return x25519(keystore_path=keystore_path)

def DH(dh_pair: Keypairs, dh_pub: bytes, keystore_path: str):
    public_key, pnt_keystore, enc_key = dh_pair.get_public_key()
    return public_key, pnt_keystore, enc_key, dh_pair.agree(dh_pub, pnt_keystore, enc_key)

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
    cipher_text = verify_signature(mk, ciphertext, associated_data)
    key, _, _ = get_mac_parameters(mk)
    iv = cipher_text[:AES.block_size]
    data = cipher_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def CONCAT(ad: bytes, header: HEADERS):
    ex_len = struct.pack("<i", len(ad))
    return ex_len + ad + header.serialize()
