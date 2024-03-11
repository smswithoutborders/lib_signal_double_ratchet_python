import dh
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import logging

class State:
    DHs:dh.C_ECDH = None # -> keypair
    DHr:str = None # -> public key

    RK = None
    CKs = None
    CKr = None

    Ns = 0
    Nr = 0

    PN = 0

    MKSKIPPED = {}

    logging = None

    def report_status(self):
        self.logging.debug("\n%s: State parameters -", self.name)
        self.logging.debug("\t+ DHs: %s", self.DHs.get_public_key(False))
        self.logging.debug("\t+ DHr: %s", self.DHr)
        self.logging.debug("\t+ PN: %s", self.PN)
        self.logging.debug("\t+ Ns: %d", self.Ns)
        self.logging.debug("\t+ Nr: %d", self.Nr)
        self.logging.debug("\t+ RK: %s", self.RK)
        self.logging.debug("\t+ CKs: %s", self.CKs)
        self.logging.debug("\t+ Ckr: %s", self.CKr)
        self.logging.debug("\t+ MKSKIPPED: %s", self.MKSKIPPED)

    def __init__(self, name):
        self.name = name

class HEADER:
    DH = None
    PN = None
    N = None
    
    LEN = None
    
    def __init__(self, DH, PN, N):
        self.DH = DH
        self.PN = PN
        self.N = N

    def compose(data):
        import json
        r_header = json.loads(data)
        return HEADER(r_header[0], r_header[1], r_header[2])

class DHRatchet:
    def __init__(self, state: State, header: HEADER):
        self.state = state
        self.state.PN = state.Ns
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.DHr = header.DH.get_public_key()
        self.state.RK, self.state.CKr = KDF_RK(
                self.state.RK, DH(self.state.DHs, self.state.DHr))
        self.state.DHs = GENERATE_DH()
        self.state.RK, self.state.CKs = KDF_RK(
                self.state.RK, DH(self.state.DHs, self.state.DHr))

    def get_state(self):
        return self.state

    def init(state, SK, dh_pub_key):
        state.DHs = GENERATE_DH()
        state.RK = SK
        state.DHr = dh_pub_key
        if state.DHr:
            state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
        return state

def GENERATE_DH():
    return dh.C_ECDH()

def DH(dh_pair, dh_pub):
    dh_pair.set_peer_public_key(dh_pub)
    return dh_pair.generate_secret()

def KDF_RK(rk, dh_out): #dh_out = pub_key
    length=32
    num_keys=2
    information=b'KDF_RK'
    return _hkdf(dh_out, rk, length, num_keys, information)

def KDF_CK(ck):
    d_ck = HMAC.new(ck, digestmod=SHA256)
    ck = d_ck.update(b'\x01').digest()

    d_ck = HMAC.new(ck, digestmod=SHA256)
    mk = d_ck.update(b'\x02').digest()
    return ck, mk

def ENCRYPT(mk, plaintext, associated_data) -> bytes:
    key, auth_key, iv = _encrypt_params(mk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = iv + cipher.encrypt(pad(plaintext,  AES.block_size))
    hmac = _build_hash_out(auth_key, associated_data, cipher_text)
    return cipher_text + hmac.digest()

def DECRYPT(mk, cipher_text, associated_data):
    try:
        cipher_text = _verify_cipher_text(mk, cipher_text, associated_data)
    except Exception as error:
        raise error
    else:
        key, _, _ = _encrypt_params(mk)
        iv = cipher_text[:AES.block_size]
        data = cipher_text[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data), AES.block_size)

def CONCAT(ad, header):
    import json
    return ad.encode() + json.dumps(
            [str(header.DH.get_public_key()), header.PN, header.N]).encode()

def _build_hash_out(auth_key, associated_data, cipher_text):
    return HMAC.new(auth_key, digestmod=SHA256).update(
            associated_data + cipher_text)

def _encrypt_params(mk):
    hash_len = 80
    information = b'ENCRYPT'
    salt = bytes(hash_len)
    hkdf_out = _hkdf(mk, salt, hash_len, 1, information)

    key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:(64+16)]

    return key, auth_key, iv


def _hkdf(master_secret, salt=None, length=32, num_keys=2, information=None):
    if not salt:
        salt = get_random_bytes(16)
    
    return HKDF(master_secret, length, salt, SHA512, num_keys, context=information)

def _verify_cipher_text(mk, cipher_text_mac, associated_data):
    """
    Throws ValueError – if the MAC does not match. 
    It means that the message has been tampered with or that 
        the MAC key is incorrect.
    """ 

    _, auth_key, _ = _encrypt_params(mk)
    mac = cipher_text_mac[len(cipher_text_mac) - SHA256.digest_size:]
    cipher_text = cipher_text_mac[:SHA256.digest_size]
    hmac = _build_hash_out(auth_key, associated_data, cipher_text)
    try:
        hmac.verify(mac)
    except Exception as error:
        logging.error("\nmac: %s\ncipher text: %s\nAD: %s\nHMAC digest: %s", 
                      mac, cipher_text, associated_data, hmac.digest())
        raise error

    return cipher_text
