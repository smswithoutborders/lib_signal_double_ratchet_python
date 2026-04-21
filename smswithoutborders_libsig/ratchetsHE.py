
import os
from smswithoutborders_libsig.protocols import (
    States,
    HEADERS,
    GENERATE_DH_HE,
    DH_HE,
    KDF_CK,
    KDF_RK_HE,
    ENCRYPT,
    HENCRYPT,
    DECRYPT,
    HDECRYPT,
    CONCAT_HE,
    DHRatchetHE,
)

from smswithoutborders_libsig.keypairs import x25519
    
class RatchetsHE:
    MAX_SKIP = int(os.environ.get("MKSKIPPED", 100))

    """
    A class to handle the ratchet mechanism.
    """

    @staticmethod
    def alice_init_HE(
        state: States, 
        SK: bytes, 
        bob_dh_public_key: bytes, 
        shared_hka: bytes, 
        shared_nhkb: bytes,
        keystore_path: str = None
    ):
        state.DHRs = GENERATE_DH_HE(keystore_path)
        state.DHRr = bob_dh_public_key
        state.RK, state.CKs, state.NHKs = KDF_RK_HE(SK, DH_HE(state.DHRs, state.DHRr))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        state.HKs = shared_hka
        state.HKr = None
        state.NHKr = shared_nhkb

    @staticmethod
    def bob_init_HE(
        state: States, 
        SK: bytes, 
        bob_dh_key_pair: x25519, 
        shared_hka: bytes, 
        shared_nhkb: bytes
    ):
        state.DHRs = bob_dh_key_pair
        state.DHRr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        state.HKs = None
        state.NHKs = shared_nhkb
        state.HKr = None
        state.NHKr = shared_hka

    @staticmethod
    def RatchetEncryptHE(*, state: States, plaintext: bytes, AD: bytes):
        state.CKs, mk = KDF_CK(state.CKs)
        header = HEADERS(state.DHRs, state.PN, state.Ns)
        enc_header = HENCRYPT(state.HKs, header.serialize())
        state.Ns += 1
        return enc_header, ENCRYPT(mk, plaintext, CONCAT_HE(AD, enc_header))

    @staticmethod
    def RatchetDecryptHE(
        *, 
        state: States, 
        enc_header: bytes, 
        ciphertext: bytes,
        AD: bytes,
    ) -> bytes:
        plaintext = RatchetsHE.TrySkippedMessageKeysHE(state, enc_header, ciphertext, AD)
        if plaintext:
            return plaintext

        header, dh_ratchet = RatchetsHE.DecryptHeader(state, enc_header)
        header = HEADERS.deserialize(header)
        if dh_ratchet:
            RatchetsHE.SkipMessageKeysHE(state, header.pn)
            DHRatchetHE(state, header)

        RatchetsHE.SkipMessageKeysHE(state, header.n)
        state.CKr, mk = KDF_CK(state.CKr)
        state.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT_HE(AD, enc_header))


    @staticmethod
    def TrySkippedMessageKeysHE(
        state: States, 
        enc_header: bytes, 
        ciphertext: bytes, 
        AD: bytes
    ) -> bytes:
        for ((hk, n), mk) in state.MKSKIPPED.items():
            header = HDECRYPT(hk, enc_header)
            if header != None and HEADERS.deserialize(header).n == n:
                del state.MKSKIPPED[hk, n]
                return DECRYPT(mk, ciphertext, CONCAT_HE(AD, enc_header))

        return None
    
    @staticmethod
    def SkipMessageKeysHE(state: States, until: int):
        if state.Nr + RatchetsHE.MAX_SKIP < until:
            raise Exception("MAX_SKIP Exceeded")

        if state.CKr:
            while state.Nr < until:
                state.CKr, mk = KDF_CK(state.CKr)
                state.MKSKIPPED[state.HKr, state.Nr] = mk
                state.Nr += 1

    @staticmethod
    def DecryptHeader(state: States, enc_header):
        header = None
        try:
            header = HDECRYPT(state.HKr, enc_header)
        except ValueError as e:
            pass

        if header != None:
            return header, False
        header = HDECRYPT(state.NHKr, enc_header)
        if header != None:
            return header, True
        raise Exception("Generic error decrypting header...")
