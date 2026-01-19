
import os
from smswithoutborders_libsig.protocols import (
    States,
    HEADERS,
    GENERATE_DH,
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
        state.DHRs = GENERATE_DH(keystore_path)
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
            if header != None and header.n == n:
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
    def DecryptHeader(state, enc_header):
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


"""
The implementations in __main__ are not an official test.
This is a quick way of checking out things in the implementation.
The original test would be found in the test_ files.
"""
if __name__ == "__main__":
    import sys
    import secrets
    from cryptography.hazmat.primitives.asymmetric.x25519 import  X25519PrivateKey

    bob = x25519("db_keys/bobs_keys.db")
    bob_ek, bob_ehk, bob_enhk = bob.initHE() 
    bob_static_keys = X25519PrivateKey.generate()

    alice = x25519()
    alice_ek, alice_ehk, alice_enhk = alice.initHE()

    alice_nonce = secrets.token_bytes(16)
    bob_nonce = secrets.token_bytes(16)

    alice_ss, alice_hk, alice_nhk = alice.agreeWithAuthAndNonce(
        auth_private_key=None,
        auth_public_key=bob_static_keys.public_key(),
        header_public_key=bob_ehk,
        next_header_public_key=bob_enhk,
        public_key=bob_ek,
        nonce1=alice_nonce,
        nonce2=bob_nonce,
    )
    bob_ss, bob_hk, bob_nhk = bob.agreeWithAuthAndNonce(
        auth_private_key=bob_static_keys,
        auth_public_key=None,
        header_public_key=alice_ehk,
        next_header_public_key=alice_enhk,
        public_key=alice_ek,
        nonce1=alice_nonce,
        nonce2=bob_nonce,
    )

    assert alice_ss == bob_ss
    assert alice_hk == bob_hk
    assert bob_nhk == bob_nhk

    # .... assuming in change in time

    original_plaintext = b"Hello world"

    alice_state = States()
    bob_state = States()

    RatchetsHE.alice_init_HE(
        state=alice_state, 
        SK=alice_ss, 
        bob_dh_public_key=bob_ek, 
        shared_hka=alice_hk, # should be same with bob
        shared_nhkb=alice_enhk, # should be same with bob
        keystore_path="db_keys/alice_keys.db"
    )

    bob1 = x25519("db_keys/bobs_keys.db")
    bob1.load_keystore(bob.pnt_keystore, bob.secret_key)
    RatchetsHE.bob_init_HE(
        state=bob_state, 
        SK=bob_ss, 
        bob_dh_key_pair=bob1,
        shared_hka=bob_hk, # should be same with alice
        shared_nhkb=bob_enhk # should be same with alice
    )

    # checking if can serialize
    alice_state.serialize_json()

    enc_header, alice_ciphertext = RatchetsHE.RatchetEncryptHE(
        state=alice_state, 
        plaintext=original_plaintext, 
        AD = bob_static_keys.public_key().public_bytes_raw()
    )

    bob_plaintext = RatchetsHE.RatchetDecryptHE(
        state=bob_state,
        enc_header=enc_header,
        ciphertext=alice_ciphertext,
        AD = bob_static_keys.public_key().public_bytes_raw()
    )

    assert original_plaintext == bob_plaintext

    for i in range(10):
        print(i)
        enc_header, alice_ciphertext = RatchetsHE.RatchetEncryptHE(
            state=alice_state, 
            plaintext=original_plaintext, 
            AD = bob_static_keys.public_key().public_bytes_raw()
        )

    bob_plaintext = RatchetsHE.RatchetDecryptHE(
        state=bob_state,
        enc_header=enc_header,
        ciphertext=alice_ciphertext,
        AD = bob_static_keys.public_key().public_bytes_raw()
    )

    assert original_plaintext == bob_plaintext
    print(bob_plaintext)
    print("ENC_HE_LEN:", len(enc_header))