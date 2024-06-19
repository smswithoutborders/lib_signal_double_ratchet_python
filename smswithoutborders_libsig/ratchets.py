#!/usr/bin/env python3

import logging
from smswithoutborders_libsig.protocols import (
    States, 
    HEADERS, 
    GENERATE_DH, 
    DH, 
    KDF_CK, 
    KDF_RK,
    ENCRYPT,
    DECRYPT,
    CONCAT,
    DHRatchet
)

from smswithoutborders_libsig.keypairs import Keypairs

class Ratchets:
    MAX_SKIP = 20

    def alice_init(state: States, SK: bytes, bob_dh_public_key: bytes, keystore_path: str=None):
        state.DHs = GENERATE_DH(keystore_path)
        state.DHr = bob_dh_public_key
        state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr)) 
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def bob_init(state: States, SK: bytes, bob_dh_key_pair: Keypairs):
        state.DHs = bob_dh_key_pair
        state.DHr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def encrypt(state: States, data: bytes, AD: bytes):
        state.CKs, mk = KDF_CK(state.CKs)
        header = HEADERS(state.DHs, state.PN, state.Ns)
        state.Ns += 1
        return header, ENCRYPT(mk, data, CONCAT(AD, header))

    def decrypt(state: States, header: HEADERS, ciphertext: bytes, AD: bytes):
        plaintext = Ratchets.try_skip_message_keys(state, header, ciphertext, AD)
        if plaintext:
            return plaintext

        if header.dh != state.DHr:
            Ratchets.skip_message_keys(state, header.pn)
            DHRatchet(state, header)

        Ratchets.skip_message_keys(state, header.n)
        state.CKr, mk = KDF_CK(state.CKr)
        state.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def try_skip_message_keys(state, header, ciphertext, AD):
        if (header.dh, header.n) in state.MKSKIPPED:
            mk = state.MKSKIPPED[header.dh, header.n]
            del state.MKSKIPPED[header.dh , header.n]
            return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def skip_message_keys(state, until):
        if state.Nr + Ratchets.MAX_SKIP < until:
            raise Exception("MAX_SKIP Exceeded")

        if state.CKr:
            while state.Nr < until:
                state.CKr, mk = KDF_CK(state.CKr)
                state.MKSKIPPED[state.DHr, state.Nr] = mk
                state.Nr += 1

if __name__ == "__main__":
    from smswithoutborders_libsig.keypairs import x25519

    alice = x25519()
    alice_public_key_original = alice.init()

    bob = x25519("db_keys/bobs_keys.db")
    bob_public_key_original = bob.init() # not an encryption key, won't work unless for AD

    SK = alice.agree(bob_public_key_original)
    SK1 = bob.agree(alice_public_key_original)

    assert(SK)
    assert(SK1)
    assert(SK == SK1)

    # .... assuming in change in time 

    original_plaintext = b"Hello world"

    alice_state = States()
    bob_state = States()

    Ratchets.alice_init(alice_state, SK, bob_public_key_original, "db_keys/alice_keys.db")
    header, alice_ciphertext = Ratchets.encrypt(
        alice_state, original_plaintext, bob_public_key_original)

    s_header = header.serialize()
    a_header1 = HEADERS.deserialize(s_header)
    assert(header == a_header1)

    bob1 = x25519("db_keys/bobs_keys.db")
    bob1.load_keystore(bob.pnt_keystore, bob.secret_key)
    Ratchets.bob_init(bob_state, SK1, bob1)

    assert(bob.secret_key == bob1.secret_key)
    assert(bob.keystore_path == bob1.keystore_path)
    assert(bob.pnt_keystore == bob1.pnt_keystore)

    assert(bob.secret_key == bob_state.DHs.secret_key)
    assert(bob1.secret_key == bob_state.DHs.secret_key)

    bob_plaintext = Ratchets.decrypt(bob_state, header, alice_ciphertext, bob_public_key_original)

    assert(original_plaintext == bob_plaintext)

    '''test if states serialization happens'''
    ss_alice = alice_state.serialize()
    
    ds_alice = States.deserialize(ss_alice)
    assert(ds_alice.Ns == alice_state.Ns)
    assert(ds_alice.Nr == alice_state.Nr)
    assert(ds_alice.PN == alice_state.PN)
    assert(ds_alice.MKSKIPPED == alice_state.MKSKIPPED)
    assert(ds_alice.CKr == alice_state.CKr)
    assert(ds_alice.CKs == alice_state.CKs)
    assert(ds_alice.DHr == alice_state.DHr)
    assert(ds_alice.DHs == alice_state.DHs)
    assert(ds_alice.DHs.pnt_keystore == alice_state.DHs.pnt_keystore)
    assert(ds_alice.DHs.keystore_path == alice_state.DHs.keystore_path)
    assert(ds_alice.DHs.secret_key == alice_state.DHs.secret_key)
    assert(ds_alice == alice_state)
