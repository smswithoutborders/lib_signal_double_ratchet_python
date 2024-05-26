#!/usr/bin/env python3

import logging
from protocols import (
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

from keypairs import Keypairs

class Ratchets:
    MAX_SKIP = 20

    def alice_init(state: States, SK: bytes, bobsPublicKey: bytes, keystore_path: str=None):
        state.DHs = GENERATE_DH(keystore_path) # TODO: some parameters for storage
        state.DHr = bobsPublicKey
        shared_secret = DH(state.DHs, state.DHr)
        state.RK, state.CKs = KDF_RK(SK, shared_secret)

    def bob_init(state: States, SK: bytes, bobsKeyPair: Keypairs):
        state.DHs = bobsKeyPair
        state.DHs.init()
        state.RK = SK

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
    from keypairs import x25519

    alice = x25519()
    alice_public_key_original = alice.init()

    bob = x25519("db_keys/bobs_keys.db")
    bob_public_key_original = bob.init()

    SK = alice.agree(bob_public_key_original)
    SK1 = bob.agree(alice_public_key_original)

    assert(SK == SK1)

    # .... assuming in change in time 

    original_plaintext = b"Hello world"

    alice_state = States()
    bob_state = States()

    Ratchets.alice_init(alice_state, SK, bob_public_key_original, "db_keys/alice_keys.db")
    print("keystore path:", alice_state.DHs.keystore_path)
    print("keystore sk:", alice_state.DHs.secret_key)
    header, alice_ciphertext = Ratchets.encrypt(
        alice_state, original_plaintext, bob_public_key_original)

    bob = x25519("db_keys/bobs_keys.db")
    Ratchets.bob_init(bob_state, SK1, bob)
    bob_plaintext = Ratchets.decrypt(bob_state, header, alice_ciphertext, bob_public_key_original)

    assert(original_plaintext == bob_plaintext)
