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
        state.DHs = GENERATE_DH() # TODO: some parameters for storage
        state.DHr = bobsPublicKey
        state.public_key, state.pnt_keystore, state.enc_key, shared_secret = \
            DH(state.DHs, state.DHr, keystore_path)
        state.RK, state.CKs = KDF_RK(SK, shared_secret)


    def bob_init(state: States, SK: bytes, bobsKeyPair: Keypairs):
        state.DHs = bobsKeyPair
        state.RK = SK

    def encrypt(state: States, data: bytes, AD: bytes):
        state.CKs, mk = KDF_CK(state.CKs)
        header = HEADERS(state.public_key, state.PN, state.Ns)
        state.Ns += 1
        return header, ENCRYPT(mk, data, CONCAT(AD, header))

    def decrypt(state: States, header: HEADERS, data_cipher: bytes, AD: bytes):
        plaintext = try_skip_message_keys(state, header, ciphertext, AD)
        if plaintext:
            return plaintext

        if header.dh != state.DHr:
            skip_message_keys(state, header.pn)
            DHRatchet(state, header)

        skip_message_keys(header.n)
        state.CKr, mk = KDF_CK(state.CKr)
        state.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def try_skip_message_keys(state, header, ciphertext, AD):
        if (header.dh, header.n) in state.MKSKIPPED:
            mk = state.MKSKIPPED[header.dh, header.n]
            del state.MKSKIPPED[header.dh , header.n]
            return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def skip_message_keys(state, until):
        if state.Nr + MAX_SKIP < until:
            raise Exception("MAX_SKIP Exceeded")

        if state.CKr:
            while state.Nr < until:
                state.CKr, mk = KDF_CK(state.CKr)
                state.MKSKIPPED[state.DHr, state.Nr] = mk
                state.Nr += 1

if __name__ == "__main__":
    from keypairs import x25519

    alice = x25519()
    alice_public_key, pnt_keystore, enc_key = alice.get_public_key()

    bob = x25519("db_keys/bobs_keys.db")
    bob_public_key, pnt_keystore1, enc_key1 = bob.get_public_key()

    SK = alice.agree(bob_public_key, pnt_keystore, enc_key)
    SK1 = bob.agree(alice_public_key, pnt_keystore1, enc_key1)

    assert(SK == SK1)

    original_plaintext = b"Hello world"

    alice_state = States()
    bob_state = States()

    Ratchets.alice_init(alice_state, SK, bob_public_key)
    header, alice_ciphertext = Ratchets.encrypt(
        alice_state, original_plaintext, bob_public_key)

    Ratchets.bob_init(bob_state, SK1, bob)
    bob_plaintext = Ratchets.decrypt(
        bob_state, header, alice_ciphertext, bob_state.public_key)

    assert(original_plaintext == bob_plaintext)