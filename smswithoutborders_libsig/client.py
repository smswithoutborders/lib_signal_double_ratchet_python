
"""
This serves as both a client and server, 
running endlessly to verify the horrors bestowed upon it by the developers.
This is for development purposes, this should not be used in any form minus references.
"""

import smswithoutborders_libsig.keypairs as keypairs 
import smswithoutborders_libsig.protocols as protocols 
import smswithoutborders_libsig.ratchetsHE as ratchets 

import sys
import secrets
import random
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

def ratchet(
    alice_ss,
    bob_ek,
    alice_hk,
    alice_nhk,
    bob_ss,
    bob_hk,
    bob_nhk,
    bob_static_keys: X25519PrivateKey,
    bob_keypair: keypairs.x25519
):
    original_plaintext = b"Hello world"

    alice_state = protocols.States()
    bob_state = protocols.States()

    ratchets.RatchetsHE.alice_init_HE(
        state=alice_state, 
        SK=alice_ss, 
        bob_dh_public_key=bob_ek, 
        shared_hka=alice_hk, # should be same with bob
        shared_nhkb=alice_nhk, # should be same with bob
        keystore_path="db_keys/alice_keys.db"
    )

    ratchets.RatchetsHE.bob_init_HE(
        state=bob_state, 
        SK=bob_ss, 
        bob_dh_key_pair=bob_keypair,
        shared_hka=bob_hk, # should be same with alice
        shared_nhkb=bob_nhk # should be same with alice
    )

    # checking if can serialize
    alice_state.serialize_json()

    enc_header, alice_ciphertext = ratchets.RatchetsHE.RatchetEncryptHE(
        state=alice_state, 
        plaintext=original_plaintext, 
        AD = bob_static_keys.public_key().public_bytes_raw()
    )

    bob_plaintext = ratchets.RatchetsHE.RatchetDecryptHE(
        state=bob_state,
        enc_header=enc_header,
        ciphertext=alice_ciphertext,
        AD = bob_static_keys.public_key().public_bytes_raw()
    )

    assert original_plaintext == bob_plaintext

    for i in range(10):
        plaintext = random.randbytes(32)
        enc_header1, alice_ciphertext1 = ratchets.RatchetsHE.RatchetEncryptHE(
            state=bob_state, 
            plaintext=plaintext, 
            AD = bob_static_keys.public_key().public_bytes_raw()
        )
        print("state Ns:", bob_state.Ns)
    print("\n")

    bob_plaintext = ratchets.RatchetsHE.RatchetDecryptHE(
        state=alice_state,
        enc_header=enc_header1,
        ciphertext=alice_ciphertext1,
        AD = bob_static_keys.public_key().public_bytes_raw()
    )
    assert plaintext == bob_plaintext

    state_switch = 0
    for i in range(10):
        sender_state = alice_state if state_switch == 0 else bob_state
        receiver_state = bob_state if state_switch == 0 else alice_state
        print("sender_state_ns:", sender_state.Ns)
        print("sender_state_nr:", sender_state.Nr)
        print("receiver_state_ns:", receiver_state.Ns)
        print("receiver_state_nr:", receiver_state.Nr)
        print("\n")

        ad_bytes = bob_static_keys.public_key().public_bytes_raw() 

        plaintext = random.randbytes(32)
        
        enc_header, ciphertext = ratchets.RatchetsHE.RatchetEncryptHE(
            state=sender_state, 
            plaintext=plaintext, 
            AD=ad_bytes
        )

        other_plaintext = ratchets.RatchetsHE.RatchetDecryptHE(
            state=receiver_state, 
            enc_header=enc_header,
            ciphertext=ciphertext,
            AD=ad_bytes
        )

        assert plaintext == other_plaintext
        state_switch = 1 - state_switch





def ratchet_with_header_encryption():
    bob = keypairs.x25519("db_keys/bobs_keys.db")
    bob_ek, bob_ehk, bob_enhk = bob.initHE() 
    bob_static_keys = X25519PrivateKey.generate()

    alice = keypairs.x25519()
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

    bob1 = keypairs.x25519("db_keys/bobs_keys.db")
    bob1.load_keystore(bob.pnt_keystore, bob.secret_key)

    ratchet(
        alice_ss = alice_ss,
        bob_ek = bob_ek,
        alice_hk = alice_hk,
        alice_nhk = alice_nhk,
        bob_ss = bob_ss,
        bob_hk = bob_hk,
        bob_nhk = bob_nhk,
        bob_static_keys = bob_static_keys,
        bob_keypair = bob1
    )

def ratchet_with_noise_ik():
    alice = keypairs.x25519()
    alice_ek, _, _ = alice.initHE()
    alice_static_keys = X25519PrivateKey.generate()

    bob_static_keys = X25519PrivateKey.generate()
    bob = keypairs.x25519("db_keys/bobs_keys.db")
    bob.initHE(
        bob_static_keys,
        bob_static_keys,
        bob_static_keys,
    )

    alice_hash, alice_enc_public_key, alice_rk, alice_hk, alice_nhk = alice.agreeWithNoiseIKPattern(
        client_static_private_key = alice_static_keys, 
        client_ephemeral_public_key = None,
        client_enc_static_public_key = None,
        server_static_public_key = bob_static_keys.public_key(),
        server_static_private_key = None,
    )

    bob_hash, _, bob_rk, bob_hk, bob_nhk= bob.agreeWithNoiseIKPattern(
        client_static_private_key = None, 
        client_ephemeral_public_key = X25519PublicKey.from_public_bytes(alice_ek),
        client_enc_static_public_key = alice_enc_public_key,
        server_static_public_key = None,
        server_static_private_key = bob_static_keys,
    )

    assert alice_hash == bob_hash
    assert alice_rk == bob_rk
    assert alice_hk == bob_hk
    assert bob_nhk == bob_nhk

    ratchet(
        alice_ss = alice_rk,
        bob_ek = bob_static_keys.public_key().public_bytes_raw(),
        alice_hk = alice_hk,
        alice_nhk = alice_nhk,
        bob_ss = bob_rk,
        bob_hk = bob_hk,
        bob_nhk = bob_nhk,
        bob_static_keys = bob_static_keys,
        bob_keypair = bob
    )


if __name__ == "__main__":
    # ratchet_with_header_encryption()
    # print("[+] Finished header encryption")
    ratchet_with_noise_ik()
    print("[+] Finished noise ik pattern")